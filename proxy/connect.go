package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"echo/cert"
	"echo/plugin"
)

// ConnectHandler handles CONNECT requests and MITM
type ConnectHandler struct {
	CertManager  *cert.Manager
	PluginLoader *plugin.Loader
	HTTPHandler  *HTTPHandler // Shared HTTP handler
	mitmServers  sync.Map     // map[string]*MitmServer
}

type MitmServer struct {
	Port     int
	Listener net.Listener
}

// HandleTunnel handles the CONNECT request
func (h *ConnectHandler) HandleTunnel(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = "443"
	}

	log.Printf("[CONNECT] %s:%s", hostname, port)

	// Check if there's a plugin match for this hostname
	matchedPlugin := h.PluginLoader.MatchPlugin(hostname)
	shouldIntercept := port == "443" || matchedPlugin != nil

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-agent: echo\r\n\r\n"))

	// If not intercepting (no plugin match and not port 443), just tunnel directly
	if !shouldIntercept {
		log.Printf("[CONNECT] No plugin match for %s:%s, tunneling directly", hostname, port)
		h.tunnelDirect(clientConn, hostname, port)
		return
	}

	if matchedPlugin != nil {
		log.Printf("[CONNECT] Intercepting %s:%s (plugin matched)", hostname, port)
	} else {
		log.Printf("[CONNECT] Intercepting %s:%s (port 443)", hostname, port)
	}

	// Peek first byte to check for TLS
	// We need to read without consuming, or read and put back
	// Using bufio.Reader to peek
	bufClientConn := bufio.NewReader(clientConn)
	peekBytes, err := bufClientConn.Peek(1)
	if err != nil {
		// Client might have closed or error
		clientConn.Close()
		return
	}

	// Check for TLS handshake (0x16)
	if peekBytes[0] == 0x16 {
		// It's TLS, start MITM
		h.handleMitm(clientConn, bufClientConn, hostname)
	} else {
		// Not TLS, tunnel directly
		log.Printf("[Protocol Sniffing] Non-TLS traffic on port 443 for %s. Bypassing MITM.", hostname)
		h.tunnelDirectWithBuffer(clientConn, bufClientConn, hostname, port)
	}
}

func (h *ConnectHandler) tunnelDirect(clientConn net.Conn, hostname, port string) {
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
	if err != nil {
		log.Printf("[Tunnel Error] %v", err)
		clientConn.Close()
		return
	}

	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

func (h *ConnectHandler) tunnelDirectWithBuffer(clientConn net.Conn, bufClientConn *bufio.Reader, hostname, port string) {
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
	if err != nil {
		log.Printf("[Tunnel Error] %v", err)
		clientConn.Close()
		return
	}

	// We need to write the buffered data to target first
	// Since we can't easily get the buffer out of bufio.Reader without reading,
	// we'll wrap it or just copy from it.

	go func() {
		defer targetConn.Close()
		defer clientConn.Close()

		// Copy from buffered reader to target
		_, err := bufClientConn.WriteTo(targetConn)
		if err != nil {
			return
		}
	}()

	go transfer(clientConn, targetConn)
}

func (h *ConnectHandler) handleMitm(clientConn net.Conn, bufClientConn *bufio.Reader, hostname string) {
	// Get or create MITM server for this hostname
	mitmServer, err := h.getMitmServer(hostname)
	if err != nil {
		log.Printf("[MITM Error] Failed to get MITM server: %v", err)
		clientConn.Close()
		return
	}

	// Connect to local MITM server
	localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mitmServer.Port))
	if err != nil {
		log.Printf("[MITM Error] Failed to connect to local MITM server: %v", err)
		clientConn.Close()
		return
	}

	// Pipe data
	go func() {
		defer localConn.Close()
		defer clientConn.Close()
		bufClientConn.WriteTo(localConn)
	}()

	go transfer(clientConn, localConn)
}

func (h *ConnectHandler) getMitmServer(hostname string) (*MitmServer, error) {
	// Check cache
	if val, ok := h.mitmServers.Load(hostname); ok {
		return val.(*MitmServer), nil
	}

	// Create new MITM server
	// We listen on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	port := listener.Addr().(*net.TCPAddr).Port
	log.Printf("[Dynamic Server] Started for %s on port %d", hostname, port)

	// Create a custom handler that supports both HTTP and WebSocket upgrade
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if it's a WebSocket upgrade request
			if IsWebSocketRequest(r) {
				log.Printf("[MITM Server] Detected WebSocket upgrade request for %s", hostname)
				wsHandler := &WebSocketHandler{PluginLoader: h.PluginLoader}
				wsHandler.HandleUpgrade(w, r, true) // true for secure (wss)
				return
			}
			// Otherwise handle as normal HTTP
			h.handleMitmRequest(w, r, hostname)
		}),
		TLSConfig: &tls.Config{
			GetCertificate: h.CertManager.GetCertificateFunc(),
		},
	}

	go server.ServeTLS(listener, "", "")

	mitmServer := &MitmServer{
		Port:     port,
		Listener: listener,
	}

	h.mitmServers.Store(hostname, mitmServer)
	return mitmServer, nil
}

func (h *ConnectHandler) handleMitmRequest(w http.ResponseWriter, r *http.Request, originalHostname string) {
	// This is the decrypted request!
	// Reconstruct the URL
	r.URL.Scheme = "https"
	r.URL.Host = r.Host
	if r.URL.Host == "" {
		r.URL.Host = originalHostname
	}

	log.Printf("[HTTPS MITM] %s %s (Host: %s)", r.Method, r.URL.String(), r.Host)

	// Reuse HTTP handler logic
	// Use the shared HTTPHandler if available, otherwise create one (fallback)
	handler := h.HTTPHandler
	if handler == nil {
		handler = NewHTTPHandler(h.PluginLoader)
	}
	handler.HandleRequest(w, r)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
