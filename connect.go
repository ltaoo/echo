package echo

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ltaoo/echo/cert"
)

// ConnectHandler handles CONNECT requests and MITM
type ConnectHandler struct {
	CertManager          *cert.Manager
	PluginLoader         *PluginLoader
	HTTPHandler          *HTTPHandler // Shared HTTP handler
	InterceptOnlyMatched bool         // Only intercept if plugin matches
	UpstreamProxy        string       // Upstream proxy URL
	mitmServers          sync.Map     // map[string]*MitmServer
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

	// Check if there are plugin matches for this hostname
	matched_plugins := h.PluginLoader.MatchPlugins(hostname)
	log.Printf("[CONNECT] %s:%s matched %d plugin(s)", hostname, port, len(matched_plugins))

	// Check if any matched plugin has Bypass enabled
	for _, p := range matched_plugins {
		if p.Bypass {
			log.Printf("[CONNECT] Bypass enabled for %s:%s, tunneling directly", hostname, port)
			// Hijack and tunnel directly
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
			clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-agent: echo\r\n\r\n"))
			h.tunnelDirect(clientConn, hostname, port)
			return
		}
	}

	should_intercept := false
	if h.InterceptOnlyMatched {
		// Only intercept if there are non-bypass plugins matched
		should_intercept = len(matched_plugins) > 0
	} else {
		// Default: intercept all port 443 or any plugin match
		should_intercept = (port == "443" || len(matched_plugins) > 0)
	}

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
	if !should_intercept {
		if h.InterceptOnlyMatched {
			log.Printf("[CONNECT] No plugin match for %s:%s, bypass (intercept-only mode)", hostname, port)
		} else {
			log.Printf("[CONNECT] No plugin match for %s:%s, tunneling directly", hostname, port)
		}
		h.tunnelDirect(clientConn, hostname, port)
		return
	}

	if len(matched_plugins) > 0 {
		log.Printf("[CONNECT] Intercepting %s:%s (%d plugin(s) matched)", hostname, port, len(matched_plugins))
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
	var targetConn net.Conn
	var err error

	if h.UpstreamProxy != "" {
		// Connect to upstream proxy and tunnel through it
		targetConn, err = h.dialUpstreamProxy(clientConn, hostname, port)
		// Fallback to direct if upstream proxy fails
		if err != nil {
			log.Printf("[UpstreamProxy] Failed, falling back to direct: %v", err)
			targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
		}
	} else {
		// Direct connection to target
		targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
	}

	if err != nil {
		log.Printf("[Tunnel Error] %v", err)
		clientConn.Close()
		return
	}

	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

func (h *ConnectHandler) tunnelDirectWithBuffer(clientConn net.Conn, bufClientConn *bufio.Reader, hostname, port string) {
	var targetConn net.Conn
	var err error

	if h.UpstreamProxy != "" {
		targetConn, err = h.dialUpstreamProxy(clientConn, hostname, port)
		if err != nil {
			log.Printf("[UpstreamProxy] Failed, falling back to direct: %v", err)
			targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
		}
	} else {
		targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(hostname, port), 10*time.Second)
	}

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

// dialUpstreamProxy connects to the upstream proxy and establishes a CONNECT tunnel
func (h *ConnectHandler) dialUpstreamProxy(clientConn net.Conn, hostname, port string) (net.Conn, error) {
	proxyURL, err := url.Parse(h.UpstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy URL: %v", err)
	}

	log.Printf("[UpstreamProxy] Connecting to %s", h.UpstreamProxy)

	var proxyConn net.Conn
	switch proxyURL.Scheme {
	case "http", "https":
		proxyConn, err = net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to upstream proxy: %v", err)
		}

		// Send CONNECT request to proxy
		req := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", hostname, port, hostname, port)
		_, err = proxyConn.Write([]byte(req))
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to send CONNECT request: %v", err)
		}

		// Read response
		respBuf := make([]byte, 1024)
		n, err := proxyConn.Read(respBuf)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to read proxy response: %v", err)
		}

		// Check for 200 Connection Established
		resp := string(respBuf[:n])
		if !strings.HasPrefix(resp, "HTTP/1.1 200") && !strings.HasPrefix(resp, "HTTP/1.0 200") {
			proxyConn.Close()
			return nil, fmt.Errorf("upstream proxy rejected CONNECT: %s", resp[:min(n, 200)])
		}
		return proxyConn, nil

	case "socks5":
		// Basic SOCKS5 connect (simplified)
		proxyConn, err = net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %v", err)
		}

		// SOCKS5 greeting: client sends version + auth methods
		_, err = proxyConn.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			proxyConn.Close()
			return nil, err
		}

		// Server selects auth method
		buf := make([]byte, 2)
		_, err = proxyConn.Read(buf)
		if err != nil || buf[0] != 0x05 || buf[1] != 0x00 {
			proxyConn.Close()
			return nil, fmt.Errorf("SOCKS5 auth failed")
		}

		// SOCKS5 connect request
		hostBytes := []byte(hostname)
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
		req = append(req, hostBytes...)
		portBytes := []byte{byte((atoi(port) >> 8) & 0xff), byte(atoi(port) & 0xff)}
		req = append(req, portBytes...)

		_, err = proxyConn.Write(req)
		if err != nil {
			proxyConn.Close()
			return nil, err
		}

		// Read response
		resp := make([]byte, 10)
		_, err = proxyConn.Read(resp)
		if err != nil || resp[1] != 0x00 {
			proxyConn.Close()
			return nil, fmt.Errorf("SOCKS5 connection failed")
		}
		return proxyConn, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: http, https, socks5)", proxyURL.Scheme)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
