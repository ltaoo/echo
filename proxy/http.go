package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ltaoo/echo/plugin"
)

// HTTPHandler handles standard HTTP proxy requests
type HTTPHandler struct {
	PluginLoader *plugin.Loader
	Transport    *http.Transport
}

// NewHTTPHandler creates a new HTTP handler with a custom transport
func NewHTTPHandler(loader *plugin.Loader) *HTTPHandler {
	return &HTTPHandler{
		PluginLoader: loader,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     false, // Disable HTTP/2
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Disable HTTP/2 by setting TLSNextProto to non-nil empty map
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}
}

// HandleRequest processes the HTTP request
func (h *HTTPHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// Remove proxy headers
	DelHopHeaders(r.Header)

	// Parse target URL
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	hostname := r.URL.Hostname()
	path := r.URL.Path + r.URL.RawQuery

	log.Printf("[HTTP] %s %s (Host: %s)", r.Method, r.URL.String(), hostname)

	// Check for plugin match
	matchedPlugin := h.PluginLoader.MatchPlugin(hostname)
	if matchedPlugin != nil {
		log.Printf("[HTTP] Plugin matched for %s", hostname)

		// Call OnRequest hook
		if matchedPlugin.OnRequest != nil {
			mockResp := matchedPlugin.OnRequest(r, path)
			if mockResp != nil {
				log.Printf("[PLUGIN] Returning direct response for %s", path)
				h.sendMockResponse(w, mockResp)
				return
			}
		}

		// Handle forwarding
		if matchedPlugin.Target != nil {
			targetURL := matchedPlugin.Target.GetTargetURL(path)
			log.Printf("[PLUGIN] Forwarding %s -> %s", hostname, targetURL)

			// Update request URL
			r.URL.Scheme = matchedPlugin.Target.Protocol
			r.URL.Host = matchedPlugin.Target.GetHostPort()
			r.Host = matchedPlugin.Target.GetHostPort()
		}
	}

	// Create client with custom transport
	client := &http.Client{
		Transport: h.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create new request
	// We need to read body if present
	var bodyReader io.Reader
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()
		bodyReader = bytes.NewReader(bodyBytes)
		// Re-assign body to request for potential reuse if we weren't creating a new request
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), bodyReader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Copy headers
	CopyHeader(proxyReq.Header, r.Header)
	DelHopHeaders(proxyReq.Header)

	// Send request
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTP Error] %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Handle OnResponse hook
	// Skip binary files to avoid corruption
	contentType := resp.Header.Get("Content-Type")
	isBinary := strings.HasPrefix(contentType, "video/") ||
		strings.HasPrefix(contentType, "image/") ||
		strings.HasPrefix(contentType, "audio/") ||
		contentType == "application/octet-stream"

	if matchedPlugin != nil && matchedPlugin.OnResponse != nil && !isBinary {
		// Decompress body if needed
		reader, err := DecompressBody(resp)
		if err != nil {
			log.Printf("[Decompress Error] %v", err)
			// Fallback to raw body
			reader = resp.Body
		}

		bodyBytes, err := io.ReadAll(reader)
		if err != nil {
			log.Printf("[Read Body Error] %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		reader.Close()

		bodyStr := string(bodyBytes)
		modifiedBody := matchedPlugin.OnResponse(resp, bodyStr, r)

		// Update headers
		DelHopHeaders(resp.Header)
		CopyHeader(w.Header(), resp.Header)

		// Remove content-encoding/length as we modified body
		w.Header().Del("Content-Encoding")
		w.Header().Set("Content-Length", strconv.Itoa(len(modifiedBody)))

		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(modifiedBody))
		return
	}

	// Copy response headers
	DelHopHeaders(resp.Header)
	CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func (h *HTTPHandler) sendMockResponse(w http.ResponseWriter, mock *plugin.MockResponse) {
	for k, v := range mock.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(mock.StatusCode)

	switch v := mock.Body.(type) {
	case string:
		w.Write([]byte(v))
	case []byte:
		w.Write(v)
	}
}
