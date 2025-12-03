package echo

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// HTTPHandler handles standard HTTP proxy requests
type HTTPHandler struct {
	PluginLoader *Loader
	Transport    *http.Transport
}

// NewHTTPHandler creates a new HTTP handler with a custom transport
func NewHTTPHandler(loader *Loader) *HTTPHandler {
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

	// Find all matching plugins
	matched_plugins := h.PluginLoader.MatchPluginsForRequest(r)

	// Create Plugin Context
	ctx := &Context{Req: r}

	// Apply OnRequest hooks in order; last Target wins
	var selected_target *TargetConfig
	if len(matched_plugins) > 0 {
		log.Printf("[HTTP] %d plugin(s) matched for %s", len(matched_plugins), hostname)
		for _, p := range matched_plugins {
			if p.OnRequest != nil {
				p.OnRequest(ctx)
				if mockResp := ctx.GetMockResponse(); mockResp != nil {
					log.Printf("[PLUGIN] Returning direct response for %s", path)
					h.sendMockResponse(w, mockResp)
					return
				}
			}
			if p.Target != nil {
				selected_target = p.Target
			}
		}
		if selected_target != nil {
			targetURL := selected_target.GetTargetURL(path)
			log.Printf("[PLUGIN] Forwarding %s -> %s", hostname, targetURL)
			r.URL.Scheme = selected_target.Protocol
			r.URL.Host = selected_target.GetHostPort()
			r.Host = selected_target.GetHostPort()
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

	// Apply OnResponse hooks of all matched plugins in order
	if len(matched_plugins) > 0 {
		ctx.Res = resp
		for _, p := range matched_plugins {
			if p.OnResponse != nil {
				p.OnResponse(ctx)
			}
		}
	}

	// Copy response headers
	DelHopHeaders(resp.Header)
	CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func (h *HTTPHandler) sendMockResponse(w http.ResponseWriter, mock *MockResponse) {
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
