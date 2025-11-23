package plugin

import (
	"fmt"
	"net/http"
)

// Plugin represents a forwarding rule configuration
type Plugin struct {
	Match        string
	Target       *TargetConfig
	MockResponse *MockResponse

	// Hooks
	OnRequest  func(req *http.Request, path string) *MockResponse
	OnResponse func(res *http.Response, body string, req *http.Request) string
}

// TargetConfig defines where to forward requests
type TargetConfig struct {
	Protocol string // http, https, ws, wss
	Host     string
	Port     int
}

// MockResponse defines a static response to return
type MockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       interface{} // string or []byte
}

// GetTargetURL returns the full target URL for forwarding
func (t *TargetConfig) GetTargetURL(path string) string {
	if t == nil {
		return ""
	}
	return t.Protocol + "://" + t.Host + ":" + string(rune(t.Port)) + path
}

// GetHostPort returns the host:port combination
func (t *TargetConfig) GetHostPort() string {
	if t == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// GetDefaultPort returns the default port for the protocol
func (t *TargetConfig) GetDefaultPort() int {
	if t.Port > 0 {
		return t.Port
	}
	switch t.Protocol {
	case "https", "wss":
		return 443
	default:
		return 80
	}
}
