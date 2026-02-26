/*
Package echo provides a simple proxy server implementation in Go, inspired by [Whistle].

# Features

  - HTTP Proxy: Supports standard HTTP proxying.
  - HTTPS/TCP Tunneling: Supports CONNECT method for HTTPS and generic TCP tunneling.
  - WebSocket Support: Supports WebSocket upgrades (hijacking) and tunneling.
  - Plugin System: Flexible plugin system to modify requests and responses.

# Quick Start

To start the proxy server, provide a Root CA certificate and private key:

	certFile, _ := os.ReadFile("certs/rootCA.crt")
	keyFile, _ := os.ReadFile("certs/rootCA.key")

	e, err := echo.NewEcho(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:    ":8888",
		Handler: e,
	}
	server.ListenAndServe()

# Plugins

Add plugins to intercept and modify requests/responses:

	e.AddPlugin(&echo.Plugin{
		Match: "example.com",
		OnRequest: func(ctx *echo.Context) {
			ctx.SetRequestHeader("X-Custom-Header", "value")
		},
		OnResponse: func(ctx *echo.Context) {
			body, _ := ctx.GetResponseBody()
			ctx.SetResponseBody(strings.ReplaceAll(body, "old", "new"))
		},
	})

# Forwarding

Use [TargetConfig] to forward requests to a different server:

	e.AddPlugin(&echo.Plugin{
		Match:  "example.com",
		Target: &echo.TargetConfig{Protocol: "http", Host: "localhost", Port: 3000},
	})

# Mock Response

Use [MockResponse] to return a static response:

	e.AddPlugin(&echo.Plugin{
		Match: "example.com/api",
		MockResponse: &echo.MockResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"status":"ok"}`,
		},
	})

[Whistle]: https://github.com/avwo/whistle
*/
package echo

import (
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ltaoo/echo/cert"
)

func init() {
	v := os.Getenv("ECHO_LOG")
	if v == "" {
		return
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "0" || v == "false" || v == "no" || v == "off" {
		log.SetOutput(io.Discard)
	}
}

type Echo struct {
	connectHandler *ConnectHandler
	wsHandler      *WebSocketHandler
	httpHandler    *HTTPHandler
	pluginLoader   *PluginLoader
}

func NewEcho(certFile []byte, certKey []byte) (*Echo, error) {
	caCert, caKey, err := cert.LoadRootCA(certFile, certKey)
	if err != nil {
		// log.Fatalf("Failed to load Root CA: %v\nPlease ensure 'certs/private.key' and 'certs/certificate.crt' exist.", err)
		return nil, err
	}
	// log.Println("Root CA loaded successfully")

	// 2. Initialize Certificate Manager
	certManager, err := cert.NewManager(caCert, caKey)
	if err != nil {
		// log.Fatalf("Failed to initialize certificate manager: %v", err)
		return nil, err
	}
	plugins := []*Plugin{}
	pluginLoader, err := NewPluginLoader(plugins)
	if err != nil {
		// log.Printf("Warning: Failed to load plugins: %v", err)
		return nil, err
	}

	// 4. Initialize Proxy Handlers
	httpHandler := NewHTTPHandler(pluginLoader)
	connectHandler := &ConnectHandler{
		CertManager:  certManager,
		PluginLoader: pluginLoader,
		HTTPHandler:  httpHandler,
	}
	wsHandler := &WebSocketHandler{PluginLoader: pluginLoader}

	return &Echo{
		connectHandler: connectHandler,
		wsHandler:      wsHandler,
		httpHandler:    httpHandler,
		pluginLoader:   pluginLoader,
	}, nil
}

func (e *Echo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT (HTTPS Tunneling)
	if r.Method == http.MethodConnect {
		e.connectHandler.HandleTunnel(w, r)
		return
	}
	// Handle WebSocket Upgrades (HTTP)
	if IsWebSocketRequest(r) {
		e.wsHandler.HandleUpgrade(w, r, false) // false = not secure (ws://)
		return
	}
	// Handle Standard HTTP
	e.httpHandler.HandleRequest(w, r)
}
func (e *Echo) AddPlugin(plugin *Plugin) {
	e.pluginLoader.AddPlugin(plugin)
}

func SetLogEnabled(enabled bool) {
	if enabled {
		log.SetOutput(os.Stderr)
	} else {
		log.SetOutput(io.Discard)
	}
}
