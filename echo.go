package echo

import (
	"net/http"

	"github.com/ltaoo/echo/cert"
)

type Echo struct {
	connectHandler *ConnectHandler
	wsHandler      *WebSocketHandler
	httpHandler    *HTTPHandler
	pluginLoader   *Loader
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
	pluginLoader, err := NewLoader(plugins)
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
