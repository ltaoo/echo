package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"echo/cert"
	"echo/plugin"
	"echo/proxy"
)

const (
	PORT = "127.0.0.1:8888"
)

func main() {
	// 1. Load Root CA
	// Assuming certs are in the current directory or a 'certs' subdirectory
	// You might need to adjust paths based on where you run the binary
	cwd, _ := os.Getwd()
	certDir := filepath.Join(cwd, "certs")
	keyPath := filepath.Join(certDir, "private.key")
	certPath := filepath.Join(certDir, "certificate.crt")

	log.Printf("Loading Root CA from %s", certDir)
	caCert, caKey, err := cert.LoadRootCA(keyPath, certPath)
	if err != nil {
		log.Fatalf("Failed to load Root CA: %v\nPlease ensure 'certs/private.key' and 'certs/certificate.crt' exist.", err)
	}
	log.Println("Root CA loaded successfully")

	// 2. Initialize Certificate Manager
	certManager, err := cert.NewManager(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize certificate manager: %v", err)
	}

	plugins := []plugin.Plugin{}
	pluginLoader, err := plugin.NewLoader(plugins)
	if err != nil {
		log.Printf("Warning: Failed to load plugins: %v", err)
	}

	// 4. Initialize Proxy Handlers
	httpHandler := proxy.NewHTTPHandler(pluginLoader)
	connectHandler := &proxy.ConnectHandler{
		CertManager:  certManager,
		PluginLoader: pluginLoader,
		HTTPHandler:  httpHandler,
	}
	wsHandler := &proxy.WebSocketHandler{PluginLoader: pluginLoader}

	// 5. Create Main Handler
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle CONNECT (HTTPS Tunneling)
		if r.Method == http.MethodConnect {
			connectHandler.HandleTunnel(w, r)
			return
		}

		// Handle WebSocket Upgrades (HTTP)
		if proxy.IsWebSocketRequest(r) {
			wsHandler.HandleUpgrade(w, r, false) // false = not secure (ws://)
			return
		}

		// Handle Standard HTTP
		httpHandler.HandleRequest(w, r)
	})

	// 6. Start Server
	server := &http.Server{
		Addr:    PORT,
		Handler: mainHandler,
	}

	log.Printf("Echo Proxy (Go) listening on port %s", PORT)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
