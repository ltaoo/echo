# Echo

A simplest implementation of a proxy server in Go, inspired by [Whistle](https://github.com/avwo/whistle).

## Features

- **HTTP Proxy**: Supports standard HTTP proxying.
- **HTTPS/TCP Tunneling**: Supports `CONNECT` method for HTTPS and generic TCP tunneling.
- **WebSocket Support**: Supports WebSocket upgrades (hijacking) and tunneling.

## Usage

1. Start the proxy server:
   ```bash
   go run main.go
   ```
   The server listens on port **8888**.

2. Configure your browser or client to use the proxy:
   - **Proxy Host**: `127.0.0.1`
   - **Proxy Port**: `8888`

3. Test with curl:
   ```bash
   # HTTP
   curl -x http://127.0.0.1:8888 http://example.com

   # HTTPS
   curl -x http://127.0.0.1:8888 https://example.com
   ```

## Implementation Details

- Uses Go's `net/http` for server handling.
- `handleHTTP` for standard proxy requests (removes hop-by-hop headers).
- `handleTunnel` for `CONNECT` requests (hijacks connection and tunnels TCP).
- `handleWebSocket` for `Upgrade: websocket` requests (hijacks connection and tunnels TCP).
