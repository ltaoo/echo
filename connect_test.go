package echo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMitmServerUsesHTTP11ForDownstreamConnections(t *testing.T) {
	cert_file, err := os.ReadFile("_example/SunnyRoot.cer")
	if err != nil {
		t.Fatal(err)
	}
	key_file, err := os.ReadFile("_example/private.key")
	if err != nil {
		t.Fatal(err)
	}
	echo_proxy, err := NewEcho(cert_file, key_file)
	if err != nil {
		t.Fatal(err)
	}
	echo_proxy.AddPlugin(&Plugin{
		Match: "video.example.test",
		OnRequest: func(ctx *Context) {
			ctx.Mock(http.StatusOK, map[string]string{"Content-Type": "video/mp4"}, []byte("video"))
		},
	})
	proxy_server := httptest.NewServer(echo_proxy)
	defer proxy_server.Close()

	proxy_url, err := url.Parse(proxy_server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxy_url),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}}
	response, err := client.Get("https://video.example.test/segment.mp4")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.ProtoMajor != 1 || response.ProtoMinor != 1 {
		t.Fatalf("downstream protocol = %s, want HTTP/1.1", response.Proto)
	}
}

func TestHandlePlainHTTPTunnelRunsResponseHooks(t *testing.T) {
	var requestLog bytes.Buffer
	loader, err := NewPluginLoader([]*Plugin{
		{
			Match:  "**.qq.com",
			Target: &TargetConfig{Protocol: "http", Host: "upstream.test", Port: 80},
			OnRequest: func(ctx *Context) {
				fmt.Fprintf(&requestLog, "%s %s", ctx.Req.Method, ctx.Req.URL.String())
			},
			OnResponse: func(ctx *Context) {
				if ctx.Res == nil || !strings.Contains(ctx.Res.Header.Get("Content-Type"), "text/html") {
					return
				}
				body, err := ctx.GetResponseBody()
				if err != nil {
					t.Errorf("read response body: %v", err)
					return
				}
				ctx.SetResponseBody(strings.Replace(body, "<title>before</title>", "<title>after</title>", 1))
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	httpHandler := NewHTTPHandler(loader)
	httpHandler.Transport.Proxy = nil
	httpHandler.Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go servePipeHTTPResponse(serverConn, `<html><head><title>before</title></head><body>ok</body></html>`)
		return clientConn, nil
	}
	connectHandler := &ConnectHandler{
		PluginLoader: loader,
		HTTPHandler:  httpHandler,
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	done := make(chan struct{})
	go func() {
		defer close(done)
		connectHandler.handlePlainHTTPTunnel(serverConn, bufio.NewReader(serverConn), "weixin.qq.com", "80")
	}()

	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: weixin.qq.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if body := string(bodyBytes); !strings.Contains(body, "<title>after</title>") {
		t.Fatalf("response hook did not rewrite title: %s", body)
	}
	if got := requestLog.String(); got != "GET http://weixin.qq.com/" {
		t.Fatalf("request hook log: got %q", got)
	}

	<-done
}

func TestHandlePlainHTTPTunnelHandlesWebSocketUpgrade(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamListener.Close()

	upstreamAddr := upstreamListener.Addr().(*net.TCPAddr)
	upstreamRequest := make(chan *http.Request, 1)
	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		upstreamRequest <- req
		_, _ = io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Connection: Upgrade\r\n"+
				"Upgrade: websocket\r\n\r\n")
		_, _ = io.Copy(io.Discard, conn)
	}()

	loader, err := NewPluginLoader([]*Plugin{{
		Match: "http://127.0.0.1:8080/*",
		Target: &TargetConfig{
			Protocol: "ws",
			Host:     upstreamAddr.IP.String(),
			Port:     upstreamAddr.Port,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	connectHandler := &ConnectHandler{PluginLoader: loader}

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		connectHandler.handlePlainHTTPTunnel(serverConn, bufio.NewReader(serverConn), "127.0.0.1", "8080")
	}()

	if _, err := io.WriteString(clientConn,
		"GET /c_webskt/ HTTP/1.1\r\n"+
			"Host: 127.0.0.1:8080\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	select {
	case req := <-upstreamRequest:
		if req.URL.Path != "/c_webskt/" {
			t.Fatalf("upstream path = %q", req.URL.Path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream WebSocket request")
	}

	_ = clientConn.Close()
	<-done
}

func servePipeHTTPResponse(conn net.Conn, body string) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()

	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	_ = resp.Write(conn)
}
