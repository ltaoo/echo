package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRelayConnectionCopiesBytesBidirectionally(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()

	backendDone := make(chan error, 1)
	go func() {
		conn, acceptErr := backendListener.Accept()
		if acceptErr != nil {
			backendDone <- acceptErr
			return
		}
		defer conn.Close()
		_, copyErr := io.Copy(conn, conn)
		backendDone <- copyErr
	}()

	relaySide, clientSide := net.Pipe()
	go relayConnection(relaySide, backendListener.Addr().String())
	defer clientSide.Close()
	_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))

	const message = "GET /CLodopfuncs.js HTTP/1.1\r\nHost: relay:8080\r\n\r\n"
	if _, err := clientSide.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}

	response := make([]byte, len(message))
	if _, err := io.ReadFull(clientSide, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != message {
		t.Fatalf("response = %q, want %q", response, message)
	}
}

func TestPatchWebSocketHeaders(t *testing.T) {
	input := []byte(
		"GET /c_webskt/ HTTP/1.1\r\n" +
			"Host: 192.168.191.215:8080\r\n" +
			"Sec-WebSocket-Key: abc123\r\n\r\n",
	)

	got, patched := patchWebSocketHeaders(input)
	if !patched {
		t.Fatal("expected WebSocket headers to be patched")
	}
	gotText := string(got)
	if !strings.Contains(gotText, "Connection: Upgrade\r\n") {
		t.Errorf("missing Connection header: %q", gotText)
	}
	if !strings.Contains(gotText, "Upgrade: websocket\r\n") {
		t.Errorf("missing Upgrade header: %q", gotText)
	}
	if !strings.Contains(gotText, "Sec-WebSocket-Key: abc123\r\n") {
		t.Errorf("original headers were not preserved: %q", gotText)
	}
}

func TestPatchWebSocketHeadersLeavesHTTPUnchanged(t *testing.T) {
	input := []byte("GET /CLodopfuncs.js HTTP/1.1\r\nHost: host:8080\r\n\r\n")
	got, patched := patchWebSocketHeaders(input)
	if patched {
		t.Fatal("ordinary HTTP request was patched")
	}
	if string(got) != string(input) {
		t.Fatalf("request changed:\n got %q\nwant %q", got, input)
	}
}
