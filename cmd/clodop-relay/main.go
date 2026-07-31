package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

func main() {
	listenAddr := flag.String("listen", ":8080", "TCP address on which the relay listens")
	targetAddr := flag.String("target", "127.0.0.1:8000", "CLodop TCP target address")
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	log.Printf("CLodop transparent TCP relay listening on %s -> %s", *listenAddr, *targetAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("accept connection: %v", err)
			continue
		}
		go relayConnection(client, *targetAddr)
	}
}

func relayConnection(client net.Conn, targetAddr string) {
	defer client.Close()

	backend, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[CLodop Relay] %s -> %s: %v", client.RemoteAddr(), targetAddr, err)
		return
	}
	defer backend.Close()

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	requestHeader, clientReader, patched, err := readAndPatchInitialRequest(client)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("[CLodop Relay] read %s: %v", client.RemoteAddr(), err)
		return
	}

	log.Printf(
		"[CLodop Relay] connected %s -> %s, WebSocket headers patched=%t",
		client.RemoteAddr(),
		targetAddr,
		patched,
	)

	done := make(chan error, 2)
	go func() {
		source := io.MultiReader(bytes.NewReader(requestHeader), clientReader)
		_, copyErr := io.Copy(backend, source)
		if tcp, ok := backend.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- copyErr
	}()
	go copyConnection(done, client, backend)

	if err := <-done; err != nil {
		log.Printf("[CLodop Relay] %s: %v", client.RemoteAddr(), err)
	}
}

func copyConnection(done chan<- error, dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	done <- err
}

func readAndPatchInitialRequest(client net.Conn) ([]byte, *bufio.Reader, bool, error) {
	reader := bufio.NewReader(client)
	var header bytes.Buffer

	for header.Len() <= 64*1024 {
		line, err := reader.ReadBytes('\n')
		header.Write(line)
		if err != nil {
			return nil, reader, false, err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			result, patched := patchWebSocketHeaders(header.Bytes())
			return result, reader, patched, nil
		}
	}

	return nil, reader, false, fmt.Errorf("request headers exceed 64 KiB")
}

func patchWebSocketHeaders(header []byte) ([]byte, bool) {
	headerText := string(header)
	lines := strings.Split(headerText, "\r\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "/c_webskt/") {
		return append([]byte(nil), header...), false
	}

	hasConnectionUpgrade := false
	hasUpgradeWebSocket := false
	for _, line := range lines[1:] {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "connection":
			hasConnectionUpgrade = strings.Contains(strings.ToLower(value), "upgrade")
		case "upgrade":
			hasUpgradeWebSocket = strings.EqualFold(strings.TrimSpace(value), "websocket")
		}
	}

	if hasConnectionUpgrade && hasUpgradeWebSocket {
		return append([]byte(nil), header...), false
	}

	end := bytes.LastIndex(header, []byte("\r\n\r\n"))
	if end < 0 {
		return append([]byte(nil), header...), false
	}

	var patched bytes.Buffer
	patched.Write(header[:end])
	patched.WriteString("\r\n")
	if !hasConnectionUpgrade {
		patched.WriteString("Connection: Upgrade\r\n")
	}
	if !hasUpgradeWebSocket {
		patched.WriteString("Upgrade: websocket\r\n")
	}
	patched.WriteString("\r\n")
	return patched.Bytes(), true
}
