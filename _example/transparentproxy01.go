package main

// forwarder
// 由于只做 TCP 原样转发，只能验证请求过去了，请求完成了
// curl客户端 request http://127.0.0.1:8080
// :8080服务 接收到 TCP 请求，并不知道 HTTP 相关信息，包括 Method、Host、Pathname 等等
// :8080服务向 www.baidu.com:80 发起 TCP 请求，baidu 收到的，就是来自 :8080 的请求，到 Http 那层
// 就是 Method GET /，Hostname 是 :8080，对 baidu 来说是不合法的请求，直接拒绝了

import (
	"flag"
	"io"
	"log"
	"net"
	"time"
)

func main() {
	listenAddr := flag.String("listen", ":8080", "listen address")
	targetAddr := flag.String("target", "proxy.frp.funzm.com:80", "target address")
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("监听 %s 失败：%v", *listenAddr, err)
	}
	defer listener.Close()

	log.Printf("TCP 转发器启动: %s -> %s", *listenAddr, *targetAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败：%v", err)
			continue
		}
		log.Printf("新连接：%s", client.RemoteAddr())

		go forward(client, *targetAddr)
	}
}

func forward(client net.Conn, targetAddr string) {
	defer client.Close()

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	target, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("连接目标 %s 失败：%v", targetAddr, err)
		return
	}
	defer target.Close()

	log.Printf("转发开始: %s <-> %s", client.RemoteAddr(), targetAddr)

	done := make(chan copyResult, 2)

	go pipe("client -> target", target, client, done)
	go pipe("target -> client", client, target, done)

	for i := 0; i < 2; i++ {
		result := <-done
		if result.err != nil {
			log.Printf("%s 结束: bytes=%d err=%v", result.direction, result.bytes, result.err)
		} else {
			log.Printf("%s 结束: bytes=%d", result.direction, result.bytes)
		}
	}
	log.Printf("连接关闭：%s", client.RemoteAddr())
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

type closeWriter interface {
	CloseWrite() error
}

func pipe(direction string, dst net.Conn, src net.Conn, done chan<- copyResult) {
	bytes, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		if closeErr := tcpConn.CloseWrite(); err == nil && closeErr != nil {
			err = closeErr
		}
	}
	done <- copyResult{
		direction: direction,
		bytes:     bytes,
		err:       err,
	}
}
