//go:build manual

package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ltaoo/echo"
)

//go:embed SunnyRoot.cer
var linuxCertFile []byte

//go:embed private.key
var linuxKeyFile []byte

const manualTitle = "[echo linux] title modified"

var manualTitleTagPattern = regexp.MustCompile(`(?is)(<title\b[^>]*>).*?(</title>)`)

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "HTTP proxy listen address")
	tcpRelay := flag.String("tcp-relay", "", "transparent TCP relay listen address, e.g. 127.0.0.1:9900")
	upstream := flag.String("upstream", "", "upstream proxy, e.g. http://127.0.0.1:7890")
	dns := flag.String("dns", "", "DNS server for echo outbound resolution, e.g. 223.5.5.5:53")
	dnsNetwork := flag.String("dns-network", "tcp", "DNS transport network: tcp or udp")
	flag.Parse()

	if *dns != "" {
		setDefaultResolver(*dns, *dnsNetwork)
	}

	listenAddr := *addr
	e, err := echo.NewEchoWithOptions(linuxCertFile, linuxKeyFile, &echo.Options{
		InterceptOnlyMatched: true,
		UpstreamProxy:        *upstream,
	})
	if err != nil {
		log.Fatalf("create echo: %v", err)
	}
	defer e.Close()

	e.AddPlugin(&echo.Plugin{
		Match: "**.qq.com",
		OnRequest: func(ctx *echo.Context) {
			if ctx.Req == nil {
				return
			}
			log.Printf("[QQ] %s %s", ctx.Req.Method, ctx.Req.URL.String())
		},
		OnResponse: func(ctx *echo.Context) {
			if ctx.Res == nil || !isManualWebPage(ctx.Res) {
				return
			}
			body, err := ctx.GetResponseBody()
			if err != nil {
				log.Printf("[QQ] read response body: %v", err)
				return
			}
			body = manualTitleTagPattern.ReplaceAllString(body, "${1}"+manualTitle+"${2}")
			ctx.SetResponseBody(body)
		},
	})

	if *tcpRelay != "" {
		if err := e.ListenTCP(*tcpRelay, listenAddr); err != nil {
			log.Fatalf("start tcp relay: %v", err)
		}
		defer e.ShutdownTCP()
		log.Printf("Transparent TCP relay listening on %s -> %s", *tcpRelay, listenAddr)
	}

	server := &http.Server{
		Addr: listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.ServeHTTP(w, r)
		}),
	}

	fmt.Printf("Echo qq.com proxy listening on %s\n", listenAddr)
	fmt.Println("Configure your browser/system HTTP proxy to this address and visit a qq.com subdomain.")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func isManualWebPage(res *http.Response) bool {
	contentType := strings.ToLower(res.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml")
}

func setDefaultResolver(server, dnsNetwork string) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	if dnsNetwork != "udp" {
		dnsNetwork = "tcp"
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, dnsNetwork, server)
		},
	}
	log.Printf("Using DNS resolver %s over %s", server, dnsNetwork)
}
