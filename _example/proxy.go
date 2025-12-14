package main

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ltaoo/echo"
)

//go:embed SunnyRoot.cer
var cert_file []byte

//go:embed private.key
var private_key_file []byte

func main() {
	// 1. Load Root CA
	// Assuming certs are in the current directory or a 'certs' subdirectory
	// You might need to adjust paths based on where you run the binary

	echo_proxy, err := echo.NewEcho(cert_file, private_key_file)
	if err != nil {
		fmt.Println("Failed to start echo server", err)
	}
	// 用例1 mock 响应
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "https://api.example.com/index.html",
		OnRequest: func(ctx *echo.Context) {
			ctx.Mock(200, map[string]string{
				"Content-Type": "text/html",
			}, "<html><body><h1>Hello echo</h1></body></html>")
		},
	})
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "https://api.example.com/api/data",
		OnRequest: func(ctx *echo.Context) {
			ctx.Mock(200, map[string]string{
				"Content-Type": "application/json",
			}, `{"ok":true}`)
		},
	})
	// 用例2 打印请求
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "*.baidu.com/*",
		OnRequest: func(ctx *echo.Context) {
			req := ctx.Req
			if req == nil {
				return
			}
			fmt.Println(req.URL)
		},
	})
	// 用例3 修改响应body
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "*.baidu.com/*",
		OnResponse: func(ctx *echo.Context) {
			res := ctx.Res
			if res == nil {
				return
			}
			content_type := res.Header.Get("Content-Type")
			fmt.Println(content_type)
			if strings.Contains(content_type, "text/html") {
				body, err := ctx.GetResponseBody()
				if err == nil {
					body = strings.Replace(body, "百度一下，你就知道", "Modify", -1)
					ctx.SetResponseBody(body)
				}
			}
		},
	})

	// 用例5 修改响应 headers
	// echo_proxy.AddPlugin(&echo.Plugin{
	// 	Match: "*.baidu.com",
	// 	OnResponse: func(ctx *echo.Context) {
	// 		res := ctx.Res
	// 		if res == nil {
	// 			return
	// 		}
	// 		res.Header.Set("_echo", "123")
	// 	},
	// })
	// 用例5 转发请求
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "https://www.aaa.com",
		Target: &echo.TargetConfig{
			Protocol: "https",
			Host:     "baidu.com",
			Port:     443,
		},
		OnResponse: func(ctx *echo.Context) {
			res := ctx.Res
			if res == nil {
				return
			}
			res.Header.Set("x-echo", "1")
		},
	})

	PORT := "127.0.0.1:1234"
	// 6. Start Server
	server := &http.Server{
		Addr: PORT,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			echo_proxy.ServeHTTP(w, r)
		}),
	}

	log.Printf("echo Proxy (Go) listening on port %s", PORT)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
