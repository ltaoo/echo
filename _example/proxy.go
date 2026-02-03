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
		Match: "site1.funzm.fun",
		Target: &echo.TargetConfig{
			Host: "127.0.0.1",
			Port: 8000,
		},
		OnResponse: func(ctx *echo.Context) {
			res := ctx.Res
			if res == nil {
				return
			}
			res.Header.Set("x-echo", "1")
		},
	})
	echo_proxy.AddPlugin(&echo.Plugin{
		Match: "site2.funzm.fun",
		Target: &echo.TargetConfig{
			Host: "127.0.0.1",
			Port: 3333,
		},
		OnResponse: func(ctx *echo.Context) {
			res := ctx.Res
			if res == nil {
				return
			}
			res.Header.Set("x-echo", "1")
		},
	})

	// 修复 App Store 访问问题 - Apple 域名直接隧道，不进行 MITM 拦截
	// 这确保了 Apple 服务的证书验证正常工作
	// apple_domains := []string{
	// 	"*.apple.com",
	// 	"*.icloud.com",
	// 	"*.icloud-content.com",
	// 	"*.apps.apple.com",
	// 	"*.itunes.apple.com",
	// 	"*.mzstatic.com",
	// 	"*.cdn-apple.com",
	// }

	// for _, domain := range apple_domains {
	// 	echo_proxy.AddPlugin(&echo.Plugin{
	// 		Match: domain,
	// 		OnRequest: func(ctx *echo.Context) {
	// 			// 对于 Apple 域名，确保直接连接不修改任何内容
	// 			// 这里只是记录日志，不进行拦截
	// 			fmt.Printf("[Apple Bypass] Direct tunnel for Apple service: %s\n", ctx.Req.URL.Host)
	// 		},
	// 	})
	// }

	PORT := "127.0.0.1:8899"
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
		return
	}
	fmt.Println("the server is running")
}
