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

	// 使用 NewEchoWithOptions 配置代理行为
	// - EnableBuiltinBypass: 自动透传 ChatGPT、Apple、Google 等使用证书固定的服务
	// - InterceptOnlyMatched: 只拦截有插件匹配的请求，其他流量直接透传
	//   这样设置为系统代理后，不会影响其他应用的正常使用
	// - UpstreamProxy: 配置上游代理，让 echo 转发所有请求到指定代理
	//   这样就可以配合其他代理软件一起使用：
	//   1. 设置系统代理为其他代理（如 8899）
	//   2. 配置 UpstreamProxy 为 echo（如 127.0.0.1:8888）
	//   请求流程：应用 -> 其他代理(8899) -> echo(8888) -> UpstreamProxy -> 目标
	echo_proxy, err := echo.NewEchoWithOptions(cert_file, private_key_file, &echo.Options{
		EnableBuiltinBypass:  false,
		InterceptOnlyMatched: true,
		// UpstreamProxy: "http://127.0.0.1:7890", // 启用上游代理（如 Clash、V2Ray 等）
	})
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

	// 用例6: 手动添加自定义 bypass 域名
	// echo_proxy.AddPlugin(&echo.Plugin{
	// 	Match:  "custom-domain.com",
	// 	Bypass: true,
	// })

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
