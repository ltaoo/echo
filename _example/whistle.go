//go:build windows

// Whistle 风格 TUN mock 示例：无需设置系统代理或浏览器代理，
// 直接在浏览器访问不存在的域名 local.whistlejs.com 即可看到 mock 页面。
//
// ## 工作流程
//
//  1. 浏览器访问 http://local.whistlejs.com/
//  2. DNS 查询被 TUN fakeDNS 劫持 → 返回假 IP (198.18.0.x)
//  3. TCP 连接到假 IP 被 TUN 截获 → 反向解析得到域名
//  4. 路由规则 domain_suffix: whistlejs.com → proxy 出站
//  5. proxy 出站通过 CONNECT 隧道转发到 echo HTTP 代理 (127.0.0.1:8899)
//  6. echo 代理匹配插件 → 本地返回 mock HTML (无需连接真实目标)
//
// ## DNS 问题的解决
//
//  local.whistlejs.com 不存在于公共 DNS，但通过 fakeDNS 机制：
//    - TUN 层拦截所有 DNS 查询，匹配路由规则中的 domain_suffix
//    - 命中后直接返回假 IP，应用拿到一个"可用"的 IP 地址
//    - 后续 TCP 连接指向假 IP，TUN 反向解析出真实域名进行路由
//    - 代理层的 Mock 在 OnRequest 阶段就返回，完全不触发外部连接
//
// 用法（以管理员身份运行）:
//
//	go run ./_example/whistle.go
//
// 启动后直接在浏览器访问 http://local.whistlejs.com/
// 也支持 HTTPS: https://local.whistlejs.com/ (浏览器会提示证书，信任即可)
package main

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ltaoo/echo"
	"github.com/ltaoo/echo/tun"
)

//go:embed SunnyRoot.cer
var certFile []byte

//go:embed private.key
var keyFile []byte

func main() {
	// 1. 构建 TUN 配置
	cfg := tun.DefaultConfig()
	cfg.Inbound.Inet4Address = "10.99.99.1/30"
	cfg.Inbound.AutoRoute = true
	cfg.Inbound.StrictRoute = true
	cfg.Inbound.Sniff = true
	cfg.DNS.FakeDNS = true
	cfg.DNS.FakeDNSRange = "198.18.0.0/15"
	cfg.Outbounds = []tun.OutboundConfig{
		{Tag: "proxy", Type: "http", Server: "127.0.0.1", Port: 8899},
		{Tag: "direct", Type: "direct"},
	}
	// 关键规则：whistlejs.com 域名 → fakeDNS 劫持 + 路由到 proxy
	cfg.Route.Rules = []tun.RuleConfig{
		{
			DomainSuffix: []string{"whistlejs.com"},
			Outbound:     "proxy",
		},
	}
	cfg.Route.Final = "direct"

	// 2. 创建 Echo 实例，开启 TUN 模式
	e, err := echo.NewEchoWithOptions(certFile, keyFile, &echo.Options{
		InterceptOnlyMatched: true,
		Tun:                  true,
		TunConfig:            cfg,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create echo: %v\n", err)
		os.Exit(1)
	}
	defer e.Close()

	// 3. 注册 mock 插件
	e.AddPlugin(&echo.Plugin{
		Match: "local.whistlejs.com",
		OnRequest: func(ctx *echo.Context) {
			ctx.Mock(200, map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			}, mockHTML)
		},
	})

	// 4. 启动 HTTP 代理服务 (TUN proxy 出站的目标)
	proxyAddr := "127.0.0.1:8899"
	server := &http.Server{
		Addr: proxyAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.ServeHTTP(w, r)
		}),
	}
	go func() {
		log.Printf("Echo proxy listening on %s", proxyAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy server: %v", err)
		}
	}()

	fmt.Println("============================================")
	fmt.Println("Echo Whistle TUN Mode")
	fmt.Println("============================================")
	fmt.Println("  No proxy configuration needed!")
	fmt.Println("  Open browser and visit:")
	fmt.Println("    http://local.whistlejs.com/")
	fmt.Println("    https://local.whistlejs.com/")
	fmt.Println("============================================")
	fmt.Println("Press Ctrl+C to stop")

	// 5. 等待退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	server.Close()
	fmt.Println("Done.")
}

const mockHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Echo Whistle TUN Mock</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
         min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #fff; border-radius: 12px; padding: 40px; max-width: 620px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center; }
  h1 { color: #333; margin-bottom: 8px; font-size: 28px; }
  .badge { display: inline-block; background: #667eea; color: #fff; padding: 4px 16px;
           border-radius: 20px; font-size: 14px; margin-bottom: 24px; }
  .flow { display: flex; justify-content: center; gap: 8px; flex-wrap: wrap;
          margin: 20px 0; font-size: 12px; color: #666; }
  .flow span { background: #f0f0f0; padding: 6px 12px; border-radius: 6px;
               white-space: nowrap; }
  .arrow { color: #667eea; font-weight: bold; }
  table { width: 100%; border-collapse: collapse; text-align: left; margin: 20px 0; }
  th { background: #f8f9fa; padding: 10px 14px; font-size: 13px; color: #666; }
  td { padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 14px; color: #444; }
  .ok { color: #22c55e; font-weight: 600; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 8px;
        text-align: left; font-size: 13px; overflow-x: auto; margin-top: 16px; }
  .comment { color: #6a9955; }
  .key { color: #9cdcfe; }
</style>
</head>
<body>
<div class="card">
  <h1>local.whistlejs.com</h1>
  <div class="badge">Echo TUN Mock — No Proxy Config</div>

  <div class="flow">
    <span>&#127760; Browser</span>
    <span class="arrow">&rarr;</span>
    <span>&#128225; DNS Query</span>
    <span class="arrow">&rarr;</span>
    <span>&#127925; TUN fakeDNS</span>
    <span class="arrow">&rarr;</span>
    <span>&#128279; Fake IP</span>
    <span class="arrow">&rarr;</span>
    <span>&#128295; TUN Route</span>
    <span class="arrow">&rarr;</span>
    <span>&#9881; Echo Proxy</span>
    <span class="arrow">&rarr;</span>
    <span>&#10003; Mock HTML</span>
  </div>

  <table>
    <tr><th>组件</th><th>状态</th></tr>
    <tr><td>TUN 虚拟网卡</td><td class="ok">&#10003; 运行中</td></tr>
    <tr><td>FakeDNS 劫持</td><td class="ok">&#10003; whistlejs.com &rarr; 198.18.0.x</td></tr>
    <tr><td>路由规则</td><td class="ok">&#10003; domain_suffix: whistlejs.com &rarr; proxy</td></tr>
    <tr><td>代理 Mock</td><td class="ok">&#10003; 本地返回 (无外部连接)</td></tr>
    <tr><td>DNS 依赖</td><td class="ok">&#10003; 零依赖 (fakeDNS 绕过)</td></tr>
    <tr><td>系统/浏览器代理</td><td class="ok">&#10003; 无需配置</td></tr>
  </table>

  <pre><span class="comment">// TUN 模式下完全不需要设置系统代理</span>
<span class="comment">// 网卡层面劫持 DNS + 路由，透明转发</span>
<span class="comment">// 域名 local.whistlejs.com 并不存在于公共 DNS</span>
<span class="comment">// 但 fakeDNS 在 DNS 层直接返回假 IP 给应用</span>

<span class="key">cfg</span> := tun.<span class="key">DefaultConfig</span>()
cfg.Route.Rules = []tun.RuleConfig{{
    <span class="key">DomainSuffix</span>: []<span class="string">string</span>{<span class="string">"whistlejs.com"</span>},
    <span class="key">Outbound</span>:     <span class="string">"proxy"</span>,
}}
<span class="comment">// fakeDNS 会自动为匹配 domain_suffix 的域名</span>
<span class="comment">// 返回假 IP，后续 TCP 连接被 TUN 拦截后</span>
<span class="comment">// 通过路由规则转发到 echo 代理处理</span></pre>
</div>
</body>
</html>`
