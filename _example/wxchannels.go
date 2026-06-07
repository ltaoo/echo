//go:build windows

// TUN 进程级流量转发示例
//
// 用法（以管理员身份运行）:
//
//	go run ./_example/wxchannels.go                         # 使用业务一致配置
//	go run ./_example/wxchannels.go -proxy-port 8899        # 指定本地 echo 代理端口
//	go run ./_example/wxchannels.go -default-interface "Ethernet 2"
//	go run ./_example/wxchannels.go -upstream http://127.0.0.1:7890
//	go run ./_example/wxchannels.go -c config.json          # 从文件加载 TUN 配置
//
// 配置文件示例 (config.json):
//
//	{
//	  "enabled": true,
//	  "inbound": {
//	    "inet4_address": "10.99.99.1/30",
//	    "mtu": 1500,
//	    "auto_route": true,
//	    "strict_route": true,
//	    "sniff": true
//	  },
//	  "outbounds": [
//	    {"tag": "proxy", "type": "http", "server": "127.0.0.1", "port": 8899},
//	    {"tag": "direct", "type": "direct"}
//	  ],
//	  "route": {
//	    "default_interface": "Ethernet 2",
//	    "rules": [
//	      {"process_name": ["wx_video_download", "wx_video_download.exe", "wx_channel", "wx_channel.exe", "go", "go.exe", "main", "main.exe"], "outbound": "direct"},
//	      {"process_name": ["WeChat", "WeChatAppEx", "WeChatAppEx.exe", "Weixin.exe", "WeChatAppEx Helper"], "outbound": "proxy"},
//	      {"domain_suffix": ["qq.com"], "outbound": "proxy"}
//	    ],
//	    "final": "direct"
//	  },
//	  "dns": {"fake_dns": true, "fake_dns_range": "198.18.0.0/15"}
//	}
package main

import (
	_ "embed"
	"flag"
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
	configPath := flag.String("c", "", "path to tun config.json")
	upstreamProxy := flag.String("upstream", "", "upstream proxy, e.g. http://127.0.0.1:7890 or socks5://127.0.0.1:1080")
	proxyPort := flag.Int("proxy-port", 8899, "local echo HTTP proxy port")
	defaultInterface := flag.String("default-interface", "", "bind TUN outbound traffic to this Windows interface, e.g. Ethernet 2")
	flag.Parse()

	// 1. Load or build TUN config
	var cfg *tun.TunConfig
	if *configPath != "" {
		var err error
		cfg, err = tun.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Loaded config from %s\n", *configPath)
	} else {
		cfg = businessTunConfig(*proxyPort)
		fmt.Println("Using business-compatible TUN config")
	}
	setProxyOutboundPort(cfg, *proxyPort)
	fmt.Printf("  outbounds: %d, rules: %d, final: %s\n",
		len(cfg.Outbounds), len(cfg.Route.Rules), cfg.Route.Final)
	effectiveDefaultInterface := cfg.Route.DefaultInterface
	if *defaultInterface != "" {
		effectiveDefaultInterface = *defaultInterface
	}
	if effectiveDefaultInterface != "" {
		fmt.Printf("  default_interface: %s\n", effectiveDefaultInterface)
	}

	// 2. Create Echo with TUN enabled.
	//    TUN 工作流程:
	//    a. 创建虚拟网卡，添加路由让所有流量经过 TUN
	//    b. 对每条 TCP 连接: 查找进程 → SNI 嗅探域名 → 匹配规则 → 转发到对应出站
	//    c. proxy 出站 → echo HTTP 代理 (127.0.0.1:8899)
	//    d. direct 出站 → 绑定物理网卡直连
	opts := &echo.Options{
		EnableBuiltinBypass:  false,
		InterceptOnlyMatched: true,
		UpstreamProxy:        *upstreamProxy,
		Tun:                  true,
		TunConfig:            cfg,
		TunDefaultInterface:  *defaultInterface,
	}
	e, err := echo.NewEchoWithOptions(certFile, keyFile, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create echo: %v\n", err)
		os.Exit(1)
	}
	defer e.Close()

	// 3. Start HTTP proxy server.
	//    TUN 中 proxy 出站的目标必须与此地址一致。
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", *proxyPort)
	server := &http.Server{
		Addr: proxyAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.ServeHTTP(w, r)
		}),
	}
	go func() {
		log.Printf("Echo HTTP proxy listening on %s", proxyAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy server: %v", err)
		}
	}()

	fmt.Println("============================================")
	fmt.Println("Echo TUN forwarder running")
	fmt.Printf("  HTTP proxy: %s\n", proxyAddr)
	if *upstreamProxy != "" {
		fmt.Printf("  upstream:   %s\n", *upstreamProxy)
	}
	fmt.Println("  TUN mode:   process-based traffic forwarding")
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("============================================")

	// 4. Wait for Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	server.Close()
	fmt.Println("Done.")
}

func businessTunConfig(proxyPort int) *tun.TunConfig {
	cfg := tun.DefaultConfig()
	cfg.Inbound.AutoRoute = true
	cfg.Inbound.StrictRoute = true
	setProxyOutboundPort(cfg, proxyPort)
	cfg.Route = tun.RouteConfig{
		Rules: []tun.RuleConfig{
			// Highest priority: self-process direct to avoid loopback.
			{
				ProcessName: []string{
					"wx_video_download",
					"wx_video_download.exe",
					"wx_channel",
					"wx_channel.exe",
					"go",
					"go.exe",
					"main",
					"main.exe",
				},
				Outbound: "direct",
			},
			// WeChat processes through proxy.
			{
				ProcessName: []string{
					"WeChat",
					"WeChatAppEx",
					"WeChatAppEx.exe",
					"Weixin.exe",
					"WeChatAppEx Helper",
				},
				Outbound: "proxy",
			},
			// qq.com domains through proxy.
			{
				DomainSuffix: []string{"qq.com"},
				Outbound:     "proxy",
			},
		},
		Final: "direct",
	}
	return cfg
}

func setProxyOutboundPort(cfg *tun.TunConfig, proxyPort int) {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == "proxy" {
			cfg.Outbounds[i].Port = uint16(proxyPort)
		}
	}
}
