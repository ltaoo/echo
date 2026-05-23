//go:build windows

// TUN 进程级流量转发示例
//
// 用法（以管理员身份运行）:
//
//	go run ./_example/tun.go                    # 使用 demo 配置
//	go run ./_example/tun.go -c config.json     # 从文件加载配置
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
//	    "rules": [
//	      {"process_name": ["WeChat.exe"], "outbound": "proxy"},
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
		cfg = tun.DefaultConfig()
		// Demo rules
		cfg.Route.Rules = []tun.RuleConfig{
			{
				ProcessName: []string{"WeChat.exe", "WeChatAppEx.exe", "Weixin.exe"},
				Outbound:    "proxy",
			},
			{
				DomainSuffix: []string{"qq.com"},
				Outbound:     "proxy",
			},
		}
		cfg.Route.Final = "direct"
		fmt.Println("Using demo config")
	}
	fmt.Printf("  outbounds: %d, rules: %d, final: %s\n",
		len(cfg.Outbounds), len(cfg.Route.Rules), cfg.Route.Final)

	// 2. Create Echo with TUN enabled.
	//    TUN 工作流程:
	//    a. 创建虚拟网卡，添加路由让所有流量经过 TUN
	//    b. 对每条 TCP 连接: 查找进程 → SNI 嗅探域名 → 匹配规则 → 转发到对应出站
	//    c. proxy 出站 → echo HTTP 代理 (127.0.0.1:8899)
	//    d. direct 出站 → 绑定物理网卡直连
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

	// 3. Start HTTP proxy server.
	//    TUN 中 proxy 出站的目标必须与此地址一致。
	proxyAddr := "127.0.0.1:8899"
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
