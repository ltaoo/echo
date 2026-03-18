//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ltaoo/echo"
	"github.com/ltaoo/echo/windows"
)

//go:embed SunnyRoot.cer
var certFile []byte

//go:embed private.key
var keyFile []byte

//go:embed WinDivert.dll
var winDivertDLL []byte

//go:embed WinDivert64.sys
var winDivert64Sys []byte

// extractWinDivert 将嵌入的 WinDivert 文件释放到 exe 同目录，已存在则跳过
func extractWinDivert() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	dir := filepath.Dir(exePath)
	dllPath := filepath.Join(dir, "WinDivert.dll")
	sysPath := filepath.Join(dir, "WinDivert64.sys")
	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		if err := os.WriteFile(dllPath, winDivertDLL, 0644); err != nil {
			return "", fmt.Errorf("failed to write WinDivert.dll: %w", err)
		}
	}
	if _, err := os.Stat(sysPath); os.IsNotExist(err) {
		if err := os.WriteFile(sysPath, winDivert64Sys, 0644); err != nil {
			return "", fmt.Errorf("failed to write WinDivert64.sys: %w", err)
		}
	}
	return dllPath, nil
}

func main() {
	fmt.Println("=== Echo Channels 进程代理示例 ===")

	// 释放 WinDivert 到临时目录
	dllPath, err := extractWinDivert()
	if err != nil {
		fmt.Printf("释放 WinDivert 失败: %v\n", err)
		fmt.Println("按回车键退出...")
		fmt.Scanln()
		os.Exit(1)
	}
	windows.SetDLLPath(dllPath)
	fmt.Printf("WinDivert 已释放到: %s\n", filepath.Dir(dllPath))

	echoProxy, err := echo.NewEchoWithOptions(certFile, keyFile, &echo.Options{
		InterceptOnlyMatched: true,
	})
	if err != nil {
		fmt.Printf("创建 Echo 代理失败: %v\n", err)
		fmt.Println("按回车键退出...")
		fmt.Scanln()
		os.Exit(1)
	}

	// 注册插件：拦截 channels.weixin.qq.com 的 HTML 响应并注入脚本
	echoProxy.AddPlugin(&echo.Plugin{
		Match: "channels.weixin.qq.com",
		OnResponse: func(ctx *echo.Context) {
			res := ctx.Res
			if res == nil {
				return
			}
			contentType := res.Header.Get("Content-Type")
			if !strings.Contains(contentType, "text/html") {
				return
			}
			html, err := ctx.GetResponseBody()
			if err != nil {
				log.Printf("Failed to read response body: %v", err)
				return
			}
			injectedScript := `<script>alert("[Echo] 进程代理注入成功"); document.title = "[Echo] " + document.title;</script>`
			html = strings.Replace(html, "<head>", "<head>\n"+injectedScript, 1)
			ctx.SetResponseBody(html)
		},
	})

	// 启动 HTTP 代理服务
	addr := "127.0.0.1:8899"
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			echoProxy.ServeHTTP(w, r)
		}),
	}
	go func() {
		log.Printf("Echo proxy listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// 创建进程拦截器，将微信流量透明代理到 Echo
	interceptor := windows.NewInterceptor(addr)
	interceptor.AddRule(&windows.ProcessRule{
		ProcessName: "WeChatAppEx.exe",
		TargetHosts: "*",
		TargetPorts: "80;443",
		Action:      windows.ActionProxy,
		Enabled:     true,
	})
	if err := interceptor.Start(); err != nil {
		fmt.Printf("启动拦截器失败: %v\n", err)
		fmt.Println("按回车键退出...")
		fmt.Scanln()
		os.Exit(1)
	}
	fmt.Println("拦截器已启动，正在拦截 WeChatAppEx.exe 流量...")
	fmt.Println("按 Ctrl+C 退出")

	// 等待 Ctrl+C 信号，优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n正在关闭...")
	if err := interceptor.Stop(); err != nil {
		log.Printf("Failed to stop interceptor: %v", err)
	}
	server.Close()
	fmt.Println("已退出")
}
