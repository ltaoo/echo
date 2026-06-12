# 进程级 TCP 拦截到 Echo 代理链路

本文记录指定进程流量如何进入 Echo 代理链路。Windows 当前有 WinDivert + TCP relay 链路；macOS/Linux 当前主要走 TUN forwarder 链路。示例进程使用 `WechatAppEx.exe` / `WeChatAppEx`。

## Windows 组件分工

这条链路由两个服务和一个拦截器组成：

```text
Echo HTTP proxy
  监听示例: 127.0.0.1:8899
  作用: 接收标准 HTTP 代理请求，包括普通 HTTP proxy 请求和 CONNECT 隧道请求。

Windows TCP relay
  监听示例: 127.0.0.1:34010
  作用: 接收被 WinDivert 重定向过来的原始 TCP 连接，查回原始目标地址，然后转换成 Echo 能处理的 HTTP 代理协议。

WinDivert interceptor
  作用: 在网络层捕获 TCP 包，识别连接所属进程，按规则决定 PROXY / DIRECT / BLOCK。
```

关键源码：

- `windows/interceptor.go`: 负责 WinDivert 捕获、进程识别、规则匹配、包改写。
- `windows/rule.go`: 定义进程规则和匹配逻辑。
- `windows/process.go`: 通过 Windows TCP 表从连接反查 PID 和进程路径。
- `windows/nat.go`: 保存源端口到原始目标地址的映射。
- `windows/relay.go`: 接收重定向连接，转换为 Echo HTTP proxy / CONNECT 请求。

## Windows 总体链路

以 `WechatAppEx.exe` 访问 HTTPS 目标为例：

```text
WechatAppEx.exe
  -> 发起 TCP 连接到 目标 IP:443
  -> WinDivert 捕获 outbound TCP 包
  -> interceptor 通过 srcIP + srcPort 反查 PID
  -> 通过 PID 获取进程路径/名称
  -> 命中 WechatAppEx.exe 的代理规则
  -> NAT 表记录: srcPort -> 原始目标 IP:443
  -> interceptor 将 TCP 目的端口改写为本地 relay 端口 34010
  -> Windows TCP relay 接收到这个连接
  -> relay 根据客户端源端口查 NAT 表，得到原始目标 IP:443
  -> relay 向 Echo HTTP proxy 发送 CONNECT 原始目标IP:443
  -> Echo 建立隧道，执行插件、匹配、上游代理等逻辑
  -> 流量到达目标站点或上游代理
```

简化成一行：

```text
WechatAppEx.exe -> WinDivert interceptor -> Windows TCP relay -> Echo HTTP proxy -> target/upstream
```

## Windows 进程级拦截如何发生

`Interceptor.Start()` 会先启动本地 TCP relay，然后打开 WinDivert 句柄捕获 TCP 包。默认 relay 地址类似：

```text
127.0.0.1:34010
```

新 TCP 连接进入 `processOutbound` 后，interceptor 会读取：

```text
srcIP
srcPort
dstIP
dstPort
```

随后通过 `srcIP + srcPort` 查询 Windows TCP 表，找到拥有这条连接的 PID，再通过 PID 查询进程路径。

规则示例：

```go
interceptor.AddRule(&windows.ProcessRule{
	ProcessName: "WechatAppEx.exe",
	TargetHosts: "*",
	TargetPorts: "80;443",
	Action:      windows.ActionProxy,
	Enabled:     true,
})
```

规则匹配时，`ProcessName` 可以是文件名，也可以带通配符，例如：

```text
WechatAppEx.exe
WeChat*.exe
*
```

如果规则返回 `ActionProxy`，interceptor 会进入代理路径；如果返回 `ActionDirect`，包保持原样放行；如果返回 `ActionBlock`，包会被丢弃。

## Windows NAT 表的作用

WinDivert 修改 TCP 包时，只把连接导向本地 relay。relay 接到连接后，必须知道这个连接原本要去哪里。

因此在重定向前，interceptor 会写入 NAT 表：

```text
key:   客户端源端口 srcPort
value: 原始目标 IP + 原始目标端口
```

例如：

```text
srcPort 52341 -> 203.0.113.10:443
```

relay 接受连接后，从 `clientConn.RemoteAddr()` 获取客户端源端口 `52341`，再查 NAT 表得到原始目标 `203.0.113.10:443`。

这个设计让 relay 不需要理解进程规则，也不需要直接接触 WinDivert 包。它只负责“把已经决定要代理的连接送进 Echo”。

## Windows relay 如何转成 Echo 代理请求

Windows relay 拿到原始目标后，根据目标端口选择代理协议：

```text
目标端口是 80:
  按明文 HTTP 处理，将请求改写为 HTTP proxy 的 absolute URL 形式。

其他端口:
  向 Echo 发送 CONNECT host:port，建立 TCP 隧道。
```

HTTPS 常见路径是：

```http
CONNECT 203.0.113.10:443 HTTP/1.1
Host: 203.0.113.10:443
```

Echo HTTP proxy 返回 `200` 后，relay 开始双向转发：

```text
WechatAppEx.exe <-> Windows TCP relay <-> Echo HTTP proxy <-> target/upstream
```

## Windows 为什么 relay 和 Echo proxy 是两个端口

Echo HTTP proxy 端口接收的是标准 HTTP 代理协议，例如：

```http
CONNECT example.com:443 HTTP/1.1
```

而透明拦截来的 TCP 连接不是 HTTP 代理请求。HTTPS 连接的第一包通常是 TLS ClientHello，明文 HTTP 连接也通常是 origin-form 请求，不是代理服务期望的格式。

因此当前实现使用两个监听端口：

```text
Echo proxy port:
  面向标准 HTTP 代理客户端。

TCP relay port:
  面向 WinDivert 重定向过来的原始 TCP 连接。
```

relay 是适配层，负责把原始连接转换为 Echo proxy 能处理的协议。

## Windows relay 和普通 TCPRelay 的区别

项目根目录下的 `tcp_relay.go` 也实现了一个通用 TCP relay，但它和 Windows relay 的目标地址来源不同：

```text
普通 TCPRelay:
  从流量内容推断目标地址。
  HTTPS 依赖 TLS ClientHello 里的 SNI。
  明文 HTTP 依赖 Host header。

Windows relay:
  从 NAT 表获取原始目标地址。
  NAT 表由 WinDivert interceptor 在重定向前写入。
```

所以 Windows 进程级代理不依赖 SNI 来判断目标地址。即使目标是 IP:443，relay 也能从 NAT 表拿到原始目标。

## macOS/Linux 组件分工

macOS/Linux 下实现进程代理时，当前项目主要依赖 TUN forwarder，而不是 WinDivert 和本地 TCP relay。

```text
Echo HTTP proxy
  监听示例: 127.0.0.1:8899
  作用: 接收 TUN proxy outbound 发来的 HTTP proxy / CONNECT 请求，并执行 Echo 插件、匹配、上游代理等逻辑。

TUN forwarder
  作用: 创建虚拟网卡和路由，让系统流量进入 TUN stack；对每条 TCP 连接查找所属进程，按 route.rules 选择 outbound。

Process searcher
  作用: 根据 TCP/UDP 四元组查找连接所属进程路径。
```

关键源码：

- `tun/tun.go`: 创建 TUN 设备、网络栈、进程 searcher、outbound map。
- `tun/handler_tcp.go`: TUN TCP 连接处理，查进程、嗅探 SNI、匹配路由、拨出 outbound。
- `tun/router.go`: 根据 `process_name` / domain / IP / port 规则选择 outbound。
- `tun/config.go`: 定义 TUN 配置、route rules 和 outbounds。
- `tun/routerhandler/searcher_darwin.go`: macOS 连接到进程的反查实现。
- `tun/routerhandler/searcher_linux.go`: Linux 连接到进程的反查实现。
- `tun/outbound.go`: `direct` / `http` / `socks5` outbound 的统一拨号接口。

## macOS/Linux 总体链路

以 `WeChatAppEx` 访问 HTTPS 目标为例：

```text
WeChatAppEx
  -> 发起 TCP 连接到 目标 IP:443
  -> 系统路由把连接导入 TUN 虚拟网卡
  -> sing-tun stack 调用 tunHandler.NewConnectionEx
  -> handler 根据 source/destination 查找连接所属进程
  -> handler 尝试读取首包，嗅探 TLS SNI
  -> matchRoute 按 process_name/domain/ip/port 规则选择 outbound
  -> 如果命中 proxy outbound:
       通过 HTTP proxy client 连接 Echo HTTP proxy，例如 127.0.0.1:8899
       Echo 收到 CONNECT 目标地址，继续处理和转发
  -> 如果命中 direct outbound:
       绑定真实物理网卡直连目标，避免回到 TUN
```

简化成一行：

```text
WeChatAppEx -> TUN forwarder -> route.rules -> proxy outbound -> Echo HTTP proxy -> target/upstream
```

直连路径是：

```text
WeChatAppEx -> TUN forwarder -> route.rules -> direct outbound -> physical interface -> target
```

## macOS 进程识别链路

macOS 的 searcher 通过内核 sysctl 快照反查连接所属进程：

```text
TCP:
  sysctl net.inet.tcp.pcblist_n

UDP:
  sysctl net.inet.udp.pcblist_n
```

处理流程：

```text
source/destination 四元组
  -> 读取 tcp/udp pcb list 快照
  -> 匹配 local addr/port 与 remote addr/port
  -> 取 xsocket 中的 lastPID 和 UID
  -> 通过 proc_info 查询 PID 对应可执行文件路径
  -> 返回 ConnectionOwner.ProcessPath
```

随后 `tun/router.go` 会取 `filepath.Base(owner.ProcessPath)`，和配置中的 `process_name` 做精确匹配。

示例：

```text
/Applications/WeChat.app/Contents/MacOS/WeChat
  -> process base name: WeChat
```

## Linux 进程识别链路

Linux 的 searcher 先用 Netlink socket diag 查连接对应的 socket inode 和 UID，再扫描 `/proc` 找到持有该 socket 的进程：

```text
source/destination 四元组
  -> NETLINK_INET_DIAG 查询 socket inode + uid
  -> 扫描 /proc/<pid>/fd
  -> 匹配 socket:[inode]
  -> 读取 /proc/<pid>/exe
  -> 返回 ConnectionOwner.ProcessPath
```

也就是说，Linux 的进程识别核心不是改包，而是从内核连接表拿 socket inode，再反查进程 fd。

示例：

```text
/opt/wechat/WeChatAppEx
  -> process base name: WeChatAppEx
```

## macOS/Linux 路由规则

TUN 的路由规则定义在 `tun.RuleConfig`：

```go
type RuleConfig struct {
	ProcessName  []string `json:"process_name,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	IPCidr       []string `json:"ip_cidr,omitempty"`
	Port         []uint16 `json:"port,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	Invert       bool     `json:"invert,omitempty"`
	Outbound     string   `json:"outbound"`
}
```

一个典型配置：

```json
{
  "enabled": true,
  "inbound": {
    "inet4_address": "10.99.99.1/30",
    "mtu": 1500,
    "auto_route": true,
    "strict_route": true,
    "sniff": true
  },
  "outbounds": [
    {"tag": "proxy", "type": "http", "server": "127.0.0.1", "port": 8899},
    {"tag": "direct", "type": "direct"}
  ],
  "route": {
    "rules": [
      {"process_name": ["WeChat", "WeChatAppEx", "WeChatAppEx.exe"], "outbound": "proxy"},
      {"domain_suffix": ["qq.com"], "outbound": "proxy"}
    ],
    "final": "direct"
  },
  "dns": {
    "fake_dns": true,
    "fake_dns_range": "198.18.0.0/15"
  }
}
```

命中 `proxy` 时，TUN handler 会通过 `httpOutbound` 拨到 Echo HTTP proxy；命中 `direct` 时，会通过 `directOutbound` 绑定真实默认网卡直连。

## macOS/Linux DNS 和域名辅助

TUN handler 除了按进程名匹配，还会尝试恢复域名信息：

```text
1. TCP 首包嗅探 TLS ClientHello，提取 SNI。
2. 如果目标是 fakeDNS IP，则通过 fakeDNS 反查域名。
3. DNS 响应会被解析并写入 dnsCache，后续可用 IP 反查域名。
```

域名信息会用于 `domain` / `domain_suffix` 路由规则，也会影响拨号目标：

```text
有 sniffedDomain:
  proxy outbound 使用 domain:port，让 Echo/上游代理看到域名目标。

direct outbound:
  先通过 directDialer 解析域名，再绑定物理网卡直连。
```

## macOS/Linux 和 Windows 的核心差异

```text
Windows WinDivert 链路:
  捕获网络包
  按进程规则改写目标端口到 relay
  relay 查 NAT 表拿原始目标
  relay 转成 Echo HTTP proxy / CONNECT 请求

macOS/Linux TUN 链路:
  系统路由把流量导入 TUN
  TUN stack 直接拿到连接对象和原始目标
  handler 查进程、匹配 route.rules
  handler 直接选择 proxy/direct/socks5 outbound
```

因此 macOS/Linux 的进程代理链路里通常不需要单独的 TCP relay 端口。`proxy` outbound 本身就是一个 HTTP proxy client，它会直接连接 Echo HTTP proxy。

## 跨平台关键边界

- Windows 的进程级判断发生在 `windows/interceptor.go`，不是 relay 内部。
- Windows relay 只处理已经被 interceptor 判定为 `ActionProxy` 的连接。
- Windows WinDivert 链路默认不会代理 DNS 端口 53，除非显式启用 DNS via proxy。
- Windows WinDivert 链路会跳过 loopback、广播、多播目标，避免本地回环和异常网络目标被代理。
- Windows relay 回连 Echo proxy 时，需要避免被再次拦截，否则可能产生回环。
- macOS/Linux TUN 链路依赖系统路由把流量导入 TUN；如果路由没有生效，进程规则不会触发。
- macOS/Linux 的 `process_name` 当前按进程路径 basename 做匹配，分享配置时要注意不同平台可执行文件名可能不同。
- macOS/Linux 的 `direct` outbound 必须绑定真实物理网卡拨出，避免直连流量再次进入 TUN。
- macOS/Linux 的 `proxy` outbound 会直接连接 Echo HTTP proxy，不需要经过 TCP relay 端口。
