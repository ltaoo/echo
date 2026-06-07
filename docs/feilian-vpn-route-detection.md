# Feilian VPN 开启但默认路由检查未显示的原因

场景：

用户确认 Windows 10 上已开启 Feilian VPN，但执行默认路由快速判断命令后，只看到类似结果：

```text
ifIndex InterfaceAlias NextHop     RouteMetric InterfaceMetric
------- -------------- -------     ----------- ---------------
     53 Meta           198.18.0.2            0
     15 Ethernet 2     192.168.1.1           0 25
     14 Wi-Fi          192.168.1.1           0 35
```

快速判断命令通常是：

```powershell
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 |
  Sort-Object RouteMetric, InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
```

## 结论

这个命令只检查 IPv4 默认路由 `0.0.0.0/0`，不是检测所有 VPN 或所有虚拟网卡。

因此，Feilian VPN 已开启但没有出现在输出中，并不代表 Feilian 没运行。它只说明：Feilian 当前没有作为 IPv4 默认公网出口，或者没有通过标准默认路由方式接管流量。

当前输出中，默认公网出口优先落到了 `Meta -> 198.18.0.2`，不是 Feilian。Feilian 仍可能在后台对公司内网、DNS 或特定应用生效。

## 常见原因

### 1. Feilian 使用分流 VPN

很多企业 VPN 不会接管全局默认路由，而是只下发公司内网路由，例如：

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.x.0/24`
- 公司办公系统的专用网段

这种情况下，`0.0.0.0/0` 默认路由里不会显示 Feilian，但访问公司内网时仍会走 Feilian。

### 2. Feilian 不通过默认路由接管流量

企业 VPN 可能通过以下方式控制流量：

- WFP 驱动
- 虚拟网卡加精细路由
- DNS 策略
- 进程级策略
- 内网域名解析策略
- 安全客户端内置代理

这些方式不一定表现为 `0.0.0.0/0` 默认路由。

### 3. Feilian 的接口名称不是 `Feilian`

Windows 中显示的接口名可能不是产品名，可能是：

- 某个 TAP/Wintun 适配器
- 企业 VPN 自定义网卡名
- 厂商驱动名
- 通用虚拟网卡名

查看完整适配器列表：

```powershell
Get-NetAdapter |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

如果要看启用中的适配器：

```powershell
Get-NetAdapter | ? Status -eq Up |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

### 4. Feilian 只下发特定 IPv4 路由或 IPv6 路由

默认路由检查只查 `0.0.0.0/0`。如果 Feilian 下发的是特定网段路由，或者只影响 IPv6，默认路由列表不会体现。

查看所有路由：

```powershell
Get-NetRoute |
  Sort-Object InterfaceAlias, DestinationPrefix |
  Format-Table ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric
```

查看 IPv6 默认路由：

```powershell
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" |
  Sort-Object RouteMetric, InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
```

## 推荐排查命令

查看所有启用网卡：

```powershell
Get-NetAdapter | ? Status -eq Up |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

查看所有接口 metric：

```powershell
Get-NetIPInterface |
  Sort-Object InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, AddressFamily, InterfaceMetric, ConnectionState
```

查看非真实出口网卡的路由：

```powershell
Get-NetRoute |
  Where-Object { $_.InterfaceAlias -notin @("Ethernet 2", "Wi-Fi", "Meta") } |
  Format-Table ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric
```

如果怀疑 Feilian 使用特定公司网段，可以用目标内网 IP 检查实际会走哪条路由：

```powershell
Find-NetRoute -RemoteIPAddress "10.0.0.1"
```

把 `"10.0.0.1"` 替换为实际公司内网服务 IP。

也可以用传统命令查看完整路由表：

```powershell
route print
```

## 与 sing-tun 报错的关系

`tun.Start: no default network interface detected - check your network connection` 关注的是 sing-tun/sing-box 能否找到可用的默认出站接口。

如果 Feilian 没有接管 `0.0.0.0/0` 默认路由，它就不一定会出现在快速判断结果里；真正影响当前 sing-tun 默认出口判断的，反而是排在最前面的 `Meta -> 198.18.0.2`。

因此本用例的优先处理方向仍然是：

1. 先处理 `Meta` 虚拟网卡抢默认路由的问题。
2. 再确认 Feilian 是否只负责公司内网分流。
3. 如果 sing-tun 必须和 Feilian 共存，显式配置 sing-tun 的真实出口网卡，例如 `Ethernet 2` 或 `Wi-Fi`。

