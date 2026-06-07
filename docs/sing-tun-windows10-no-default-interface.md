# Windows 10 sing-tun 默认网卡检测失败排查

报错：

```text
tun.Start: no default network interface detected - check your network connection
```

这个错误通常表示 sing-tun/sing-box 启动 TUN 时没有找到系统默认出站网卡。它不一定是 TUN 驱动损坏，更常见是默认路由、虚拟网卡、VPN 或网卡优先级导致默认接口检测失败。

## 快速判断

用管理员 PowerShell 执行：

```powershell
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 |
  Sort-Object RouteMetric, InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
```

再查看当前启用的网卡：

```powershell
Get-NetAdapter | ? Status -eq Up
```

如果默认路由最前面的 `InterfaceAlias` 是 `WireGuard Tunnel`、`Tailscale`、`ZeroTier`、`vEthernet`、`Wintun`、`TAP`、`Clash`、`mihomo` 等虚拟网卡，而不是 `Wi-Fi`、`WLAN`、`Ethernet`，就可能是其它 VPN/虚拟网卡抢了默认路由。

也可以查看传统路由表：

```powershell
route print -4
```

重点看 `0.0.0.0` 这一行对应的接口和 metric。

## 可能原因

### 1. 系统没有有效默认网关

现象：

- Wi-Fi 或以太网显示已连接，但没有 IPv4 默认网关。
- `Get-NetRoute -DestinationPrefix 0.0.0.0/0` 没有输出。
- 只有局域网地址，无法直接访问互联网。

处理：

- 断开并重新连接网络。
- 检查 DHCP 是否正常分配默认网关。
- 重启网络适配器。
- 网络正常后重启 sing-box/sing-tun 客户端。

### 2. 其它 VPN 或虚拟网卡抢了默认路由

常见来源：

- WireGuard
- Tailscale
- ZeroTier
- OpenVPN/TAP
- Clash/mihomo TUN
- WSL/Hyper-V 的 `vEthernet`
- 企业 VPN
- 旧的 Wintun/TAP 虚拟网卡残留

处理方案 A：不要同时开两个 TUN/VPN

退出其它 VPN 或代理客户端，然后重启 sing-box/sing-tun。这是最简单、最可靠的处理方式。

处理方案 B：显式指定真实出口网卡

先确认真实网卡名：

```powershell
Get-NetAdapter | ? Status -eq Up
```

然后在 sing-box 配置里指定真实出口网卡：

```json
{
  "route": {
    "auto_detect_interface": false,
    "default_interface": "Wi-Fi"
  }
}
```

把 `"Wi-Fi"` 换成实际网卡名，例如 `"WLAN"` 或 `"Ethernet"`。

注意：`auto_detect_interface` 和 `default_interface` 不要同时启用；如果 `auto_detect_interface` 为 `true`，`default_interface` 不生效。

处理方案 C：调整 Windows 网卡优先级

例如让真实 Wi-Fi 优先，让 VPN 虚拟网卡靠后：

```powershell
Set-NetIPInterface -InterfaceAlias "Wi-Fi" -InterfaceMetric 10
Set-NetIPInterface -InterfaceAlias "WireGuard Tunnel" -InterfaceMetric 500
```

把接口名替换为你机器上的实际名称。改完后重启 sing-box/sing-tun，必要时断开并重连网络。

### 3. 服务启动太早

如果 sing-box/sing-tun 是开机自启动服务，可能在 Windows 网络初始化前启动，导致启动时没有默认接口。

处理：

- 把服务设置为延迟启动。
- 网络连上后手动重启客户端或服务。
- 如果使用任务计划程序启动，增加 10 到 30 秒延迟。

### 4. 网卡 metric 混乱

Windows 可能同时存在多个默认路由，metric 较低的虚拟网卡被优先选择，但实际不可用。

检查：

```powershell
Get-NetIPInterface -AddressFamily IPv4 |
  Sort-Object InterfaceMetric |
  Format-Table InterfaceAlias, InterfaceMetric, ConnectionState
```

处理：

- 降低真实出口网卡 metric，例如 `10`。
- 提高虚拟网卡 metric，例如 `500`。
- 删除不再使用的旧 VPN/TAP/Wintun 虚拟网卡。

### 5. 客户端或 sing-box 版本问题

sing-box 早期版本曾修复过 Windows 下 `auto_detect_interface` 默认接口识别错误的问题。如果配置看起来没问题，但仍然报错，建议升级 sing-box 或使用的图形客户端。

## 推荐处理顺序

1. 先确认系统能正常联网。
2. 执行 `Get-NetRoute -DestinationPrefix 0.0.0.0/0` 看默认路由。
3. 关闭其它 VPN/TUN 客户端后重试。
4. 如果必须共存，配置 `route.default_interface` 指向真实出口网卡。
5. 调整 Windows 接口 metric。
6. 如果是开机启动问题，改为延迟启动。
7. 升级 sing-box/客户端。

## 特殊场景

如果你本来就是想让 sing-box 的出站流量走另一个 VPN，例如先连接 WireGuard，再让 sing-box 走 WireGuard，可以把 `default_interface` 指向那个 VPN 的虚拟网卡。

但不要把 `default_interface` 指向 sing-box 自己创建的 TUN/Wintun 网卡，否则容易形成路由回环。

## 官方配置参考

- Route 配置：<https://sing-box.sagernet.org/configuration/route/>
- TUN 入站配置：<https://sing-box.sagernet.org/configuration/inbound/tun/>

