# 全新 Windows 10 电脑 TUN 默认网卡检测失败排查

报错：

```text
tun.Start: no default network interface detected - check your network connection
```

如果是一台全新的 Windows 10 电脑，优先怀疑不是 VPN 抢默认路由，而是系统当前没有可用的默认出站网卡，或者网络初始化还没完成。

## 最常见原因

### 1. 没有 IPv4 默认网关

Wi-Fi 或网线看起来已经连接，但 DHCP 没有拿到默认网关时，程序无法识别默认出口。

检查：

```powershell
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0
Get-NetIPConfiguration
```

正常情况应该能看到类似：

```text
InterfaceAlias  NextHop
Wi-Fi           192.168.1.1
```

如果没有 `0.0.0.0/0` 默认路由，先修 Windows 网络、DHCP 或路由器网关。

### 2. 只有 IPv6 默认路由，没有 IPv4 默认路由

部分公司网络、校园网或特殊网络环境可能 IPv6 可用，但 IPv4 没有默认路由。

检查 IPv6 默认路由：

```powershell
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0"
```

如果只有 IPv6 默认路由，而没有 IPv4 `0.0.0.0/0`，当前 TUN 默认接口检测可能失败。

### 3. 程序启动太早

如果程序设置为开机自启动，Windows 网络服务、DHCP、Wi-Fi 连接可能还没初始化完成，TUN 已经开始启动。

处理：

- 等网络连接正常后手动重启程序。
- 如果是 Windows 服务，设置为延迟启动。
- 如果使用任务计划程序，增加 10 到 30 秒启动延迟。

### 4. 网卡驱动或适配器状态异常

全新电脑常见问题：

- Wi-Fi/以太网驱动未正确安装。
- 网卡状态不是 `Up`。
- 蓝牙、热点、虚拟网卡等适配器排在真实网卡前面。
- 网卡被禁用或处于省电异常状态。

检查启用中的网卡：

```powershell
Get-NetAdapter | ? Status -eq Up |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

检查所有网卡：

```powershell
Get-NetAdapter |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

### 5. 静态 IP 配置缺默认网关

如果手动配置了静态 IP，但没有填写默认网关，也会没有默认出口。

检查：

```powershell
Get-NetIPConfiguration
```

重点看当前真实网卡下是否有 `IPv4DefaultGateway`。

### 6. 网络连接未真正放行

常见场景：

- Wi-Fi 已连接，但需要网页认证。
- 路由器没有外网。
- 公司 NAC/安全准入还未放行。
- 新系统时间错误导致认证失败。
- DNS 可用性异常。

这种情况下，Windows 可能显示“已连接”，但实际默认出口不可用或不稳定。

## 推荐排查命令

用管理员 PowerShell 执行：

```powershell
Get-NetAdapter | ? Status -eq Up |
  Format-Table ifIndex, Name, InterfaceDescription, Status
```

```powershell
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 |
  Sort-Object RouteMetric, InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
```

```powershell
Find-NetRoute -RemoteIPAddress 8.8.8.8
```

```powershell
Get-NetIPConfiguration
```

如果 `Get-NetRoute -DestinationPrefix 0.0.0.0/0` 没有输出，说明当前 Windows 没有 IPv4 默认路由，先处理网络配置。

如果有默认路由，但程序仍然报错，需要看程序新增的诊断日志：

```text
diagnostic active adapters
diagnostic ipv4 interface metrics
diagnostic ipv4 default routes
diagnostic tun split routes
```

重点确认：

- `active adapters` 里真实网卡是否是 `Up`。
- `ipv4 default routes` 是否有 `0.0.0.0/0`。
- `InterfaceAlias` 是否是 `Wi-Fi`、`WLAN`、`Ethernet` 这类真实网卡。
- 是否存在异常虚拟网卡排在真实网卡前面。

## 处理顺序

1. 确认 Windows 能正常访问互联网。
2. 确认真实网卡状态是 `Up`。
3. 确认存在 IPv4 默认路由 `0.0.0.0/0`。
4. 如果没有默认路由，检查 DHCP、默认网关、静态 IP 配置。
5. 如果是开机自启动问题，改为延迟启动或网络连上后重启。
6. 如果默认路由存在但程序仍报错，查看程序诊断日志中的默认路由和网卡列表。

