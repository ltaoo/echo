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


```bash
ifIndex DestinationPrefix                              NextHop                                  RouteMetric ifMetric PolicyStore
------- -----------------                              -------                                  ----------- -------- -----------
15      0.0.0.0/0                                      192.168.1.1                                        0 25       ActiveStore
14      0.0.0.0/0                                      192.168.1.1                                        0 35       ActiveStore

ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : CorpLink TAP-Windows6
InterfaceIndex       : 13
InterfaceDescription : TAP-Windows Adapter V9
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{4504F743-1ECD-4D33-A79C-765DFA671808}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = ";?55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = ";?55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           : MSFT_NetConnectionProfile (InstanceID = "{4504F743-1ECD-4D33-A79C-765DFA671808}")
AllIPAddresses       : {192.168.77.227, fe80:abcd::abcd:1%13}
IPv6Address          : {fe80:abcd::abcd:1%13}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {}
IPv4Address          : {192.168.77.227}
IPv6DefaultGateway   :
IPv4DefaultGateway   :
DNSServer            : {MSFT_DNSClientServerAddress (Name = "13", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "13", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False


ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : Ethernet 2
InterfaceIndex       : 15
InterfaceDescription : Intel(R) Ethernet Controller I226-V
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{8213F5F9-C8E1-46DF-903B-126755C339F2}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = ";?55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = ";?55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           : MSFT_NetConnectionProfile (InstanceID = "{8213F5F9-C8E1-46DF-903B-126755C339F2}")
AllIPAddresses       : {192.168.1.112, fe80::a32c:329:9045:18f%15}
IPv6Address          : {}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {fe80::a32c:329:9045:18f%15}
IPv4Address          : {192.168.1.112}
IPv6DefaultGateway   :
IPv4DefaultGateway   : {MSFT_NetRoute (InstanceID = ":8:8:8:9:55;?55;C?8;@B8;8;55;")}
DNSServer            : {MSFT_DNSClientServerAddress (Name = "15", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "15", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False


ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : Tailscale
InterfaceIndex       : 30
InterfaceDescription : Tailscale Tunnel
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{37217669-42DA-4657-A55B-0D995D328250}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = "?:55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = "?:55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           : MSFT_NetConnectionProfile (InstanceID = "{37217669-42DA-4657-A55B-0D995D328250}")
AllIPAddresses       : {100.123.19.123, fd7a:115c:a1e0::1e35:137b, fe80::d8ff:5060:f230:9168%30}
IPv6Address          : {fd7a:115c:a1e0::1e35:137b}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {fe80::d8ff:5060:f230:9168%30}
IPv4Address          : {100.123.19.123}
IPv6DefaultGateway   :
IPv4DefaultGateway   :
DNSServer            : {MSFT_DNSClientServerAddress (Name = "30", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "30", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False


ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : Wi-Fi
InterfaceIndex       : 14
InterfaceDescription : Intel(R) Wi-Fi 6 AX200 160MHz
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{56DB9F8D-4353-4EA1-927F-A7CF18A90A46}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = ";?55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = ";?55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           :
AllIPAddresses       : {169.254.112.189, fe80::4999:6e8:c1cf:6c25%14}
IPv6Address          : {}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {fe80::4999:6e8:c1cf:6c25%14}
IPv4Address          : {169.254.112.189}
IPv6DefaultGateway   :
IPv4DefaultGateway   : {MSFT_NetRoute (InstanceID = ":8:8:8:9:55;?55;C?8;@B8;8;55;")}
DNSServer            : {MSFT_DNSClientServerAddress (Name = "14", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "14", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False


ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : Bluetooth Network Connection
InterfaceIndex       : 3
InterfaceDescription : Bluetooth Device (Personal Area Network)
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{00E045F1-7D35-432D-87BE-6170A4BF2D66}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = "?55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = "?55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           :
AllIPAddresses       : {169.254.17.7, fe80::6281:4363:bb35:a0b4%3}
IPv6Address          : {}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {fe80::6281:4363:bb35:a0b4%3}
IPv4Address          : {169.254.17.7}
IPv6DefaultGateway   :
IPv4DefaultGateway   :
DNSServer            : {MSFT_DNSClientServerAddress (Name = "3", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "3", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False


ComputerName         : WINDOWS-FS58B39
InterfaceAlias       : Ethernet 3
InterfaceIndex       : 16
InterfaceDescription : Intel(R) Ethernet Controller I226-V #2
CompartmentId        : 1
NetAdapter           : MSFT_NetAdapter (CreationClassName = "MSFT_NetAdapter", DeviceID = "{8C57A83A-8669-4207-A2F9-C0EC9BD2789E}", SystemCreationClassName = "CIM_NetworkPort", SystemName = "WINDOWS-FS58B39")
NetCompartment       : MSFT_NetCompartment (InstanceID = ";55;")
NetIPv6Interface     : MSFT_NetIPInterface (Name = ";@55??55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetIPv4Interface     : MSFT_NetIPInterface (Name = ";@55?55;", CreationClassName = "", SystemCreationClassName = "", SystemName = "")
NetProfile           :
AllIPAddresses       : {169.254.23.187, fe80::c176:3474:768f:ab91%16}
IPv6Address          : {}
IPv6TemporaryAddress : {}
IPv6LinkLocalAddress : {fe80::c176:3474:768f:ab91%16}
IPv4Address          : {169.254.23.187}
IPv6DefaultGateway   :
IPv4DefaultGateway   :
DNSServer            : {MSFT_DNSClientServerAddress (Name = "16", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "16", CreationClassName = "", SystemCreationClassName = "",
                       SystemName = "2")}
Detailed             : False

```

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

