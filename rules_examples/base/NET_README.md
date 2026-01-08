# 网络接口模拟模块 (net.lua)

## 概述

`base/net.lua` 模块提供网络接口信息模拟功能，用于在沙箱环境中拦截和处理网络接口相关的 ioctl 系统调用。

## 功能

### 1. 支持的 ioctl 命令

模块支持以下网络接口相关的 ioctl 命令：

- **接口信息获取**：
  - `SIOCGIFADDR` (0x8915) - 获取IP地址
  - `SIOCGIFNETMASK` (0x891b) - 获取子网掩码
  - `SIOCGIFBRDADDR` (0x8919) - 获取广播地址
  - `SIOCGIFHWADDR` (0x8927) - 获取MAC地址
  - `SIOCGIFMTU` (0x8921) - 获取MTU
  - `SIOCGIFINDEX` (0x8933) - 获取接口索引
  - `SIOCGIFFLAGS` (0x8913) - 获取接口标志

- **特权操作**（可选择阻止）：
  - `SIOCSIFADDR` - 设置IP地址
  - `SIOCSIFNETMASK` - 设置子网掩码
  - 等等...

### 2. 模拟的网络配置

默认配置模拟 Docker 容器中的 `eth0` 接口：

```lua
NET_CONFIG = {
    INTERFACE_NAME = "eth0",
    INTERFACE_INDEX = 2,
    IP_ADDRESS = "172.17.0.5",
    NETMASK = "255.255.0.0",
    BROADCAST = "172.17.255.255",
    MAC_ADDRESS = "66:2f:23:ab:3f:c5",
    MTU = 1500,
    FLAGS = 0x1043,  -- IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST
}
```

### 3. 接口映射机制

当程序请求不存在的网络接口时，模块会自动映射到真实的接口并返回真实接口的信息。

**默认映射**：
```lua
INTERFACE_MAPPING = {
    ["br0"] = "eth0",      -- 桥接接口 -> eth0
    ["br1"] = "eth0",      -- 桥接接口 -> eth0
    ["wlan0"] = "eth0",    -- 无线接口 -> eth0
}
```

**工作原理**：
- 如果程序请求 `eth0`（真实存在的接口），直接放行给原系统调用处理
- 如果程序请求 `br0`（不存在的接口），拦截并返回 `eth0` 的网络配置信息
- 如果程序请求其他未映射的接口，放行给原系统调用处理

**示例**：
```
程序请求: ioctl(fd, SIOCGIFADDR, "br0")
↓
检测到 br0 不存在，但在映射表中
↓
返回 eth0 的 IP 地址: 172.17.0.5
```

这样程序可以正常获取网络信息，即使它请求的接口名称不存在。

## API

### net.get_cmd_name(cmd)
检查命令是否是网络接口相关命令。
- **参数**：`cmd` - ioctl 命令号
- **返回**：命令名称字符串，如果不是网络命令则返回 nil

### net.handle_ioctl(cmd, ifreq_addr)
处理网络接口 ioctl 请求并写入模拟数据。
- **参数**：
  - `cmd` - ioctl 命令号
  - `ifreq_addr` - ifreq 结构体的内存地址
- **返回**：`(handled, retval)`
  - `handled` - true 表示已拦截并处理
  - `retval` - 返回值（0=成功，-1=失败）

### net.is_privileged_cmd(cmd_name)
检查是否是需要特权的设置类命令。
- **参数**：`cmd_name` - 命令名称
- **返回**：true 表示是特权命令

### net.read_ifname(ifreq_addr)
读取 ifreq 结构中的接口名称。
- **参数**：`ifreq_addr` - ifreq 结构体地址
- **返回**：接口名称字符串

### net.should_intercept(ifname)
检查是否应该拦截此接口的请求。
- **参数**：`ifname` - 接口名称
- **返回**：`(should_handle, real_ifname)`
  - `should_handle` - true 表示应该拦截
  - `real_ifname` - 映射后的真实接口名

## 使用示例

### 在 ioctl.lua 中使用

```lua
-- 加载网络模块
local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local net = require(script_dir .. "base/net")

function do_syscall(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    local cmd_name = net.get_cmd_name(cmd)

    if cmd_name then
        -- 尝试拦截并处理
        local handled, retval = net.handle_ioctl(cmd, arg)

        if handled then
            -- 拦截成功，返回模拟数据
            c_log(string.format("[ioctl] %s intercepted, returning %d", cmd_name, retval))
            return 1, retval  -- (拦截标志, 返回值)
        end

        -- 检查是否是特权命令
        if net.is_privileged_cmd(cmd_name) then
            c_log("[ioctl] WARNING: Privileged operation attempted")
        end
    end

    -- 放行给原系统调用
    return 0, 0
end
```

## 实现细节

### ifreq 结构体布局

```c
struct ifreq {
    char ifr_name[16];      // 接口名称（以 \0 结尾）
    union {
        struct sockaddr ifr_addr;        // IP地址
        struct sockaddr ifr_netmask;     // 子网掩码
        struct sockaddr ifr_broadaddr;   // 广播地址
        struct sockaddr ifr_hwaddr;      // MAC地址
        int ifr_ifindex;                 // 接口索引
        int ifr_mtu;                     // MTU
        short ifr_flags;                 // 标志位
        // ... 更多字段
    };
};
```

### sockaddr_in 结构体（用于IP地址）

```c
struct sockaddr_in {
    uint16_t sin_family;     // AF_INET (2)
    uint16_t sin_port;       // 端口号（通常为0）
    uint32_t sin_addr;       // IP地址（网络字节序）
    uint8_t sin_zero[8];     // 填充
};
```

### 字节序

所有多字节数值使用小端字节序（little-endian），符合 x86/ARM 架构。

## 自定义配置

### 修改网络配置

如果需要修改模拟的网络配置，可以在加载模块后修改：

```lua
local net = require("base/net")

-- 修改 IP 地址
net.NET_CONFIG.IP_ADDRESS = "192.168.1.100"
net.NET_CONFIG.NETMASK = "255.255.255.0"
net.NET_CONFIG.BROADCAST = "192.168.1.255"

-- 修改 MAC 地址
net.NET_CONFIG.MAC_ADDRESS = "aa:bb:cc:dd:ee:ff"
```

### 添加接口映射

如果程序请求其他不存在的接口，可以添加映射：

```lua
local net = require("base/net")

-- 添加新的接口映射
net.INTERFACE_MAPPING["docker0"] = "eth0"
net.INTERFACE_MAPPING["veth0"] = "eth0"
```

## 注意事项

1. **接口映射**：不存在的接口（如 `br0`, `wlan0`）会自动映射到 `eth0` 并返回 `eth0` 的网络配置
2. **真实接口放行**：对 `eth0` 的请求会直接放行给原系统调用，返回真实的网络信息
3. **SIOCGIFCONF 未实现**：获取所有接口列表的命令暂未完全实现，会放行给原系统调用
4. **特权操作**：特权操作命令（SIOCS*/SIOCD*）默认只记录警告，不阻止，可根据需要修改
5. **内存写入**：所有内存写入操作使用 `c_write_bytes()` C 函数
6. **可扩展映射表**：可以通过修改 `INTERFACE_MAPPING` 添加更多接口映射

## 典型使用场景

### 场景 1：程序请求不存在的 br0 接口

```
程序: ioctl(fd, SIOCGIFADDR, "br0")  // 请求 br0 的 IP 地址
↓
Lua 检测到 br0 在映射表中: br0 -> eth0
↓
返回 eth0 的 IP: 172.17.0.5
↓
程序: 收到 IP 地址，继续运行 ✓
```

### 场景 2：程序请求真实的 eth0 接口

```
程序: ioctl(fd, SIOCGIFADDR, "eth0")  // 请求 eth0 的 IP 地址
↓
Lua 检测到请求的是真实接口，放行
↓
原系统调用执行，返回真实的 eth0 信息
↓
程序: 收到真实 IP 地址 ✓
```

### 场景 3：程序请求未映射的接口

```
程序: ioctl(fd, SIOCGIFADDR, "lo")  // 请求 lo 的 IP 地址
↓
Lua 检测到 lo 不在映射表中，放行
↓
原系统调用执行，返回 lo 的真实信息
↓
程序: 收到 lo 的 IP (127.0.0.1) ✓
```
