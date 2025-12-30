-- net.lua - 网络接口模拟工具模块
-- 提供网络接口信息模拟和 ifreq 结构体操作

local M = {}

-- ioctl 命令常量定义
M.IOCTL_CMDS = {
    -- 接口信息获取类
    [0x8910] = "SIOCGIFNAME",      -- 根据接口索引获取接口名称
    [0x8933] = "SIOCGIFINDEX",     -- 获取接口的索引号
    [0x8912] = "SIOCGIFCONF",      -- 获取系统中所有网络接口的配置信息列表

    -- 地址相关
    [0x8915] = "SIOCGIFADDR",      -- 获取接口的IP地址
    [0x8916] = "SIOCSIFADDR",      -- 设置接口的IP地址（需要特权）
    [0x8917] = "SIOCDIFADDR",      -- 删除接口的IP地址（需要特权）

    -- 网络掩码和广播地址
    [0x891b] = "SIOCGIFNETMASK",   -- 获取接口的网络掩码
    [0x891c] = "SIOCSIFNETMASK",   -- 设置接口的网络掩码（需要特权）
    [0x8919] = "SIOCGIFBRDADDR",   -- 获取接口的广播地址
    [0x891a] = "SIOCSIFBRDADDR",   -- 设置接口的广播地址（需要特权）

    -- 接口标志和状态
    [0x8913] = "SIOCGIFFLAGS",     -- 获取接口的活动标志位
    [0x8914] = "SIOCSIFFLAGS",     -- 设置接口的活动标志位（需要特权）
    [0x8935] = "SIOCGIFPFLAGS",    -- 获取接口的扩展（私有）标志,
    [0x8936] = "SIOCSIFPFLAGS",    -- 设置接口的扩展（私有）标志（需要特权）

    -- 硬件相关
    [0x8927] = "SIOCGIFHWADDR",    -- 获取接口的硬件地址（MAC地址）
    [0x8924] = "SIOCSIFHWADDR",    -- 设置接口的硬件地址（需要特权）
    [0x8937] = "SIOCSIFHWBROADCAST", -- 设置接口的硬件广播地址（需要特权）
    [0x8970] = "SIOCGIFMAP",       -- 获取接口的硬件参数
    [0x8971] = "SIOCSIFMAP",       -- 设置接口的硬件参数（需要特权）

    -- 网络参数
    [0x8921] = "SIOCGIFMTU",       -- 获取接口的MTU（最大传输单元）
    [0x8922] = "SIOCSIFMTU",       -- 设置接口的MTU（需要特权）
    [0x891d] = "SIOCGIFMETRIC",    -- 获取接口的度量值
    [0x891e] = "SIOCSIFMETRIC",    -- 设置接口的度量值（需要特权）
    [0x8942] = "SIOCGIFTXQLEN",    -- 获取接口的传输队列长度
    [0x8943] = "SIOCSIFTXQLEN",    -- 设置接口的传输队列长度（需要特权）

    -- 多播和接口管理
    [0x8931] = "SIOCADDMULTI",     -- 向接口的链路层多播过滤器添加地址（需要特权）
    [0x8932] = "SIOCDELMULTI",     -- 从接口的链路层多播过滤器删除地址（需要特权）
    [0x8923] = "SIOCSIFNAME",      -- 更改接口名称（需要特权，仅在接口未启动时允许）
}

-- 配置：模拟的网络接口信息
M.NET_CONFIG = {
    INTERFACE_NAME = "eth0",
    INTERFACE_INDEX = 2,
    IP_ADDRESS = "172.17.0.5",
    NETMASK = "255.255.0.0",
    BROADCAST = "172.17.255.255",
    MAC_ADDRESS = "66:2f:23:ab:3f:c5",
    MTU = 1500,
    FLAGS = 0x1043,  -- IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST
}

-- 辅助函数：将IP地址字符串转换为4字节数组
local function ip_to_bytes(ip_str)
    local bytes = {}
    for octet in string.gmatch(ip_str, "%d+") do
        table.insert(bytes, tonumber(octet))
    end
    return bytes
end

-- 辅助函数：将MAC地址字符串转换为6字节数组
local function mac_to_bytes(mac_str)
    local bytes = {}
    for hex in string.gmatch(mac_str, "%x%x") do
        table.insert(bytes, tonumber(hex, 16))
    end
    return bytes
end

-- 辅助函数：将16位整数转换为小端字节序字符串
local function u16_to_bytes(value)
    return string.char(value & 0xFF, (value >> 8) & 0xFF)
end

-- 辅助函数：将32位整数转换为小端字节序字符串
local function u32_to_bytes(value)
    return string.char(
        value & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF
    )
end

-- 辅助函数：构建 sockaddr_in 结构体（用于IP地址）
-- struct sockaddr_in: 2字节 family + 2字节 port + 4字节 IP + 8字节 padding
local function build_sockaddr_in(ip_str)
    local AF_INET = 2
    local ip_bytes = ip_to_bytes(ip_str)

    local sockaddr = u16_to_bytes(AF_INET)  -- sin_family
    sockaddr = sockaddr .. u16_to_bytes(0)  -- sin_port (0)

    -- sin_addr (4字节IP地址)
    for i = 1, 4 do
        sockaddr = sockaddr .. string.char(ip_bytes[i] or 0)
    end

    -- sin_zero (8字节填充)
    sockaddr = sockaddr .. string.rep("\0", 8)

    return sockaddr
end

-- 读取 ifreq 结构中的接口名称
-- @param ifreq_addr: ifreq 结构体的地址
-- @return 接口名称字符串
function M.read_ifname(ifreq_addr)
    local IFNAMSIZ = 16
    local ifname, rc = c_read_string(ifreq_addr, IFNAMSIZ)
    if rc == 0 and ifname then
        -- 去掉尾部的空字符
        ifname = ifname:match("^([^%z]*)")
        return ifname
    end
    return nil
end

-- 检查是否应该拦截此接口的请求
-- @param ifname: 接口名称
-- @return true 表示应该拦截并返回模拟数据
function M.should_intercept(ifname)
    -- 只拦截 eth0 的请求
    return ifname == M.NET_CONFIG.INTERFACE_NAME
end

-- 处理网络接口 ioctl 请求并写入模拟数据
-- @param cmd: ioctl 命令
-- @param ifreq_addr: ifreq 结构体地址
-- @return (handled, retval): handled=true表示已处理, retval是返回值
function M.handle_ioctl(cmd, ifreq_addr)
    local cmd_name = M.IOCTL_CMDS[cmd]
    if not cmd_name then
        return false, 0
    end

    -- 读取接口名称
    local ifname = M.read_ifname(ifreq_addr)
    if not ifname then
        c_log("[net] Failed to read interface name from ifreq")
        return false, 0
    end

    -- 检查是否应该拦截
    if not M.should_intercept(ifname) then
        c_log(string.format("[net] %s for %s - not intercepting", cmd_name, ifname))
        return false, 0
    end

    -- ifreq 偏移量
    local IFNAMSIZ = 16  -- 接口名称长度
    local ifr_data_offset = ifreq_addr + IFNAMSIZ  -- 联合体数据起始位置

    if cmd == 0x8915 then  -- SIOCGIFADDR - 获取IP地址
        c_log(string.format("[net] %s for %s: Returning IP %s", cmd_name, ifname, M.NET_CONFIG.IP_ADDRESS))
        local sockaddr = build_sockaddr_in(M.NET_CONFIG.IP_ADDRESS)
        local written, rc = c_write_bytes(ifr_data_offset, sockaddr)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for IP address", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write IP address: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x891b then  -- SIOCGIFNETMASK - 获取网络掩码
        c_log(string.format("[net] %s for %s: Returning netmask %s", cmd_name, ifname, M.NET_CONFIG.NETMASK))
        local sockaddr = build_sockaddr_in(M.NET_CONFIG.NETMASK)
        local written, rc = c_write_bytes(ifr_data_offset, sockaddr)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for netmask", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write netmask: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8919 then  -- SIOCGIFBRDADDR - 获取广播地址
        c_log(string.format("[net] %s for %s: Returning broadcast %s", cmd_name, ifname, M.NET_CONFIG.BROADCAST))
        local sockaddr = build_sockaddr_in(M.NET_CONFIG.BROADCAST)
        local written, rc = c_write_bytes(ifr_data_offset, sockaddr)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for broadcast", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write broadcast: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8927 then  -- SIOCGIFHWADDR - 获取MAC地址
        c_log(string.format("[net] %s for %s: Returning MAC %s", cmd_name, ifname, M.NET_CONFIG.MAC_ADDRESS))
        -- struct sockaddr: 2字节 family + 14字节数据
        local ARPHRD_ETHER = 1
        local mac_bytes = mac_to_bytes(M.NET_CONFIG.MAC_ADDRESS)

        local sockaddr = u16_to_bytes(ARPHRD_ETHER)  -- sa_family
        for i = 1, 6 do
            sockaddr = sockaddr .. string.char(mac_bytes[i] or 0)
        end
        sockaddr = sockaddr .. string.rep("\0", 8)  -- 填充到14字节

        local written, rc = c_write_bytes(ifr_data_offset, sockaddr)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for MAC address", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write MAC address: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8921 then  -- SIOCGIFMTU - 获取MTU
        c_log(string.format("[net] %s for %s: Returning MTU %d", cmd_name, ifname, M.NET_CONFIG.MTU))
        local mtu_bytes = u32_to_bytes(M.NET_CONFIG.MTU)
        local written, rc = c_write_bytes(ifr_data_offset, mtu_bytes)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for MTU", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write MTU: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8933 then  -- SIOCGIFINDEX - 获取接口索引
        c_log(string.format("[net] %s for %s: Returning index %d", cmd_name, ifname, M.NET_CONFIG.INTERFACE_INDEX))
        local index_bytes = u32_to_bytes(M.NET_CONFIG.INTERFACE_INDEX)
        local written, rc = c_write_bytes(ifr_data_offset, index_bytes)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for interface index", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write interface index: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8913 then  -- SIOCGIFFLAGS - 获取接口标志
        c_log(string.format("[net] %s for %s: Returning flags 0x%x", cmd_name, ifname, M.NET_CONFIG.FLAGS))
        local flags_bytes = u16_to_bytes(M.NET_CONFIG.FLAGS)
        local written, rc = c_write_bytes(ifr_data_offset, flags_bytes)
        if rc == 0 then
            c_log(string.format("[net] Successfully wrote %d bytes for flags", written))
            return true, 0
        else
            c_log(string.format("[net] Failed to write flags: rc=%d", rc))
            return true, -1
        end

    elseif cmd == 0x8912 then  -- SIOCGIFCONF - 获取所有接口配置
        c_log(string.format("[net] %s: Returning interface list (not fully implemented)", cmd_name))
        -- SIOCGIFCONF 需要特殊处理，结构更复杂
        -- 暂时不拦截，让原系统调用处理
        return false, 0

    else
        return false, 0
    end
end

-- 检查命令是否是网络接口相关命令
-- @param cmd: ioctl 命令
-- @return cmd_name 或 nil
function M.get_cmd_name(cmd)
    return M.IOCTL_CMDS[cmd]
end

-- 检查是否是需要特权的设置类命令
-- @param cmd_name: 命令名称
-- @return true 表示是特权命令
function M.is_privileged_cmd(cmd_name)
    return cmd_name:match("^SIOCS") or cmd_name:match("^SIOCD") or
           cmd_name == "SIOCADDMULTI" or cmd_name == "SIOCDELMULTI"
end

return M
