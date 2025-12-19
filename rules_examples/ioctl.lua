-- ioctl.lua - 网络接口 ioctl 调用拦截脚本
-- 模拟网络接口信息获取，用于沙箱环境

-- ioctl 命令常量定义
local IOCTL_CMDS = {
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
local NET_CONFIG = {
    INTERFACE_NAME = "eth0",
    INTERFACE_INDEX = 2,
    IP_ADDRESS = "192.168.1.100",
    NETMASK = "255.255.255.0",
    BROADCAST = "192.168.1.255",
    MAC_ADDRESS = "52:54:00:12:34:56",
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

-- 辅助函数：构建 ifreq 结构体（简化版）
-- ifreq 结构: 16字节接口名 + 24字节联合体
local function build_ifreq_response(cmd, ifreq_addr)
    local cmd_name = IOCTL_CMDS[cmd] or string.format("0x%x", cmd)

    -- 读取接口名称（假设已实现 c_read_bytes）
    -- 这里需要从 ifreq_addr 读取并写回修改后的数据
    -- 注意：当前版本的 Lua 脚本可能还没有内存读写函数

    if cmd == 0x8915 then  -- SIOCGIFADDR - 获取IP地址
        c_log(string.format("[ioctl] %s: Returning IP %s", cmd_name, NET_CONFIG.IP_ADDRESS))
        -- 需要实现：将 IP 地址写入 ifreq 结构的 ifr_addr 字段
        -- 格式：sockaddr 结构 (2字节 family + 2字节 port + 4字节 IP + 8字节 padding)
        return true

    elseif cmd == 0x891b then  -- SIOCGIFNETMASK - 获取网络掩码
        c_log(string.format("[ioctl] %s: Returning netmask %s", cmd_name, NET_CONFIG.NETMASK))
        return true

    elseif cmd == 0x8919 then  -- SIOCGIFBRDADDR - 获取广播地址
        c_log(string.format("[ioctl] %s: Returning broadcast %s", cmd_name, NET_CONFIG.BROADCAST))
        return true

    elseif cmd == 0x8927 then  -- SIOCGIFHWADDR - 获取MAC地址
        c_log(string.format("[ioctl] %s: Returning MAC %s", cmd_name, NET_CONFIG.MAC_ADDRESS))
        return true

    elseif cmd == 0x8921 then  -- SIOCGIFMTU - 获取MTU
        c_log(string.format("[ioctl] %s: Returning MTU %d", cmd_name, NET_CONFIG.MTU))
        return true

    elseif cmd == 0x8933 then  -- SIOCGIFINDEX - 获取接口索引
        c_log(string.format("[ioctl] %s: Returning index %d", cmd_name, NET_CONFIG.INTERFACE_INDEX))
        return true

    elseif cmd == 0x8913 then  -- SIOCGIFFLAGS - 获取接口标志
        c_log(string.format("[ioctl] %s: Returning flags 0x%x", cmd_name, NET_CONFIG.FLAGS))
        return true

    elseif cmd == 0x8912 then  -- SIOCGIFCONF - 获取所有接口配置
        c_log(string.format("[ioctl] %s: Returning interface list", cmd_name))
        return true

    else
        return false
    end
end

-- 统计计数器
local ioctl_count = 0
local cmd_stats = {}

-- 主处理函数
function do_syscall(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    ioctl_count = ioctl_count + 1

    local cmd_name = IOCTL_CMDS[cmd]

    if cmd_name then
        -- 统计命令使用次数
        cmd_stats[cmd_name] = (cmd_stats[cmd_name] or 0) + 1

        -- 记录网络接口相关的 ioctl 调用
        c_log(string.format("[ioctl] #%d: fd=%d, cmd=%s (0x%x), arg=0x%x",
                           ioctl_count, fd, cmd_name, cmd, arg))

        -- 对于读取类操作，尝试构建响应
        local handled = build_ifreq_response(cmd, arg)

        if handled then
            -- 注意：实际返回模拟数据需要内存写入功能
            -- 当前先让原系统调用执行，只做监控
            c_log(string.format("[ioctl] %s would be handled (memory write not yet implemented)", cmd_name))
            return 0, 0  -- 继续执行原系统调用
        end

        -- 对于设置类操作（需要特权），可以选择阻止
        if cmd_name:match("^SIOCS") or cmd_name:match("^SIOCD") or
           cmd_name == "SIOCADDMULTI" or cmd_name == "SIOCDELMULTI" then
            c_log(string.format("[ioctl] WARNING: Privileged operation %s attempted", cmd_name))
            -- 可以选择阻止：return 1, -1  -- EPERM
        end

        return 0, 0  -- 继续执行原系统调用
    else
        -- 非网络接口相关的 ioctl，放行
        -- 只在前几次记录未知命令，避免日志过多
        if ioctl_count <= 10 or ioctl_count % 100 == 0 then
            c_log(string.format("[ioctl] #%d: fd=%d, cmd=0x%x (unknown), arg=0x%x",
                               ioctl_count, fd, cmd, arg))
        end
        return 0, 0
    end
end
