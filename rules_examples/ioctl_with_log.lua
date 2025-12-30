-- ioctl_with_log.lua - 使用 log 模块改进的 ioctl 拦截脚本
-- 这是一个示例，展示如何用 log 模块重构现有脚本

local log = require("rules_examples.base.log")

-- 设置日志级别
log.set_level(log.LEVEL.INFO)

-- ioctl 命令常量定义
local IOCTL_CMDS = {
    -- 接口信息获取类
    [0x8910] = "SIOCGIFNAME",
    [0x8933] = "SIOCGIFINDEX",
    [0x8912] = "SIOCGIFCONF",

    -- 地址相关
    [0x8915] = "SIOCGIFADDR",
    [0x8916] = "SIOCSIFADDR",
    [0x8917] = "SIOCDIFADDR",

    -- 网络掩码和广播地址
    [0x891b] = "SIOCGIFNETMASK",
    [0x891c] = "SIOCSIFNETMASK",
    [0x8919] = "SIOCGIFBRDADDR",
    [0x891a] = "SIOCSIFBRDADDR",

    -- 接口标志和状态
    [0x8913] = "SIOCGIFFLAGS",
    [0x8914] = "SIOCSIFFLAGS",

    -- 硬件相关
    [0x8927] = "SIOCGIFHWADDR",
    [0x8924] = "SIOCSIFHWADDR",

    -- 网络参数
    [0x8921] = "SIOCGIFMTU",
    [0x8922] = "SIOCSIFMTU",
}

-- 配置：模拟的网络接口信息
local NET_CONFIG = {
    INTERFACE_NAME = "eth0",
    INTERFACE_INDEX = 2,
    IP_ADDRESS = "192.168.1.100",
    MAC_ADDRESS = "52:54:00:12:34:56",
    MTU = 1500,
}

-- 处理网络接口 ioctl
local function handle_network_ioctl(cmd, cmd_name, fd, arg)
    if cmd == 0x8915 then  -- SIOCGIFADDR
        log.info("Returning IP %s for %s", NET_CONFIG.IP_ADDRESS, cmd_name)
        return true
    elseif cmd == 0x8927 then  -- SIOCGIFHWADDR
        log.info("Returning MAC %s for %s", NET_CONFIG.MAC_ADDRESS, cmd_name)
        return true
    elseif cmd == 0x8921 then  -- SIOCGIFMTU
        log.info("Returning MTU %d for %s", NET_CONFIG.MTU, cmd_name)
        return true
    elseif cmd == 0x8933 then  -- SIOCGIFINDEX
        log.info("Returning index %d for %s", NET_CONFIG.INTERFACE_INDEX, cmd_name)
        return true
    end

    return false
end

-- 主处理函数
function do_syscall(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    -- 统计 ioctl 调用
    log.count("ioctl_total")

    local cmd_name = IOCTL_CMDS[cmd]

    if cmd_name then
        -- 统计特定命令
        log.count("ioctl_" .. cmd_name)

        -- 记录 ioctl 调用
        log.syscall("ioctl", "fd=%d, cmd=%s (0x%x)", fd, cmd_name, cmd)

        -- 处理网络接口相关操作
        local handled = handle_network_ioctl(cmd, cmd_name, fd, arg)

        if handled then
            log.debug("Command %s handled", cmd_name)
        end

        -- 检查特权操作
        if cmd_name:match("^SIOCS") or cmd_name:match("^SIOCD") then
            log.warn("Privileged operation %s attempted on fd=%d", cmd_name, fd)
        end

        return 0, 0
    else
        -- 未知命令
        if log.stats["ioctl_total"] <= 10 then
            log.debug("Unknown ioctl: fd=%d, cmd=0x%x", fd, cmd)
        end

        log.count("ioctl_unknown")
        return 0, 0
    end
end

-- 显示加载信息
log.info("ioctl_with_log.lua loaded")
log.info("Monitoring network interface ioctl calls")
