-- advanced_example.lua - 展示如何使用 QEMU C 函数的高级示例
-- 这个示例展示了内存读写、寄存器访问等功能

local log = require("rules_examples.base.log")

-- 启用文件日志
log.enable_file_logging()
log.set_level(log.LEVEL.INFO)

-- 在脚本加载时列出所有可用的寄存器
log.separator("=", 60)
log.info("Advanced Example - Demonstrating C Function Usage")
log.separator("=", 60)

-- 列出所有寄存器
local regs = c_list_regs()
if regs and #regs > 0 then
    log.info("Available registers: %d", #regs)
    log.debug("Register list: %s", table.concat(regs, ", "))
else
    log.warn("No registers available (not in syscall context yet)")
end

log.separator("-", 60)

-- 系统调用拦截函数
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    log.count("syscall_total")

    -- 根据系统调用号执行不同的操作
    if num == 39 then  -- getpid
        log.syscall("getpid", "intercepted")

        -- 读取 PC 寄存器
        local pc, size, rc = c_get_reg("pc")
        if rc == 0 then
            log.info("  PC register: 0x%x", pc)
        end

        -- 执行真实的系统调用并返回
        local real_pid = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6)
        log.info("  Real PID: %d", real_pid)

        return 1, real_pid

    elseif num == 2 then  -- open
        log.syscall("open", "pathname=0x%x, flags=0x%x, mode=0x%x", arg1, arg2, arg3)

        -- 读取路径字符串
        if arg1 ~= 0 then
            local path = c_read_string(arg1, 256)
            log.info("  Path: %s", path)

            -- 检查特定文件
            if path:match("/proc/") then
                log.info("  Accessing /proc filesystem")
            elseif path:match("/etc/") then
                log.warn("  Accessing /etc directory")
            end
        end

        return 0, 0

    elseif num == 1 then  -- write
        log.syscall("write", "fd=%d, buf=0x%x, count=%d", arg1, arg2, arg3)

        -- 读取要写入的内容
        if arg2 ~= 0 and arg3 > 0 and arg3 < 1024 then
            local content = c_read_string(arg2, arg3)
            if #content > 0 then
                -- 只显示前 80 个字符
                local preview = content:sub(1, 80)
                if #content > 80 then
                    preview = preview .. "..."
                end
                log.info("  Content: %s", preview)
            end
        end

        return 0, 0

    elseif num == 0 then  -- read
        log.syscall("read", "fd=%d, buf=0x%x, count=%d", arg1, arg2, arg3)

        -- 可以在读取后检查缓冲区内容
        -- 注意：需要在系统调用返回后才能读取
        return 0, 0

    elseif num == 41 then  -- socket
        log.syscall("socket", "domain=%d, type=%d, protocol=%d", arg1, arg2, arg3)
        log.count("socket_calls")
        return 0, 0

    else
        -- 其他系统调用，只在前几次记录
        if log.stats["syscall_total"] <= 20 then
            log.debug("Syscall #%d: num=%d", log.stats["syscall_total"], num)
        end
        return 0, 0
    end
end

log.info("Advanced example loaded successfully")
