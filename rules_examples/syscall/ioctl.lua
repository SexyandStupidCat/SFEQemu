-- ioctl.lua - 网络接口 ioctl 调用拦截脚本
-- 使用 base/net.lua 模块处理网络接口模拟

-- 加载网络模块
local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local net = require(rules_dir .. "base/net")

-- 统计计数器
local ioctl_count = 0
local cmd_stats = {}

-- 主处理函数
function do_syscall(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    -- fakefile 优先处理（命中后直接拦截返回）
    local action, retval = fakefile.handle_ioctl(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    ioctl_count = ioctl_count + 1

    local cmd_name = net.get_cmd_name(cmd)

    if cmd_name then
        -- 统计命令使用次数
        cmd_stats[cmd_name] = (cmd_stats[cmd_name] or 0) + 1

        -- 记录网络接口相关的 ioctl 调用
        c_log(string.format("[ioctl] #%d: fd=%d, cmd=%s (0x%x), arg=0x%x",
                           ioctl_count, fd, cmd_name, cmd, arg))

        -- 对于读取类操作，尝试构建响应并写入内存
        local handled, retval = net.handle_ioctl(cmd, arg)

        if handled then
            -- 返回 (1, retval) 表示拦截syscall，返回 retval
            c_log(string.format("[ioctl] %s intercepted, returning %d", cmd_name, retval))
            return 1, retval
        end

        -- 对于设置类操作（需要特权），可以选择阻止
        if net.is_privileged_cmd(cmd_name) then
            c_log(string.format("[ioctl] WARNING: Privileged operation %s attempted", cmd_name))
            -- 可以选择阻止：return 1, -1  -- 返回 EPERM
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
