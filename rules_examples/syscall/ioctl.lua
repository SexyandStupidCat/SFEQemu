-- ioctl.lua - ioctl syscall 拦截脚本
--
-- 当前覆盖两类高频场景：
-- 1) /dev/nvram（ASUS/Broadcom 常见）：使 nvram_init/nvram_get/nvram_set 能继续前进
-- 2) 网络接口 ioctl：由 base/net.lua 构造最小返回结构（SIOCGIF* 等）
--
-- 其他 ioctl 默认放行（由宿主内核处理），或由 fakefile 的设备规则接管。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")

local nvram = require(rules_dir .. "base/nvram")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")
local net = require(rules_dir .. "base/net")

-- 统计计数器
local ioctl_count = 0
local cmd_stats = {}

function do_syscall(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    -- 1) /dev/nvram 优先（避免 nvram_init 失败导致固件崩溃/死循环）
    local action, retval = nvram.handle_ioctl(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    -- 2) fakefile（命中后直接拦截返回）
    action, retval = fakefile.handle_ioctl(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    -- 3) 网络接口 ioctl（SIOCGIF* 等）
    ioctl_count = ioctl_count + 1
    local cmd_name = net.get_cmd_name(cmd)

    if cmd_name then
        cmd_stats[cmd_name] = (cmd_stats[cmd_name] or 0) + 1
        if type(c_log) == "function" then
            c_log(string.format("[ioctl] #%d: fd=%s cmd=%s(0x%x) arg=0x%x",
                ioctl_count, fdmap.format(fd), tostring(cmd_name), tonumber(cmd) or 0, tonumber(arg) or 0))
        end

        local handled, r = net.handle_ioctl(cmd, arg)
        if handled then
            if type(c_log) == "function" then
                c_log(string.format("[ioctl] %s intercepted ret=%d", tostring(cmd_name), tonumber(r) or 0))
            end
            return 1, r
        end

        -- 未处理则放行
        return 0, 0
    end

    -- 4) 其它 ioctl：放行。仅在少数次数打印 unknown，避免刷屏
    if type(c_log) == "function" then
        if ioctl_count <= 10 or ioctl_count % 200 == 0 then
            c_log(string.format("[ioctl] #%d: fd=%s cmd=0x%x(unknown) arg=0x%x",
                ioctl_count, fdmap.format(fd), tonumber(cmd) or 0, tonumber(arg) or 0))
        end
    end
    return 0, 0
end

