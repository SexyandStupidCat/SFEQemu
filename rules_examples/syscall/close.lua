-- close.lua - Hook for close syscall
-- 用于在 fd 关闭时清理 fakefile 的 fd 映射，避免 fd 复用导致误判。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")
local mtd = require(rules_dir .. "base/mtd")

function do_syscall(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 重要：很多固件 daemonize 时会批量 close(0..N)，这会把 QEMU 侧用于日志/框架的内部 fd 也关掉，
    -- 导致后续 syscall 无法记录，AI 也无法触发/闭环。
    --
    -- 在本项目默认配置下，fd=3 通常被 QEMU 用作内部日志文件句柄（因此 guest 的 open() 经常从 4 开始）。
    -- 这里做一个保守保护：忽略对 fd=3 的 close 请求。
    --
    -- 风险：若某些极端场景 fd=3 被 guest 正常占用，会造成 fd 泄漏；但在当前仿真框架下几乎不成立。
    if tonumber(fd) == 3 then
        if type(c_log) == "function" then
            c_log("[close.protect] ignore close(fd=3) to keep sfemu log alive")
        end
        return 1, 0
    end

    -- /proc/mtd：清理 read offset
    local info = fdmap.get(tonumber(fd) or -1)
    if type(info) == "table" and info.path == "/proc/mtd" then
        mtd.unmark_fd(fd)
    end

    local action, ret = fakefile.handle_close(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if action == 1 and type(ret) == "number" and ret == 0 then
        fdmap.clear(fd)
    end
    return action, ret
end
