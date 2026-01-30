-- close_range.lua - Hook for close_range syscall
--
-- 目的：
-- - 部分固件在 daemonize 时会调用 close_range(3, ~0, 0) 一次性关闭大量 fd。
-- - 由于 linux-user 模式下 guest/host 共用同一 fd 表，这会把 QEMU/SFEmu 自己打开的内部 fd 也关掉，
--   例如内部日志文件句柄，从而导致后续 syscall 无法记录、AI 无法触发/闭环。
--
-- 处理策略（保守）：
-- - 当 close_range 的范围覆盖到“保留 fd”（目前固定为 3）且 flags 不包含 CLOSE_RANGE_CLOEXEC 时，
--   将调用拆成两段：先关闭 [first,2]，再关闭 [4,last]，从而绕开 fd=3。
-- - 其它情况直接放行原始 syscall。
--
-- 注意：
-- - 这里假设 fd=3 通常为 QEMU 内部日志句柄（因此 guest open() 常从 4 开始）。
-- - 若未来内部 fd 号变化，可考虑在 C 侧暴露一个“内部 fd 列表”给 Lua 做更精确保护。

local PROTECTED_FD = 3
local CLOSE_RANGE_CLOEXEC = 1 << 2

local function log(msg)
    if type(c_log) == "function" then
        c_log(msg)
    end
end

function do_syscall(num, first, last, flags, arg4, arg5, arg6, arg7, arg8)
    first = tonumber(first) or 0
    last = tonumber(last) or 0
    flags = tonumber(flags) or 0

    -- flags 含 CLOEXEC：不关闭 fd，仅设置 FD_CLOEXEC；对内部日志影响较小，直接放行。
    if (flags & CLOSE_RANGE_CLOEXEC) ~= 0 then
        return 0, 0
    end

    -- 仅在范围覆盖到 protected fd 时介入
    if first <= PROTECTED_FD and PROTECTED_FD <= last then
        log(string.format("[close_range.protect] split close_range(%d,%d,0) to keep fd=%d", first, last, PROTECTED_FD))

        local ret1 = 0
        if first <= (PROTECTED_FD - 1) then
            ret1 = c_do_syscall(num, first, PROTECTED_FD - 1, flags, 0, 0, 0, 0, 0)
            if type(ret1) == "number" and ret1 < 0 then
                return 1, ret1
            end
        end

        local ret2 = 0
        if last >= (PROTECTED_FD + 1) then
            ret2 = c_do_syscall(num, PROTECTED_FD + 1, last, flags, 0, 0, 0, 0, 0)
            if type(ret2) == "number" and ret2 < 0 then
                return 1, ret2
            end
        end

        return 1, 0
    end

    return 0, 0
end

