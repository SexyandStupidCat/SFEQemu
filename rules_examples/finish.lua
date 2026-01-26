-- finish.lua - 系统调用结束脚本
--
-- 约定：
-- C 侧每次系统调用结束都会调用：
-- finish(syscall_name, num, ret, intercepted, arg1..arg8)

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[finish] " .. fmt, ...))
    else
        c_log("[finish] " .. tostring(fmt))
    end
end

-- syscall_name 可能为 nil（C 侧映射表不全）。这里补充一小段“按 syscall 号反查名称”，
-- 保证 sendmsg/recvmsg 等网络相关 syscall 也能正确落盘/打印。
--
-- 说明：这些号以 ARM EABI 为准（与本项目已有日志一致：socket=281, connect=283, openat=322）。
local SYSCALL_NUM_TO_NAME = {
    [289] = "send",
    [290] = "sendto",
    [291] = "recv",
    [292] = "recvfrom",
    [296] = "sendmsg",
    [297] = "recvmsg",
}

function finish(syscall_name, num, ret, intercepted, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    local ctx = _G._sfemu_syscall_ctx
    if type(ctx) ~= "table" or ctx.hooked ~= true then
        return 0
    end

    -- C 侧未提供 syscall_name 时，尝试用 num 反查；若仍无法反查，则使用 ctx.name 作为兜底展示名
    if type(syscall_name) ~= "string" or syscall_name == "" then
        if type(num) == "number" then
            syscall_name = SYSCALL_NUM_TO_NAME[num]
        end
        if type(syscall_name) ~= "string" or syscall_name == "" then
            syscall_name = ctx.name
        end
    end

    -- 以 syscall 号为准做一致性校验，避免因 name 缺失导致无法写回 ret/无法清理 ctx
    if type(ctx.num) == "number" and type(num) == "number" and ctx.num ~= num then
        return 0
    end

    -- 将返回值写回上下文（entry.lua 内存队列引用的是同一 table）
    ctx.ret = ret
    ctx.intercepted = (intercepted == true)
    ctx.finished = true

    -- 若 entry.lua 已将上下文落盘，则在文件末尾追加本次 syscall 的结果
    if type(ctx.data_path) == "string" and ctx.data_path ~= "" then
        local f = io.open(ctx.data_path, "ab")
        if f then
            f:write(string.format("ret: %s\n", tostring(ret)))
            f:write(string.format("intercepted: %s\n", tostring(intercepted)))
            f:close()
        end
    end

    log("%s ret=%s intercepted=%s", tostring(syscall_name), tostring(ret), tostring(intercepted))

    -- 清理上下文，避免长期驻留
    _G._sfemu_syscall_ctx = nil
    return 0
end
