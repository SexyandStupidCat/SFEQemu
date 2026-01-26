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

function finish(syscall_name, num, ret, intercepted, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    local ctx = _G._sfemu_syscall_ctx
    if type(ctx) ~= "table" or ctx.hooked ~= true then
        return 0
    end
    if ctx.name ~= syscall_name then
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
