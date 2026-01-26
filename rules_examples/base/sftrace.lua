-- sftrace.lua - 调用栈地址解析/符号化工具（基于 SFAnalysis 输出）
--
-- 设计目标：
-- - 将“地址 -> (模块/函数名/偏移/伪C)”解析逻辑封装成模块，便于多个 syscall 脚本复用。
-- - 优先按 host 地址方式解析（适配 shadowstack 返回 host 地址的场景）。
-- - 自动降级：host 解析失败 -> 尝试 guest->host 指针解析 -> 再降级到 guest 解析。

local M = {}

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format(fmt, ...))
    else
        c_log(tostring(fmt))
    end
end

local function has_global(name)
    return type(_G[name]) == "function"
end

local function safe_call(fn, ...)
    local ok, a, b = pcall(fn, ...)
    if not ok then
        return nil, -1, tostring(a)
    end
    return a, b
end

-- 解析单个地址（优先 host）
-- @param addr: number（可能是 host 地址或 guest 地址）
-- @param opts: { max_pseudocode_bytes=number }
-- @return info(table|nil), rc(number)
function M.resolve(addr, opts)
    opts = opts or {}
    local max_bytes = tonumber(opts.max_pseudocode_bytes)
    if max_bytes == nil then
        max_bytes = 4096
    end
    if max_bytes < 0 then
        max_bytes = 0
    end

    -- 1) 尝试：直接按 host 地址解析（addr 视为 host）
    if has_global("c_resolve_host_addr") then
        local info, rc = safe_call(c_resolve_host_addr, addr, max_bytes)
        if type(rc) == "number" and rc == 0 and type(info) == "table" then
            info._sftrace_mode = "host"
            return info, 0
        end

        -- 2) 尝试：把 addr 当作 guest，先 g2h 得到 host_ptr 再解析（更通用）
        if has_global("c_g2h") then
            local host_ptr = safe_call(c_g2h, addr)
            if host_ptr ~= nil then
                local info2, rc2 = safe_call(c_resolve_host_addr, host_ptr, max_bytes)
                if type(rc2) == "number" and rc2 == 0 and type(info2) == "table" then
                    info2._sftrace_mode = "g2h_host"
                    info2._sftrace_guest_input = addr
                    info2._sftrace_host_ptr = tostring(host_ptr)
                    return info2, 0
                end
            end
        end
    end

    -- 3) 降级：按 guest 地址解析（老接口）
    if has_global("c_resolve_addr") then
        local info, rc = safe_call(c_resolve_addr, addr, max_bytes)
        if type(rc) == "number" and rc == 0 and type(info) == "table" then
            info._sftrace_mode = "guest"
            return info, 0
        end
        if type(rc) == "number" then
            return info, rc
        end
    end

    return nil, -1
end

local function num(v, default)
    if type(v) ~= "number" then
        return default
    end
    return v
end

-- 输出单帧（与 write.lua 原有格式尽量兼容）
function M.log_frame(i, addr, opts)
    local info, rc = M.resolve(addr, opts)
    if rc == 0 and type(info) == "table" then
        local shown_addr = num(info.addr, addr)
        local name = info.func_name or "??"
        local off = num(info.func_offset, 0)
        local mod = info.map_path or "??"

        log("frame[%d]=0x%x %s+0x%x @ %s", i, shown_addr, name, off, mod)

        local extra = {}
        if type(info.host_addr) == "number" then
            extra[#extra + 1] = string.format("host=0x%x", info.host_addr)
        elseif has_global("c_g2h") and type(info.guest_addr) == "number" then
            local host_ptr = safe_call(c_g2h, info.guest_addr)
            if host_ptr ~= nil then
                extra[#extra + 1] = string.format("host_ptr=%s", tostring(host_ptr))
            end
        elseif has_global("c_g2h") and type(addr) == "number" then
            local host_ptr = safe_call(c_g2h, addr)
            if host_ptr ~= nil then
                extra[#extra + 1] = string.format("host_ptr=%s", tostring(host_ptr))
            end
        end
        if type(info.guest_addr) == "number" and info.guest_addr ~= 0 then
            extra[#extra + 1] = string.format("guest=0x%x", info.guest_addr)
        end
        if type(info.analysis_addr) == "number" then
            extra[#extra + 1] = string.format("analysis=0x%x", info.analysis_addr)
        end
        if type(info.load_bias) == "number" and info.load_bias ~= 0 then
            extra[#extra + 1] = string.format("load_bias=0x%x", info.load_bias)
        end
        if #extra > 0 then
            log("  %s", table.concat(extra, ", "))
        end

        if info.prototype then
            log("  proto: %s", info.prototype)
        end

        if info.pseudocode then
            log("  pseudo_c:\n%s", info.pseudocode)
            if info.pseudocode_truncated then
                log("  pseudo_c: ...(truncated)")
            end
        elseif info.pseudocode_file then
            log("  pseudo_c_file: %s", info.pseudocode_file)
        end

        return true
    end

    -- 失败：尽量输出 host 指针辅助定位
    if has_global("c_g2h") and type(addr) == "number" then
        local host_ptr = safe_call(c_g2h, addr)
        if host_ptr ~= nil then
            log("frame[%d]=0x%x (resolve失败 rc=%d, host_ptr=%s)", i, addr, rc, tostring(host_ptr))
            return false
        end
    end

    log("frame[%d]=0x%x (resolve失败 rc=%d)", i, addr, rc)
    return false
end

-- 输出一组地址（常用于 c_get_shadowstack() 的返回）
function M.log_addrs(addrs, opts)
    if type(addrs) ~= "table" then
        return false
    end
    for i, addr in ipairs(addrs) do
        M.log_frame(i, addr, opts)
    end
    return true
end

return M

