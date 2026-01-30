-- execve.lua - Hook for execve syscall
-- 目标：只记录将要执行的命令行，不做任何干预（直接放行原始 syscall）。

local function u32_le(bytes)
    if type(bytes) ~= "string" or #bytes < 4 then
        return nil
    end
    local b1 = string.byte(bytes, 1)
    local b2 = string.byte(bytes, 2)
    local b3 = string.byte(bytes, 3)
    local b4 = string.byte(bytes, 4)
    return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)
end

local function read_cstr(ptr, max_len)
    if not ptr or ptr == 0 then
        return nil, -1
    end

    -- 说明：c_read_string 内部会 lock_user(max_len)，若字符串指针接近页边界，
    -- max_len 过大可能导致 rc!=0。这里采用“由小到大”探测，提升稳定性。
    local lens = { 256, 1024, 4096 }
    for _, n in ipairs(lens) do
        local s, rc = c_read_string(ptr, math.min(n, max_len or n))
        if rc == 0 and s and s ~= "" and s ~= "(null)" then
            s = s:match("^([^%z]*)")
            return s, 0
        end
    end

    local _, rc = c_read_string(ptr, math.min(256, max_len or 256))
    return nil, rc
end

local function read_argv(argv_ptr, max_args, max_arg_len)
    argv_ptr = tonumber(argv_ptr) or 0
    if argv_ptr == 0 then
        return nil, "argv_null"
    end

    max_args = tonumber(max_args) or 32
    max_arg_len = tonumber(max_arg_len) or 256
    if max_args < 1 then
        max_args = 1
    end
    if max_args > 256 then
        max_args = 256
    end

    local out = {}
    for i = 0, max_args - 1 do
        local pbytes, rc = c_read_bytes(argv_ptr + i * 4, 4)
        if rc ~= 0 then
            break
        end
        local p = u32_le(pbytes) or 0
        if p == 0 then
            break
        end
        local s = nil
        s = select(1, read_cstr(p, max_arg_len))
        if s and s ~= "" then
            table.insert(out, s)
        else
            table.insert(out, string.format("<arg@0x%x>", p))
        end
    end

    if #out == 0 then
        return nil, "argv_empty"
    end
    return out, nil
end

local function join_cmd(argv, fallback)
    if type(argv) == "table" and #argv > 0 then
        local s = table.concat(argv, " ")
        if #s > 1024 then
            s = s:sub(1, 1024) .. "..."
        end
        return s
    end
    return tostring(fallback or "")
end

function do_syscall(num, filename, argv, envp, arg4, arg5, arg6, arg7, arg8)
    local path = select(1, read_cstr(filename, 4096)) or string.format("(unreadable filename=0x%x)", tonumber(filename) or 0)
    local args = select(1, read_argv(argv, 64, 512))
    local cmd = join_cmd(args, path)

    if type(c_log) == "function" then
        c_log(string.format("[execve] %s", cmd))
    end

    -- 不拦截：继续执行真实 syscall
    return 0, 0
end

