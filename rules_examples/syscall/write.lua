-- write.lua - Hook for write syscall
-- This script monitors write operations and logs buffer content

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local nvram = require(rules_dir .. "base/nvram")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")
local sftrace = require(rules_dir .. "base/sftrace")

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- 先执行 write 自己的逻辑（日志/解析），再交给 fakefile（命中时会拦截并丢弃写入）
    local orig_buf = buf
    local orig_count = count

    -- 读取 buf 指向的字符串内容
    local buf_content = ""

    local byte = ""
    c_log(string.format("[write] fd=%s, buf=0x%x, count=%d", fdmap.format(fd), buf, count))

    local left = tonumber(count) or 0
    if left < 0 then
        left = 0
    end
    while left > 0 do
        byte = c_read_bytes(buf, 1)
        buf_content = buf_content .. byte
        buf = buf + 1
        left = left - 1
    end
    -- 记录 write 操作的基本信息
    c_log(string.format("  -> Buffer: %s", buf_content))

    -- 调用栈符号化：封装在 base/sftrace.lua，默认优先按 host 地址解析
    local stack = c_get_shadowstack()
    -- sftrace.log_addrs(stack, { max_pseudocode_bytes = 2048 })

    -- /dev/nvram：优先兼容（让 nvram_set/nvram_unset 成功）
    local action, retval = nvram.handle_write(num, fd, orig_buf, orig_count, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    local action, retval = fakefile.handle_write(num, fd, orig_buf, orig_count, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    return 0, 0
end
