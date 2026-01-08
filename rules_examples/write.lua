-- write.lua - Hook for write syscall
-- This script monitors write operations and logs buffer content

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- 读取 buf 指向的字符串内容
    local buf_content = ""

    local byte = ""
    c_log(string.format("[write] fd=%d, buf=0x%x, count=%d", fd, buf, count))

    while true do
        byte = c_read_bytes(buf, 1)
        if count == -1 then break end
        buf_content = buf_content .. byte
        buf = buf + 1
        count = count - 1
    end
    -- 记录 write 操作的基本信息
    c_log(string.format("  -> Buffer: %s", buf_content))
      local stack = c_get_shadowstack()
    for i,addr in ipairs(stack) do
      c_log(string.format("frame[%d]=0x%x", i, addr))
      c_log(string.format("frame[%d]=0x%x", i, c_g2h(addr)))
    end


    return 0, 0
end
