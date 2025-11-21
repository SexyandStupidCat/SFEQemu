-- write_with_content.lua - Enhanced write hook that reads and logs buffer content
-- This demonstrates using c_read_guest_string to read memory

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- Read the actual content being written
    local content = c_read_guest_string(buf, count)

    c_log(string.format("[Write] fd=%d, count=%d, content='%s'", fd, count, content))

    -- Call the original write syscall
    local ret = c_do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)

    if ret >= 0 then
        c_log(string.format("  -> Successfully wrote %d bytes", ret))
    else
        c_log(string.format("  -> Error: %d", ret))
    end

    return ret
end

c_log("Loaded write_with_content.lua - reading buffer content")
