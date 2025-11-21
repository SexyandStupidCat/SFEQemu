-- open.lua - Hook for open syscall
-- This script demonstrates conditional blocking and forwarding

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("open(pathname=0x%x, flags=0x%x, mode=0x%x)", pathname, flags, mode))

    -- Example: Block opening files in write mode (flags & O_WRONLY or O_RDWR)
    local O_WRONLY = 1
    local O_RDWR = 2
    local is_write = (flags & O_WRONLY ~= 0) or (flags & O_RDWR ~= 0)

    if false then -- Change to true to enable blocking
        if is_write then
            c_log("  -> Blocked write access!")
            return -13  -- -EACCES (Permission denied)
        end
    end

    -- Forward to original syscall
    local ret = c_do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("  -> Returned fd: %d", ret))
    return ret
end

c_log("Loaded open.lua (v2)")
