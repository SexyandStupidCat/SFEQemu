-- open.lua - Hook for open syscall
-- This script monitors file open operations

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("open(pathname=0x%x, flags=0x%x, mode=0x%x)", pathname, flags, mode))

    -- You could read the pathname using c_read_string if properly implemented
    -- local path = c_read_string(pathname)
    -- if path:match("/etc/passwd") then
    --     c_log("Blocked attempt to open /etc/passwd")
    --     return 1, -13  -- Return -EACCES
    -- end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded open.lua")
