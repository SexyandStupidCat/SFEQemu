-- open.lua - Hook for open syscall
-- This script monitors file open operations and logs pathname
--
-- Return values:
--   (0, 0) = Don't intercept, let the original syscall run
--   (1, return_value) = Intercept and return the specified value

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 读取 pathname 指向的字符串
    local path = ""
    local rc = -1

    if pathname ~= 0 then
        -- c_read_string 返回两个值：字符串和错误码
        path, rc = c_read_string(pathname)

        -- 确保 path 和 rc 不是 nil
        if not path then
            path = ""
        end
        if not rc then
            rc = -1
        end
    end

    -- 记录 open 操作
    c_log(string.format("[open] pathname=0x%x, flags=0x%x, mode=0x%x", pathname, flags, mode))

    -- 打印路径字符串
    if path and path ~= "" and rc == 0 then
        c_log(string.format("  -> Pathname: %s", path))
    else
        c_log(string.format("  -> Pathname read failed (rc=%s)", tostring(rc)))
    end

    -- 返回 (0, 0) 表示不拦截，让原始 syscall 继续执行
    return 0, 0
end
