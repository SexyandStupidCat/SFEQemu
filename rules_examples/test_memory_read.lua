-- test_memory_read.lua - 测试内存读取功能的简单脚本

local log = require("rules_examples.base.log")

-- 启用文件日志
local success, log_path = log.enable_file_logging()
if success then
    log.info("Test script logging to: %s", log_path)
end

-- 测试计数器
local call_count = 0

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    call_count = call_count + 1

    -- 只处理前几个系统调用，避免日志过多
    if call_count > 10 then
        return 0, 0
    end

    log.separator("-", 40)
    log.info("Syscall #%d: num=%d", call_count, num)

    -- 测试不同的系统调用
    if num == 2 then  -- open
        log.info("  open(pathname=0x%x, flags=0x%x, mode=0x%x)", arg1, arg2, arg3)

        if arg1 ~= 0 then
            local path, rc = c_read_string(arg1)
            log.info("  c_read_string returned: path='%s', rc=%s",
                    tostring(path), tostring(rc))

            if path and rc == 0 then
                log.info("  ✓ Successfully read pathname: %s", path)
            else
                log.warn("  ✗ Failed to read pathname (rc=%s)", tostring(rc))
            end
        end

    elseif num == 1 then  -- write
        log.info("  write(fd=%d, buf=0x%x, count=%d)", arg1, arg2, arg3)

        if arg2 ~= 0 and arg3 > 0 and arg3 < 200 then
            local content, rc = c_read_string(arg2, arg3)
            log.info("  c_read_string returned: content='%s', rc=%s",
                    tostring(content), tostring(rc))

            if content and rc == 0 then
                log.info("  ✓ Successfully read buffer: %s", content)
            else
                log.warn("  ✗ Failed to read buffer (rc=%s)", tostring(rc))
            end
        end

    else
        log.debug("  (other syscall)")
    end

    return 0, 0
end

log.info("Test script loaded - will show detailed info for first 10 syscalls")
