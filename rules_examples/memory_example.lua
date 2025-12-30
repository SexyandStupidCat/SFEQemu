-- memory_example.lua - 展示如何读写客户机内存
-- 这个示例展示了各种内存操作函数

local log = require("rules_examples.base.log")

log.enable_file_logging()
log.set_level(log.LEVEL.INFO)

log.info("=== Memory Operations Example ===")

-- 辅助函数：十六进制转储
local function hex_dump(data, addr, max_bytes)
    max_bytes = max_bytes or 64
    local len = math.min(#data, max_bytes)

    for i = 1, len, 16 do
        local hex_line = ""
        local ascii_line = ""

        for j = i, math.min(i + 15, len) do
            local byte = string.byte(data, j)
            hex_line = hex_line .. string.format("%02x ", byte)

            -- ASCII 表示
            if byte >= 32 and byte <= 126 then
                ascii_line = ascii_line .. string.char(byte)
            else
                ascii_line = ascii_line .. "."
            end
        end

        -- 对齐
        hex_line = hex_line .. string.rep("   ", 16 - (math.min(i + 15, len) - i + 1))

        log.info("  %08x: %-48s |%s|", addr + i - 1, hex_line, ascii_line)
    end

    if len < #data then
        log.info("  ... (%d more bytes)", #data - len)
    end
end

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    log.count("syscall_total")

    if num == 2 then  -- open
        log.syscall("open", "pathname=0x%x", arg1)

        if arg1 ~= 0 then
            -- 方法 1: 使用 c_read_string 读取字符串
            local path = c_read_string(arg1, 256)
            log.info("  Path (via c_read_string): %s", path)

            -- 方法 2: 使用 c_read_guest_bytes 读取原始字节
            local raw_bytes = c_read_guest_bytes(arg1, 64)
            log.info("  First 64 bytes (raw):")
            hex_dump(raw_bytes, arg1, 64)
        end

        return 0, 0

    elseif num == 1 then  -- write
        log.syscall("write", "fd=%d, buf=0x%x, count=%d", arg1, arg2, arg3)

        if arg2 ~= 0 and arg3 > 0 and arg3 <= 256 then
            -- 读取缓冲区内容
            local content = c_read_string(arg2, arg3)
            log.info("  Content: %s", content)

            -- 如果是写入到特定 fd，显示十六进制转储
            if arg1 == 1 or arg1 == 2 then  -- stdout or stderr
                log.info("  Hex dump of buffer:")
                local raw = c_read_guest_bytes(arg2, math.min(arg3, 64))
                hex_dump(raw, arg2)
            end
        end

        return 0, 0

    elseif num == 9 then  -- mmap
        log.syscall("mmap", "addr=0x%x, length=%d, prot=0x%x, flags=0x%x",
                   arg1, arg2, arg3, arg4)
        return 0, 0

    elseif num == 0 then  -- read
        log.syscall("read", "fd=%d, buf=0x%x, count=%d", arg1, arg2, arg3)

        -- 注意：read 的缓冲区在系统调用返回后才有数据
        -- 这里只能记录参数，不能读取内容

        return 0, 0

    elseif num == 17 then  -- pread64
        log.syscall("pread64", "fd=%d, buf=0x%x, count=%d, offset=%d",
                   arg1, arg2, arg3, arg4)
        return 0, 0

    else
        -- 其他系统调用
        if log.stats["syscall_total"] <= 10 then
            log.debug("Syscall #%d: num=%d", log.stats["syscall_total"], num)
        end
        return 0, 0
    end
end

-- 示例：演示如何写入内存（危险操作，通常不建议）
--[[
function demonstrate_memory_write()
    local test_addr = 0x12345000  -- 假设的地址

    -- 写入 32 位整数
    local rc = c_write_guest_u32(test_addr, 0xdeadbeef)
    if rc == 0 then
        log.info("Wrote u32 to 0x%x", test_addr)

        -- 读回验证
        local value = c_read_guest_u32(test_addr)
        log.info("Read back: 0x%x", value)
    end

    -- 写入原始字节
    local data = "\x01\x02\x03\x04\x05"
    local rc = c_write_guest_bytes(test_addr + 4, data)
    if rc == 0 then
        log.info("Wrote %d bytes", #data)
    end
end
]]--

log.info("Memory operations example loaded")
