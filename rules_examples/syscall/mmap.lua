-- mmap.lua - Hook for mmap syscall
-- This script monitors memory mapping operations

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local nvram = require(rules_dir .. "base/nvram")

function do_syscall(num, addr, length, prot, flags, fd, offset, arg7, arg8)
    -- /dev/nvram：优先兼容（nvram_init 需要 mmap 成功）
    local action, retval = nvram.handle_mmap(num, addr, length, prot, flags, fd, offset, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    local sec, nsec = c_get_timestamp()

    -- Log large memory mappings
    if length > 1048576 then  -- > 1MB
        c_log(string.format("[%d.%09d] Large mmap: addr=0x%x, length=%d bytes (%.2f MB)",
                           sec, nsec, addr, length, length / 1048576.0))
    end

    -- Log anonymous mappings
    if flags & 0x20 then  -- MAP_ANONYMOUS
        c_log(string.format("  -> Anonymous mapping"))
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded mmap.lua")
