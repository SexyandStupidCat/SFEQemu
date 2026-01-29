-- mmap2.lua - Hook for mmap2 syscall（ARM EABI）
--
-- 说明：
-- - 在 ARM 上用户态通常使用 mmap2（offset 以 4K 页为单位）
-- - /dev/nvram 的 nvram_init 依赖 mmap2 成功建立“nvram 数据区”

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local nvram = require(rules_dir .. "base/nvram")

function do_syscall(num, addr, length, prot, flags, fd, pgoffset, arg8, arg9)
    local action, retval = nvram.handle_mmap(num, addr, length, prot, flags, fd, pgoffset, arg8, arg9)
    if action == 1 then
        return action, retval
    end
    return 0, 0
end

c_log("Loaded mmap2.lua")

