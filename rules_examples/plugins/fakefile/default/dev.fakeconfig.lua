-- dev.fakeconfig.lua - 默认规则（/dev 下设备文件）
-- 行为：
-- - open  : 返回对应 fakefile 的 fd
-- - read  : 永远返回 0 字节（EOF）
-- - write : 丢弃写入但返回 count（假装写成功）
-- - ioctl : 返回 0（不写入任何输出缓冲）

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir
    :gsub("plugins/fakefile/config/?$", "")
    :gsub("plugins/fakefile/default/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")

local M = {
    file_type = "dev",
    default_state = "init",
    states = {
        init = {
            open = function(ctx) return fakefile.default_open(ctx) end,
            read = function(ctx) return fakefile.default_read_empty(ctx) end,
            write = function(ctx) return fakefile.default_write_discard(ctx) end,
            ioctl = function(ctx) return fakefile.default_ioctl_empty(ctx) end,
        }
    }
}

return M
