-- socket.fakeconfig.lua - 默认规则（Unix domain socket）
-- 行为：
-- - connect: 当目标 socket 缺失/不可用时，将 sockfd 交给 fakefile 托管并返回成功（避免创建真实 socket 文件）。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir
    :gsub("plugins/fakefile/config/?$", "")
    :gsub("plugins/fakefile/default/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")

local M = {
    file_type = "socket",
    default_state = "init",
    states = {
        init = {
            connect = function(ctx) return fakefile.default_connect_socket(ctx) end,
        }
    }
}

return M
