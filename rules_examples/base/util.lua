-- base/util.lua - 规则侧通用小工具
--
-- 约定：
-- - 本模块只放“无副作用”的纯工具函数，避免引入额外依赖

local M = {}

-- 把常见的环境变量/字符串开关解析为 boolean
function M.str_bool(v, default)
    if v == nil then
        return default
    end
    if v == true or v == 1 then
        return true
    end
    if v == false or v == 0 then
        return false
    end
    local s = tostring(v):lower()
    if s == "1" or s == "true" or s == "on" or s == "yes" then
        return true
    end
    if s == "0" or s == "false" or s == "off" or s == "no" then
        return false
    end
    return default
end

return M

