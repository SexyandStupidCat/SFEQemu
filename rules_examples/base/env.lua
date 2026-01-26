-- env.lua - 从 rules/config/env 读取配置（.env 风格）并注入到 Lua 全局变量
--
-- 设计目标：
-- - 让 AI/规则相关配置集中在 rules/config/env 中（例如 OPENAI_API_KEY、OPENAI_BASE_URL、SFEMU_AI_*）。
-- - 解析足够简单且稳健：支持 KEY=VALUE、export KEY=VALUE、忽略空行与注释行。
-- - 不做“类型推断”：全部按字符串写入 _G；上层用 tonumber/str_bool 自行解析。

local M = {}

local function trim(s)
    return (tostring(s):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function strip_utf8_bom(s)
    -- UTF-8 BOM: EF BB BF
    return (tostring(s):gsub("^\239\187\191", ""))
end

local function parse_line(line)
    line = tostring(line or ""):gsub("\r", "")
    line = trim(line)
    if line == "" then
        return nil
    end
    local first = line:sub(1, 1)
    if first == "#" or first == ";" then
        return nil
    end

    line = line:gsub("^export%s+", "")
    local k, v = line:match("^([A-Za-z_][A-Za-z0-9_]*)%s*=%s*(.*)$")
    if not k then
        return nil
    end

    v = trim(v or "")
    local q = v:sub(1, 1)
    if (#v >= 2) and ((q == "'" and v:sub(-1) == "'") or (q == "\"" and v:sub(-1) == "\"")) then
        v = v:sub(2, -2)
        return k, v
    end

    -- 非引号包裹：去掉尾部注释（常见 .env 写法；不追求完全兼容）
    local p_hash = v:find("%s#")
    if p_hash then
        v = trim(v:sub(1, p_hash - 1))
    end
    local p_semi = v:find("%s;")
    if p_semi then
        v = trim(v:sub(1, p_semi - 1))
    end

    return k, v
end

function M.load(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end
    local data = f:read("*a") or ""
    f:close()

    data = strip_utf8_bom(data)

    local env = {}
    local order = {}
    for line in (data .. "\n"):gmatch("([^\n]*)\n") do
        local k, v = parse_line(line)
        if k then
            env[k] = v
            order[#order + 1] = k
        end
    end
    return env, order
end

function M.load_into_globals(path, opts)
    opts = opts or {}
    local once_key = opts.once_key
    if type(once_key) == "string" and rawget(_G, once_key) then
        return true, { skipped = true, path = path }
    end

    local env, err = M.load(path)
    if not env then
        return false, err
    end

    local loaded = {}
    for k, v in pairs(env) do
        _G[k] = v
        loaded[#loaded + 1] = k
    end
    table.sort(loaded)

    if type(once_key) == "string" then
        _G[once_key] = true
    end

    return true, { path = path, loaded = loaded }
end

return M

