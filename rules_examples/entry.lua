-- entry.lua - 系统调用入口脚本
--
-- 约定：
-- 1) C 侧每次进入系统调用都会调用：entry(syscall_name, num, arg1..arg8)
-- 2) 本脚本根据 syscall_name 在 syscall/ 目录中查找同名脚本（例如 syscall/open.lua）
-- 3) syscall/<name>.lua 需定义 do_syscall(num, arg1..arg8)，返回：(need_change, ret)
--    - need_change=true/1：拦截该 syscall，直接返回 ret（不执行 syscall.c 的 do_syscall1）
--    - need_change=false/0：不拦截，继续执行原始 syscall

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir

-- 让 require 支持“绝对路径形式”的模块名（例如 /abs/path/rules/plugins/fakefile）
if type(package) == "table" and type(package.path) == "string" then
    package.path = package.path .. ";?.lua;?/init.lua"
end

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[entry] " .. fmt, ...))
    else
        c_log("[entry] " .. tostring(fmt))
    end
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

-- 加载 config/env（可选）：集中管理 AI/规则相关配置（例如 OPENAI_*、SFEMU_AI_*）
do
    local env_path = rules_dir .. "config/env"
    if not rawget(_G, "_sfemu_env_loaded") and file_exists(env_path) then
        local ok, env_mod = pcall(require, rules_dir .. "base/env")
        if ok and type(env_mod) == "table" and type(env_mod.load_into_globals) == "function" then
            local ok2, info_or_err = env_mod.load_into_globals(env_path, { once_key = "_sfemu_env_loaded" })
            if not ok2 then
                log("加载 config/env 失败：%s", tostring(info_or_err))
            else
                log("已加载 config/env：%s", env_path)
            end
        else
            -- base/env.lua 不存在也不算错误：允许用户只靠命令行/环境变量配置
            if not ok then
                log("加载 base/env.lua 失败：%s", tostring(env_mod))
            end
        end
    end
end

-- syscall_name -> env(do_syscall)
local handler_cache = {}
-- syscall_name -> true（不存在或加载失败，避免每次都做 I/O）
local missing_cache = {}

local CFG = {
    -- 写入 rules/data/ 的上下文保留数量（0=不落盘；由 qemu-user 启动参数 --rules-ctx-keep 设置）
    ctx_keep = tonumber(rawget(_G, "SFEMU_SYSCALL_CTX_KEEP")) or 256,

    -- backtrace 采集/用于签名的最大帧数
    bt_max_frames = 16,
    bt_key_frames = 8,

    -- 死循环检测：寻找“重复序列”
    loop_max_seq_len = 8,
    loop_min_repeats = 3,

    -- 触发交互后，允许继续运行的 syscall 数（用来观察是否被打破）
    probe_grace_syscalls = 64,
}

local data_dir = rules_dir .. "data/"
local state = {
    seq = 0,
    keys = {},
    ctxs = {},
    files = {},
    ai = {
        runs = 0,
        last_run_seq = 0,
    },
    loop = {
        active = false,
        probe_started = false,
        probe_at_seq = 0,
        last_report_path = nil,
        seq_len = nil,
        repeats = nil,
    },
}

local function reset_loop_state()
    state.loop.active = false
    state.loop.probe_started = false
    state.loop.probe_at_seq = 0
    state.loop.last_report_path = nil
    state.loop.seq_len = nil
    state.loop.repeats = nil
end

local function invalidate_handler(syscall_name)
    if type(syscall_name) ~= "string" or syscall_name == "" then
        return
    end
    handler_cache[syscall_name] = nil
    missing_cache[syscall_name] = nil
end

local ai_mod_checked = false
local ai_mod = nil

local function get_ai_module()
    if ai_mod_checked then
        return ai_mod
    end
    ai_mod_checked = true
    local ok, mod = pcall(require, rules_dir .. "base/ai")
    if ok and type(mod) == "table" and type(mod.handle) == "function" then
        ai_mod = mod
        return ai_mod
    end
    if not ok then
        log("加载 AI 模块失败：%s", tostring(mod))
    else
        log("AI 模块不可用：base/ai.lua 未返回 handle()")
    end
    ai_mod = nil
    return nil
end

local function load_handler_env(syscall_name)
    if handler_cache[syscall_name] then
        return handler_cache[syscall_name]
    end
    if missing_cache[syscall_name] then
        return nil
    end

    local path = rules_dir .. "syscall/" .. syscall_name .. ".lua"
    if not file_exists(path) then
        missing_cache[syscall_name] = true
        return nil
    end

    local env = setmetatable({}, { __index = _G })
    env.__rules_dir = rules_dir
    env.__syscall_name = syscall_name

    local chunk, err = loadfile(path, "t", env)
    if not chunk then
        log("加载失败：%s（%s）", path, tostring(err))
        missing_cache[syscall_name] = true
        return nil
    end

    local ok, exec_err = pcall(chunk)
    if not ok then
        log("执行失败：%s（%s）", path, tostring(exec_err))
        missing_cache[syscall_name] = true
        return nil
    end

    if type(env.do_syscall) ~= "function" then
        log("脚本未定义 do_syscall：%s", path)
        missing_cache[syscall_name] = true
        return nil
    end

    handler_cache[syscall_name] = env
    return env
end

local function get_backtrace()
    if type(c_get_shadowstack) ~= "function" then
        return {}
    end
    local bt = c_get_shadowstack()
    if type(bt) ~= "table" then
        return {}
    end
    local out = {}
    local n = math.min(#bt, CFG.bt_max_frames)
    for i = 1, n do
        out[i] = bt[i]
    end
    return out
end

local function make_sig_key(ctx)
    local parts = { tostring(ctx.num or 0) }
    local args = ctx.args or {}
    for i = 1, 8 do
        parts[#parts + 1] = tostring(args[i] or 0)
    end
    local bt = ctx.backtrace or {}
    local bt_parts = {}
    local n = math.min(#bt, CFG.bt_key_frames)
    for i = 1, n do
        bt_parts[#bt_parts + 1] = string.format("0x%x", bt[i])
    end
    parts[#parts + 1] = table.concat(bt_parts, ",")
    return table.concat(parts, "|")
end

local function join_args(args)
    if type(args) ~= "table" then
        return ""
    end
    local out = {}
    for i = 1, #args do
        out[i] = tostring(args[i])
    end
    return table.concat(out, ", ")
end

local function write_ctx_to_data_dir(ctx)
    if CFG.ctx_keep <= 0 then
        return nil
    end

    local safe_name = tostring(ctx.name or "nil"):gsub("[^%w_%-%.]", "_")
    local path = string.format("%ssyscall_ctx_%08d_%s.txt", data_dir, ctx.seq, safe_name)

    local f = io.open(path, "wb")
    if not f then
        log("写入失败：%s（请确认 data/ 目录存在且可写）", path)
        return nil
    end

    f:write(string.format("seq: %d\n", ctx.seq))
    if ctx.ts_sec ~= nil and ctx.ts_nsec ~= nil then
        f:write(string.format("ts: %d.%09d\n", ctx.ts_sec, ctx.ts_nsec))
    elseif ctx.ts_sec ~= nil then
        f:write(string.format("ts: %s\n", tostring(ctx.ts_sec)))
    end
    f:write(string.format("syscall: %s (%d)\n", tostring(ctx.name), tonumber(ctx.num) or 0))
    f:write(string.format("args: %s\n", join_args(ctx.args)))
    f:write("backtrace:\n")
    for i, addr in ipairs(ctx.backtrace or {}) do
        f:write(string.format("  #%02d 0x%x\n", i, addr))
    end
    f:close()

    table.insert(state.files, path)
    while #state.files > CFG.ctx_keep do
        local old = table.remove(state.files, 1)
        pcall(os.remove, old)
    end

    return path
end

local function push_recent(ctx)
    local mem_keep = math.min(math.max(CFG.ctx_keep, 256), 2048)
    table.insert(state.keys, ctx.sig_key)
    table.insert(state.ctxs, ctx)
    while #state.keys > mem_keep do
        table.remove(state.keys, 1)
    end
    while #state.ctxs > mem_keep do
        table.remove(state.ctxs, 1)
    end
end

local function detect_repeating_sequence(keys, max_seq_len, min_repeats)
    local n = #keys
    for seq_len = 1, max_seq_len do
        local total = seq_len * min_repeats
        if n < total then
            break
        end

        local ok = true
        local base0 = n - seq_len + 1
        for rep = 1, min_repeats - 1 do
            local base = base0
            local other = n - (rep + 1) * seq_len + 1
            for i = 0, seq_len - 1 do
                if keys[base + i] ~= keys[other + i] then
                    ok = false
                    break
                end
            end
            if not ok then
                break
            end
        end

        if ok then
            return seq_len, min_repeats
        end
    end
    return nil, nil
end

local function resolve_addr_brief(addr, max_bytes)
    if type(c_resolve_addr) ~= "function" then
        return nil, -1
    end
    local info, rc = c_resolve_addr(addr, max_bytes or 2048)
    return info, rc
end

local function dump_deadloop_report(seq_len, repeats)
    local need = seq_len * repeats
    if need <= 0 or #state.ctxs < need then
        return nil
    end

    local path = string.format("%sdeadloop_%08d.log", data_dir, state.seq)
    local f = io.open(path, "wb")
    if not f then
        log("写入失败：%s（请确认 data/ 目录存在且可写）", path)
        return nil
    end

    f:write(string.format("deadloop: seq_len=%d repeats=%d\n", seq_len, repeats))
    f:write(string.format("note: 该报告由 Lua 侧基于 syscall 上下文重复序列生成；若启用 --sfanalysis，可附带伪C。\n\n"))

    local start = #state.ctxs - need + 1
    for i = start, #state.ctxs do
        local ctx = state.ctxs[i]
        f:write(string.format("== ctx #%d (global_seq=%d) ==\n", i - start + 1, ctx.seq))
        if ctx.ts_sec ~= nil and ctx.ts_nsec ~= nil then
            f:write(string.format("ts: %d.%09d\n", ctx.ts_sec, ctx.ts_nsec))
        end
        f:write(string.format("syscall: %s (%d)\n", tostring(ctx.name), tonumber(ctx.num) or 0))
        f:write(string.format("args: %s\n", join_args(ctx.args)))
        f:write("backtrace:\n")

        local bt = ctx.backtrace or {}
        local max_frames = math.min(#bt, 8)
        for j = 1, max_frames do
            local addr = bt[j]
            f:write(string.format("  #%02d 0x%x\n", j, addr))
            local info, rc = resolve_addr_brief(addr, 2048)
            if rc == 0 and type(info) == "table" then
                local fn = info.func_name or "(unknown)"
                local mod = info.module_name or "(unknown)"
                f:write(string.format("        %s :: %s\n", tostring(mod), tostring(fn)))
                if info.prototype then
                    f:write(string.format("        %s\n", tostring(info.prototype)))
                end
                if info.pseudocode then
                    f:write("        --- pseudocode ---\n")
                    f:write(tostring(info.pseudocode))
                    if tostring(info.pseudocode):sub(-1) ~= "\n" then
                        f:write("\n")
                    end
                    if info.pseudocode_truncated then
                        f:write("        (pseudocode truncated)\n")
                    end
                    f:write("        --- end ---\n")
                end
            end
        end

        f:write("\n")
    end

    f:close()
    return path
end

local function check_status(ctx)
    local seq_len, repeats = detect_repeating_sequence(state.keys, CFG.loop_max_seq_len, CFG.loop_min_repeats)
    if not seq_len then
        reset_loop_state()
        return true
    end

    if not state.loop.active then
        state.loop.active = true
        state.loop.probe_started = false
        state.loop.probe_at_seq = 0
        state.loop.last_report_path = nil
        state.loop.seq_len = seq_len
        state.loop.repeats = repeats
        log("检测到疑似死循环：重复序列 seq_len=%d repeats=%d", seq_len, repeats)
    end

    if not state.loop.probe_started then
        state.loop.probe_started = true
        state.loop.probe_at_seq = state.seq
        if type(c_async_probe_http) == "function" then
            local started, rc = c_async_probe_http("127.0.0.1", 500)
            log("触发目标服务交互（80/443）: started=%s rc=%s", tostring(started), tostring(rc))
        else
            log("未找到 c_async_probe_http，跳过自动交互探测")
        end
        return true
    end

    if (state.seq - state.loop.probe_at_seq) < CFG.probe_grace_syscalls then
        return true
    end

    if not state.loop.last_report_path then
        state.loop.last_report_path = dump_deadloop_report(seq_len, repeats)
    end
    return false
end

local function pause_and_wait_handle(ctx)
    log("进入暂停：syscall=%s(%d) seq=%d", tostring(ctx.name), tonumber(ctx.num) or 0, ctx.seq)
    if state.loop.last_report_path then
        log("死循环报告已写入：%s", tostring(state.loop.last_report_path))
    end
end

local function need_ai(ctx)
    local v = rawget(_G, "SFEMU_AI_ENABLE")
    if v == nil then
        -- 兼容旧开关：SFEMU_NEED_AI
        local legacy = rawget(_G, "SFEMU_NEED_AI")
        if legacy ~= nil then
            return legacy == true
        end
        -- 默认开启：仅在 exit/死循环这类失败路径触发，避免影响正常路径
        return true
    end
    return v == true or v == 1 or tostring(v) == "1" or tostring(v) == "true" or tostring(v) == "on"
end

local function ai_handle(ctx, meta)
    meta = meta or {}
    local ai = get_ai_module()
    if not ai then
        return { auto_continue = false }
    end

    log("触发 AI.handle：reason=%s syscall=%s(%d) seq=%d",
        tostring(meta.reason or "unknown"),
        tostring(ctx and ctx.name),
        tonumber(ctx and ctx.num) or 0,
        tonumber(ctx and ctx.seq) or 0)

    state.ai.runs = (state.ai.runs or 0) + 1
    state.ai.last_run_seq = ctx.seq

    local ok, res = pcall(ai.handle, ctx, state, meta)
    if not ok then
        log("AI 干预失败：%s", tostring(res))
        return { auto_continue = false }
    end

    if type(res) == "table" then
        log("AI.handle 完成：run_id=%s auto_continue=%s applied_fix=%d",
            tostring(res.run_id or ""),
            tostring(res.auto_continue == true),
            type(res.applied_fix_syscalls) == "table" and #res.applied_fix_syscalls or 0)
    end

    if type(res) == "table" and type(res.applied_syscalls) == "table" then
        for _, name in ipairs(res.applied_syscalls) do
            invalidate_handler(name)
        end
    end

    return res or { auto_continue = false }
end

local function manual_handle(ctx)
    if type(c_wait_user_continue) == "function" then
        c_wait_user_continue("检测到仿真异常/死循环，输入 YES 继续运行: ")
        reset_loop_state()
        return
    end
    io.write("检测到仿真异常/死循环，输入 YES 继续运行: ")
    io.flush()
    io.read("*l")
    reset_loop_state()
end

local function save_content(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    state.seq = state.seq + 1
    local sec, nsec = nil, nil
    if type(c_get_timestamp) == "function" then
        sec, nsec = c_get_timestamp()
    end

    local ctx = {
        seq = state.seq,
        name = syscall_name,
        num = num,
        args = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8 },
        ts_sec = sec,
        ts_nsec = nsec,
        backtrace = get_backtrace(),
    }
    ctx.sig_key = make_sig_key(ctx)
    ctx.data_path = write_ctx_to_data_dir(ctx)

    _G._sfemu_syscall_ctx = ctx
    push_recent(ctx)
end

function entry(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 清理上一条 syscall 的上下文，避免 finish.lua 误用旧数据
    _G._sfemu_syscall_ctx = nil

    if type(syscall_name) ~= "string" or syscall_name == "" then
        return false, 0
    end

    save_content(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    _G._sfemu_syscall_ctx.hooked = true

    -- exit/exit_group：始终触发人工/AI 处理，但不做 check_status
    if syscall_name == "exit" or syscall_name == "exit_group" then
        pause_and_wait_handle(_G._sfemu_syscall_ctx)
        local res = nil
        local ai_on = need_ai(_G._sfemu_syscall_ctx)
        log("exit 触发：need_ai=%s", tostring(ai_on))
        if ai_on then
            res = ai_handle(_G._sfemu_syscall_ctx, { reason = "exit" })
        end
        if not (type(res) == "table" and res.auto_continue == true) then
            manual_handle(_G._sfemu_syscall_ctx)
        end
    else
        if not check_status(_G._sfemu_syscall_ctx) then
            pause_and_wait_handle(_G._sfemu_syscall_ctx)
            local loop_names = {}
            if state.loop.seq_len and state.loop.seq_len > 0 then
                local n = #state.ctxs
                local start = math.max(1, n - state.loop.seq_len + 1)
                for i = start, n do
                    local c = state.ctxs[i]
                    if type(c) == "table" and type(c.name) == "string" then
                        loop_names[#loop_names + 1] = c.name
                    end
                end
            end

            local res = nil
            local ai_on = need_ai(_G._sfemu_syscall_ctx)
            log("deadloop 触发：need_ai=%s", tostring(ai_on))
            if ai_on then
                res = ai_handle(_G._sfemu_syscall_ctx, {
                    reason = "deadloop",
                    loop_seq_len = state.loop.seq_len,
                    loop_repeats = state.loop.repeats,
                    loop_report_path = state.loop.last_report_path,
                    loop_names = loop_names,
                })
            end
            if type(res) == "table" and res.auto_continue == true then
                -- 自动继续时，需解除本轮“已判定失败”的状态，避免立即再次触发暂停
                reset_loop_state()
            end
            if not (type(res) == "table" and res.auto_continue == true) then
                manual_handle(_G._sfemu_syscall_ctx)
            end
        end
    end

    -- 若 AI 已进入“验证窗口”，则在正常 syscall 路径中检测是否已稳定并导出规则
    do
        local gs = rawget(_G, "_sfemu_ai_state")
        if type(gs) == "table" and type(gs.verify) == "table" and gs.verify.active == true then
            local ai = get_ai_module()
            if ai and type(ai.on_syscall) == "function" then
                pcall(ai.on_syscall, _G._sfemu_syscall_ctx, state)
            end
        end
    end



    local env = load_handler_env(syscall_name)
    if not env then
        return false, 0
    end

    local ok, action, ret = pcall(env.do_syscall, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if not ok then
        log("do_syscall 异常：%s（%s）", syscall_name, tostring(action))
        return false, 0
    end

    local need_change = (action == true) or (action == 1)
    if not need_change then
        return false, 0
    end

    if type(ret) ~= "number" then
        ret = 0
    end

    _G._sfemu_syscall_ctx.need_change = true
    _G._sfemu_syscall_ctx.ret = ret

    return true, ret
end
