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

-- 通用开关解析（auto_ai / SFEMU_AUTO_AI 等）
local util_checked = false
local util_mod = nil

local function str_bool(v, default)
    if v == nil then
        return default
    end

    if not util_checked then
        util_checked = true
        local ok, mod = pcall(require, rules_dir .. "base/util")
        if ok and type(mod) == "table" and type(mod.str_bool) == "function" then
            util_mod = mod
        end
    end

    if util_mod and type(util_mod.str_bool) == "function" then
        return util_mod.str_bool(v, default)
    end

    -- 兜底：最小实现
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

local function auto_ai_enabled()
    -- 兼容多种命名：auto_ai（推荐，最短）、SFEMU_AUTO_AI（更语义化）
    local v = rawget(_G, "auto_ai")
    if v == nil then
        v = rawget(_G, "SFEMU_AUTO_AI")
    end
    return str_bool(v, false)
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

-- 启动前自检/补齐：某些固件 rootfs 解包后权限/目录/证书不完整，会导致 httpd 早退。
-- 这里把“必要但无副作用”的补齐动作放在入口处，确保在业务代码启动前完成。
do
    local ok, mod = pcall(require, rules_dir .. "base/bootstrap_fs")
    if ok and type(mod) == "table" and type(mod.bootstrap) == "function" then
        local ok2, err = pcall(mod.bootstrap)
        if not ok2 then
            log("bootstrap_fs 执行失败：%s", tostring(err))
        end
    elseif not ok then
        log("加载 bootstrap_fs 失败：%s", tostring(mod))
    end
end

-- syscall_name -> env(do_syscall)
local handler_cache = {}
-- syscall_name -> true（不存在或加载失败，避免每次都做 I/O）
local missing_cache = {}

local CFG = {
    -- 写入 rules/cache/ 的上下文保留数量（0=不落盘；由 qemu-user 启动参数 --rules-ctx-keep 设置）
    ctx_keep = tonumber(rawget(_G, "SFEMU_SYSCALL_CTX_KEEP")) or 256,

    -- backtrace 采集/用于签名的最大帧数
    bt_max_frames = 16,
    bt_key_frames = 8,

    -- 死循环检测：寻找“重复序列”
    loop_max_seq_len = 8,
    loop_min_repeats = 3,
    -- 死循环检测的时间窗：仅把“短时间内高频重复”的序列视为死循环（避免将周期性轮询误判为死循环）
    loop_max_span_ms = tonumber(rawget(_G, "SFEMU_LOOP_MAX_SPAN_MS")) or 500,

    -- 触发交互后，允许继续运行的 syscall 数（用来观察是否被打破）
    probe_grace_syscalls = 64,
}

-- syscall_name 可能为 nil（C 侧映射表不全）。这里补充一小段“按 syscall 号反查名称”，
-- 以便为网络相关 syscall（sendmsg/recvmsg 等）加载对应 Lua 规则。
--
-- 说明：这些号以 ARM EABI 为准（与本项目已有日志一致：socket=281, connect=283, openat=322）。
local SYSCALL_NUM_TO_NAME = {
    -- ARM EABI: execve=11 / execveat=387（仅观测：打印命令行，不拦截）
    [11] = "execve",
    [387] = "execveat",
    [289] = "send",
    [290] = "sendto",
    [291] = "recv",
    [292] = "recvfrom",
    [296] = "sendmsg",
    [297] = "recvmsg",
    -- ARM EABI: mmap2=192（大量动态链接/库加载会用到；/dev/nvram 也依赖 mmap2）
    [192] = "mmap2",
    -- ARM EABI: close_range=436（daemonize 常用：一次性关闭大量 fd；需保护 QEMU 内部 fd）
    [436] = "close_range",
    -- ARM EABI: pselect6=335（很多固件用它当 sleep；若卡在“长睡眠循环”需要可观测/可触发 AI）
    [335] = "pselect6",
    -- ARM EABI: _newselect=142（部分固件用它当 sleep；若未映射会导致日志/死循环检测/AI 触发链断裂）
    [142] = "select",
}

-- cache/：用于落盘 syscall 上下文、死循环报告、AI 快照与稳定规则等
local function ensure_dir(path)
    if type(path) ~= "string" or path == "" then
        return false
    end
    if type(c_mkdir_p) == "function" then
        local ok = pcall(c_mkdir_p, path, 493) -- 0755
        return ok
    end
    local cmd = string.format("mkdir -p %q >/dev/null 2>&1", path)
    local r1, _r2, r3 = os.execute(cmd)
    return r1 == true or r1 == 0 or r3 == 0
end

local cache_dir = rules_dir .. "cache/"
ensure_dir(cache_dir)
local state = {
    seq = 0,
    keys = {},
    ctxs = {},
    files = {},
    idle_seq = 0,
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
        -- “长睡眠循环”检测：常见形态为 pselect6(nfds=0, timeout=~10s) 反复调用
        sleep_detected = false,
        sleep_count = 0,
        sleep_repeats = nil,
    },
}

local function reset_loop_state()
    state.loop.active = false
    state.loop.probe_started = false
    state.loop.probe_at_seq = 0
    state.loop.last_report_path = nil
    state.loop.seq_len = nil
    state.loop.repeats = nil
    state.loop.sleep_detected = false
    state.loop.sleep_count = 0
    state.loop.sleep_repeats = nil
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

    -- 规则加载优先级：
    -- 1) syscall_override_user/<name>.lua（本地临时修复，通常由人工快速迭代）
    -- 2) syscall_override/<name>.lua（AI/临时修复，不覆盖原规则）
    -- 2) syscall/<name>.lua（基础规则）
    local function resolve_rule_path(name)
        local od = rawget(_G, "SFEMU_RULES_OVERRIDE_DIR")
        if type(od) ~= "string" or od == "" then
            -- 默认：先查用户临时 override，再查 AI 生成 override（若目录不存在则自动跳过）
            od = "syscall_override_user:syscall_override"
        end

        -- 支持使用 ':' 指定多个 override 目录（类似 PATH）
        for dir in tostring(od):gmatch("[^:]+") do
            dir = tostring(dir):gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "")
            if dir ~= "" then
                local p1
                if dir:sub(1, 1) == "/" then
                    p1 = dir .. "/" .. name .. ".lua"
                else
                    p1 = rules_dir .. dir .. "/" .. name .. ".lua"
                end
                if file_exists(p1) then
                    return p1
                end
            end
        end
        local p2 = rules_dir .. "syscall/" .. name .. ".lua"
        if file_exists(p2) then
            return p2
        end
        return nil
    end

    -- 重要：AI 可能在运行中生成新规则文件。
    -- 若之前该 syscall 缺失导致 missing_cache 命中，则这里需要“有条件地破缓存”：
    -- - 仅当 override 目录中出现了新文件时才清理 missing_cache 并尝试加载；
    -- - 避免在正常情况下每次都触发 I/O。
    if missing_cache[syscall_name] then
        local p_user = rules_dir .. "syscall_override_user/" .. syscall_name .. ".lua"
        local p_ai = rules_dir .. "syscall_override/" .. syscall_name .. ".lua"
        if file_exists(p_user) or file_exists(p_ai) then
            missing_cache[syscall_name] = nil
        else
            return nil
        end
    end

    local path = resolve_rule_path(syscall_name)
    if not path then
        missing_cache[syscall_name] = true
        return nil
    end

    if str_bool(rawget(_G, "SFEMU_LOG_RULE_LOAD"), false) then
        log("加载规则：%s -> %s", tostring(syscall_name), tostring(path))
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
    local path = string.format("%ssyscall_ctx_%08d_%s.txt", cache_dir, ctx.seq, safe_name)

    local f = io.open(path, "wb")
    if not f then
        log("写入失败：%s（请确认 cache/ 目录存在且可写）", path)
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

    local path = string.format("%sdeadloop_%08d.log", cache_dir, state.seq)
    local f = io.open(path, "wb")
    if not f then
        log("写入失败：%s（请确认 cache/ 目录存在且可写）", path)
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
    -- 额外：长睡眠循环（不属于“短时间高频重复”，但会导致 httpd 永远不启动）
    --
    -- 典型：pselect6(nfds=0, timeout=10s) 被当作 sleep() 使用，反复等待某个永远不会满足的条件。
    -- 这里用“次数阈值”触发一次 AI 干预，避免一直挂起且无法被 deadloop/idle_watchdog 捕捉。
    do
        if type(ctx) == "table" and type(ctx.args) == "table" then
            -- 注意：ARM 上 syscall 142 为 _newselect，但有些 QEMU 映射表会把它展示为 select 或直接缺失 name。
            -- 只要识别到“nfds=0 的 select/pselect6”，就把它视为 sleep 型等待并计数。
            local is_sleep_like = (ctx.name == "pselect6") or (ctx.name == "select") or (ctx.name == "_newselect")
            if is_sleep_like then
                local nfds = tonumber(ctx.args[1]) or -1
                if nfds == 0 then
                    state.loop.sleep_count = (tonumber(state.loop.sleep_count) or 0) + 1
                    local th = tonumber(rawget(_G, "SFEMU_SLEEP_LOOP_SELECT_REPEATS"))
                        or tonumber(rawget(_G, "SFEMU_SLEEP_LOOP_PSELECT6_REPEATS"))
                        or 2
                    if th < 1 then
                        th = 1
                    end
                    if state.loop.sleep_count >= th then
                        state.loop.sleep_detected = true
                        state.loop.sleep_repeats = state.loop.sleep_count
                        state.loop.sleep_count = 0
                        log("检测到疑似长睡眠循环：%s(nfds=0) repeats=%d", tostring(ctx.name), tonumber(state.loop.sleep_repeats) or th)
                        return false
                    end
                    return true
                end
            end
        end
        -- 只要不是 nfds=0 的 select/pselect6，就清空计数
        state.loop.sleep_count = 0
        state.loop.sleep_detected = false
        state.loop.sleep_repeats = nil
    end

    local seq_len, repeats = detect_repeating_sequence(state.keys, CFG.loop_max_seq_len, CFG.loop_min_repeats)
    if not seq_len then
        reset_loop_state()
        return true
    end

    -- 仅把“短时间内高频重复”的序列视为死循环：如果跨度太大，多半是正常周期性轮询（例如 netlink 周期查询）。
    do
        local need = seq_len * repeats
        if need > 0 and #state.ctxs >= need then
            local first = state.ctxs[#state.ctxs - need + 1]
            local last = state.ctxs[#state.ctxs]
            if first and last and first.ts_sec ~= nil and last.ts_sec ~= nil then
                local t1 = (tonumber(first.ts_sec) or 0) * 1000 + (tonumber(first.ts_nsec) or 0) / 1e6
                local t2 = (tonumber(last.ts_sec) or 0) * 1000 + (tonumber(last.ts_nsec) or 0) / 1e6
                local span = t2 - t1
                if span > (CFG.loop_max_span_ms or 500) then
                    reset_loop_state()
                    return true
                end
            end
        end
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
    -- auto_ai=1：强制开启 AI 干预（并由 base/ai.lua 自动设置 auto_continue，不再询问 YES）
    if auto_ai_enabled() then
        return true
    end

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

local function reexec_on_exit_fix_enabled()
    -- 是否在 exit/exit_group + “AI 已应用修复规则”后，触发 re-exec 重新跑一遍。
    --
    -- 背景：
    -- - linux-user 模式下，exit/exit_group 会导致整个 QEMU 进程退出；
    -- - 但 AI 往往在“即将退出”的失败路径上补规则（如补文件/改返回值），需要重跑一次才能验证修复是否生效；
    -- - 因此这里默认开启（可通过 SFEMU_AI_REEXEC_ON_EXIT_FIX=0 关闭）。
    local v = rawget(_G, "SFEMU_AI_REEXEC_ON_EXIT_FIX")
    if v == nil then
        return true
    end
    return v == true or v == 1 or tostring(v) == "1" or tostring(v) == "true" or tostring(v) == "on"
end

local function ai_repair_on_error_enabled()
    -- 是否在“关键 syscall 返回错误”时触发 AI 干预并尝试在该 syscall 处完成重试（避免走到 exit）。
    --
    -- 说明：
    -- - 该模式用于“修复出错的 syscall 并在同一 syscall 点重试”，而不是等到 exit 才介入；
    -- - 默认开启（只对少量关键 syscall 生效），可通过 SFEMU_AI_REPAIR_ON_ERROR=0 关闭。
    local v = rawget(_G, "SFEMU_AI_REPAIR_ON_ERROR")
    if v == nil then
        return true
    end
    return v == true or v == 1 or tostring(v) == "1" or tostring(v) == "true" or tostring(v) == "on"
end

local ai_repair_syscalls_checked = false
local ai_repair_syscalls = nil

local function parse_csv_set(s)
    local out = {}
    if type(s) ~= "string" then
        return out
    end
    for part in s:gmatch("[^,]+") do
        local k = tostring(part):gsub("^%s+", ""):gsub("%s+$", "")
        if k ~= "" then
            out[k] = true
        end
    end
    return out
end

local function get_ai_repair_syscalls()
    if ai_repair_syscalls_checked then
        return ai_repair_syscalls
    end
    ai_repair_syscalls_checked = true

    -- 默认仅覆盖“高频根因”且相对安全的 syscall
    local s = rawget(_G, "SFEMU_AI_REPAIR_SYSCALLS")
    if type(s) ~= "string" or s == "" then
        s = "open,openat,access,ioctl"
    end
    ai_repair_syscalls = parse_csv_set(s)
    return ai_repair_syscalls
end

local ai_repair_errnos_checked = false
local ai_repair_errnos = nil

local function get_ai_repair_errnos()
    if ai_repair_errnos_checked then
        return ai_repair_errnos
    end
    ai_repair_errnos_checked = true

    -- 默认覆盖：
    -- EPERM(1) / ENOENT(2) / EACCES(13) / ENODEV(19) / EINVAL(22) / ENOTTY(25)
    local s = rawget(_G, "SFEMU_AI_REPAIR_ERRNOS")
    if type(s) ~= "string" or s == "" then
        s = "1,2,13,19,22,25"
    end
    local set = {}
    for part in tostring(s):gmatch("[^,]+") do
        local n = tonumber((tostring(part):gsub("^%s+", ""):gsub("%s+$", "")))
        if n and n >= 0 then
            set[n] = true
        end
    end
    ai_repair_errnos = set
    return ai_repair_errnos
end

local function should_ai_repair_ret(ret)
    if type(ret) ~= "number" or ret >= 0 then
        return false, nil
    end
    local eno = -ret
    local allow = get_ai_repair_errnos()
    return allow[eno] == true, eno
end

local function maybe_ai_repair_and_retry(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if not ai_repair_on_error_enabled() then
        return nil
    end
    if type(syscall_name) ~= "string" or syscall_name == "" then
        return nil
    end
    local wl = get_ai_repair_syscalls()
    if not wl[syscall_name] then
        return nil
    end
    if type(c_do_syscall) ~= "function" then
        log("启用 AI_REPAIR_ON_ERROR 但未找到 c_do_syscall，跳过")
        return nil
    end

    -- 1) 先执行一次真实 syscall，获取错误码（这是“读取之前上下文并修复出错 syscall”的关键证据）
    local ret0 = c_do_syscall(num, arg1 or 0, arg2 or 0, arg3 or 0, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    local ctx = _G._sfemu_syscall_ctx
    if type(ctx) == "table" then
        ctx.ret = ret0
        ctx.intercepted = true
    end

    if type(ret0) ~= "number" then
        ret0 = 0
    end
    if ret0 >= 0 then
        -- syscall 成功：直接返回该结果（避免 C 侧再执行一次）
        return true, ret0
    end

    local ok_eno, eno = should_ai_repair_ret(ret0)
    if not ok_eno then
        return true, ret0
    end

    -- 2) syscall 失败：触发 AI（在“出错 syscall 点”介入，而不是等到 exit）
    local ai_on = need_ai(ctx)
    log("syscall_error 触发：name=%s ret=%s errno=%s need_ai=%s", tostring(syscall_name), tostring(ret0), tostring(eno), tostring(ai_on))
    if not ai_on then
        return true, ret0
    end

    local res = ai_handle(ctx, {
        reason = "syscall_error",
        errno = eno,
        last_ret = ret0,
    })

    local applied_fix = (type(res) == "table" and type(res.applied_fix_syscalls) == "table") and #res.applied_fix_syscalls or 0
    if not (type(res) == "table" and res.auto_continue == true and applied_fix > 0) then
        return true, ret0
    end

    -- 3) AI 已应用修复：优先“走规则拦截”重试（因为很多修复是 syscall_override/<name>.lua）
    invalidate_handler(syscall_name)
    local env = load_handler_env(syscall_name)
    if env and type(env.do_syscall) == "function" then
        local ok2, action2, ret2 = pcall(env.do_syscall, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
        if ok2 then
            local need_change2 = (action2 == true) or (action2 == 1)
            if need_change2 and type(ret2) == "number" then
                if type(ctx) == "table" then
                    ctx.ret = ret2
                end
                log("syscall_error：规则拦截生效，重试成功：%s ret=%s", tostring(syscall_name), tostring(ret2))
                return true, ret2
            end
        else
            log("syscall_error：重试阶段 env.do_syscall 异常：%s", tostring(action2))
        end
    end

    -- 4) 若规则未拦截，则再次执行真实 syscall（适用于“补文件/补目录/补设备节点”等环境修复）
    local ret1 = c_do_syscall(num, arg1 or 0, arg2 or 0, arg3 or 0, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if type(ctx) == "table" then
        ctx.ret = ret1
    end
    log("syscall_error：重试真实 syscall：%s ret=%s (原 ret=%s)", tostring(syscall_name), tostring(ret1), tostring(ret0))
    return true, ret1
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

    if type(c_watchdog_suspend) == "function" then
        pcall(c_watchdog_suspend, true)
    end
    local ok, res = pcall(ai.handle, ctx, state, meta)
    if type(c_watchdog_suspend) == "function" then
        pcall(c_watchdog_suspend, false)
    end
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
    if type(res) == "table" and type(res.applied_fix_syscalls) == "table" then
        for _, name in ipairs(res.applied_fix_syscalls) do
            invalidate_handler(name)
        end
    end

    return res or { auto_continue = false }
end

local function manual_handle(ctx)
    if auto_ai_enabled() then
        log("auto_ai=1：跳过人工确认（不再等待 YES）")
        reset_loop_state()
        return
    end
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

-- idle(pc, idle_ms, pc_seq_len, pc_repeats)
-- 由 C 侧 idle watchdog 触发：当长时间没有 syscall 时，采样 PC 序列检测到重复模式，
-- 认为“疑似用户态死循环”，进入与 deadloop 类似的 AI/人工干预路径。
function idle(pc, idle_ms, pc_seq_len, pc_repeats)
    state.idle_seq = (state.idle_seq or 0) + 1

    local sec, nsec = nil, nil
    if type(c_get_timestamp) == "function" then
        sec, nsec = c_get_timestamp()
    end

    local ctx = {
        -- 避免与 syscall seq 冲突：基于 syscall seq 叠加一个 idle 子序号
        seq = (tonumber(state.seq) or 0) * 100000 + (tonumber(state.idle_seq) or 0),
        name = "idle",
        num = -1,
        args = { pc, idle_ms, pc_seq_len, pc_repeats },
        ts_sec = sec,
        ts_nsec = nsec,
        backtrace = get_backtrace(),
        hooked = true,
    }

    log("长时间无 syscall：pc=0x%x idle_ms=%s pc_seq_len=%s repeats=%s",
        tonumber(pc) or 0,
        tostring(idle_ms),
        tostring(pc_seq_len),
        tostring(pc_repeats))

    pause_and_wait_handle(ctx)

    local res = nil
    local ai_on = need_ai(ctx)
    log("idle deadloop 触发：need_ai=%s", tostring(ai_on))
    if ai_on then
        res = ai_handle(ctx, {
            reason = "idle_deadloop",
            pc = pc,
            idle_ms = idle_ms,
            pc_seq_len = pc_seq_len,
            pc_repeats = pc_repeats,
        })
    end

    if not (type(res) == "table" and res.auto_continue == true) then
        manual_handle(ctx)
    end
end

function entry(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 清理上一条 syscall 的上下文，避免 finish.lua 误用旧数据
    _G._sfemu_syscall_ctx = nil

    local generated_unknown = false
    if type(syscall_name) ~= "string" or syscall_name == "" then
        local mapped = nil
        if type(num) == "number" then
            mapped = SYSCALL_NUM_TO_NAME[num]
        end
        if type(mapped) == "string" and mapped ~= "" then
            syscall_name = mapped
        else
            -- 默认：未映射 syscall 直接跳过（性能更好，避免刷屏）。
            -- 但在排障/批量实验中，常见“进程卡住但日志不再前进”的情况其实是进入了未映射 syscall（例如 futex/epoll/nanosleep 等）。
            -- 此时可设置：SFEMU_LOG_UNKNOWN_SYSCALLS=1，让 entry/finish 也记录这些 syscall（使用 sys_<num> 作为展示名）。
            if not str_bool(rawget(_G, "SFEMU_LOG_UNKNOWN_SYSCALLS"), false) then
                return false, 0
            end
            syscall_name = string.format("sys_%d", tonumber(num) or 0)
            generated_unknown = true
        end
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

        -- 关键：若 AI 已应用修复规则且允许自动继续，则触发 re-exec 重新运行目标程序，
        -- 否则本次 exit/exit_group 会直接把 QEMU 进程带走，无法完成“重试验证”。
        local applied_fix = (type(res) == "table" and type(res.applied_fix_syscalls) == "table") and #res.applied_fix_syscalls or 0
        local applied_actions = (type(res) == "table" and tonumber(res.applied_actions_count)) or 0
        local need_reexec = (applied_fix > 0) or (applied_actions > 0)
        if need_reexec and type(res) == "table" and res.auto_continue == true and reexec_on_exit_fix_enabled() then
            if type(c_request_reexec) == "function" then
                log("exit：AI 已应用修复（规则=%d 动作=%d），触发 re-exec 重新加载镜像并重试验证", applied_fix, applied_actions)
                pcall(c_request_reexec, tostring(res.run_id or ""))
                -- 不拦截 exit：让 C 侧看到“需要 re-exec”后立刻 execv 重新跑；拦截 exit 会导致 guest 走到不可预期分支/反复 exit。
                return false, 0
            else
                log("exit：需要 re-exec，但未找到 c_request_reexec（请更新/重编译 QEMU）")
            end
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
            local reason = (state.loop.sleep_detected == true) and "sleep_loop" or "deadloop"
            log("%s 触发：need_ai=%s", tostring(reason), tostring(ai_on))
            if ai_on then
                res = ai_handle(_G._sfemu_syscall_ctx, {
                    reason = reason,
                    loop_seq_len = state.loop.seq_len,
                    loop_repeats = state.loop.repeats,
                    loop_report_path = state.loop.last_report_path,
                    loop_names = loop_names,
                    sleep_repeats = state.loop.sleep_repeats,
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

    -- 对未映射 syscall：仅做观测与死循环检测，不做规则加载/AI 修复（避免大量 I/O 与误伤）。
    if generated_unknown then
        return false, 0
    end

    local env = load_handler_env(syscall_name)
    if not env then
        -- 当没有对应规则脚本时，允许在“关键 syscall 失败”处触发 AI 并在该 syscall 点完成重试
        local handled, r = maybe_ai_repair_and_retry(syscall_name, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
        if handled ~= nil then
            return handled, r or 0
        end
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
