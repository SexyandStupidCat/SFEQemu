-- ai.lua - 退出/死循环触发的 AI 干预基框架（M1~M3 可用）
--
-- 设计目标（对齐 plan.md）：
-- 1) 失败触发时采集上下文快照（寄存器/调用栈/伪代码/近期 syscall 序列）
-- 2) 生成最小可解释的诊断报告（启发式），并补采关键内存证据
-- 3) 生成可回滚的 rules_patch（默认不覆盖现有规则；可按配置自动应用“新规则文件”）
--
-- 注意：
-- - 本模块不依赖网络，不内置真实 LLM；如需更强分析，可通过 SFEMU_AI_CMD 接入外部工具。
-- - 本模块不硬编码具体 syscall 的“修复策略”；修复规则由外部工具生成并输出到 rules_patch/fix/syscall/。
-- - “快照方式采用 CRIU”在本仓库内仅作为未来扩展点；当前实现为“轻量上下文快照”。

local M = {}

-- ----------------------------
-- 工具函数：日志/路径/文件
-- ----------------------------

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[ai] " .. fmt, ...))
    else
        c_log("[ai] " .. tostring(fmt))
    end
end

local function sh_quote(s)
    -- 单引号安全转义：' -> '"'"'
    return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end

local function mkdir_p(path, mode)
    if not path or path == "" then
        return false, -1
    end
    if type(c_mkdir_p) == "function" then
        -- Lua 没有八进制字面量：0755(八进制) == 493(十进制)
        local ok, rc = c_mkdir_p(path, mode or 493)
        if ok then
            return true, 0
        end
        return false, rc
    end

    -- 兼容：无 c_mkdir_p 时退化到 shell
    local ok, _, code = os.execute("mkdir -p -- " .. sh_quote(path))
    if ok == true or ok == 0 or code == 0 then
        return true, 0
    end
    return false, -1
end

local function write_file(path, data)
    local f, err = io.open(path, "wb")
    if not f then
        return false, err
    end
    f:write(data or "")
    f:close()
    return true
end

local function append_file(path, data)
    local f, err = io.open(path, "ab")
    if not f then
        return false, err
    end
    f:write(data or "")
    f:close()
    return true
end

local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end
    local data = f:read("*a")
    f:close()
    return data or ""
end

local function copy_file(src, dst)
    local data, err = read_file(src)
    if not data then
        return false, err
    end
    return write_file(dst, data)
end

local function to_hex(s, max_len)
    if type(s) ~= "string" then
        return ""
    end
    local n = #s
    if max_len and max_len > 0 and n > max_len then
        n = max_len
    end
    local out = {}
    for i = 1, n do
        out[#out + 1] = string.format("%02x", s:byte(i))
    end
    local hex = table.concat(out)
    if max_len and max_len > 0 and #s > max_len then
        hex = hex .. string.format("...(trunc %d/%d)", max_len, #s)
    end
    return hex
end

local function fnv1a32(s)
    local hash = 0x811c9dc5
    for i = 1, #s do
        hash = hash ~ s:byte(i)
        hash = (hash * 0x01000193) & 0xffffffff
    end
    return hash
end

local function now_run_id(seq)
    local ts = os.date("%Y%m%d_%H%M%S")
    local n = tonumber(seq) or 0
    return string.format("%s_%08d", ts, n)
end

local function str_bool(v, default)
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

local function clamp_int(v, lo, hi, default)
    local n = tonumber(v)
    if not n then
        return default
    end
    n = math.floor(n)
    if n < lo then
        return lo
    end
    if n > hi then
        return hi
    end
    return n
end

-- ----------------------------
-- JSON（最小实现，满足 snapshot.json）
-- ----------------------------

local function json_escape(s)
    -- 重要：Lua 字符串是“字节序列”，可能包含非 UTF-8 字节（例如从 guest 内存读到的“伪字符串”）。
    -- JSON 规范要求文本必须是 UTF-8；如果把原始高位字节直接写进 snapshot.json，Python 侧按 UTF-8 读取会直接炸。
    --
    -- 因此这里做“字节级”转义：
    -- - 控制字符、DEL(0x7f)、所有非 ASCII(>=0x80) 字节，统一输出为 \\u00XX
    -- - 常见转义（\\ \" \n \r \t \b \f）保持可读
    s = tostring(s or "")
    local out = {}
    for i = 1, #s do
        local b = s:byte(i)
        if b == 0x5c then         -- \
            out[#out + 1] = "\\\\"
        elseif b == 0x22 then     -- "
            out[#out + 1] = "\\\""
        elseif b == 0x08 then     -- \b
            out[#out + 1] = "\\b"
        elseif b == 0x0c then     -- \f
            out[#out + 1] = "\\f"
        elseif b == 0x0a then     -- \n
            out[#out + 1] = "\\n"
        elseif b == 0x0d then     -- \r
            out[#out + 1] = "\\r"
        elseif b == 0x09 then     -- \t
            out[#out + 1] = "\\t"
        elseif b < 0x20 or b == 0x7f or b >= 0x80 then
            out[#out + 1] = string.format("\\u%04x", b)
        else
            out[#out + 1] = string.char(b)
        end
    end
    return table.concat(out)
end

local function is_array(t)
    local max = 0
    local n = 0
    for k, _ in pairs(t) do
        if type(k) ~= "number" or k <= 0 or k % 1 ~= 0 then
            return false, 0
        end
        if k > max then
            max = k
        end
        n = n + 1
    end
    if n == 0 then
        return true, 0
    end
    for i = 1, max do
        if t[i] == nil then
            return false, 0
        end
    end
    return true, max
end

local function json_encode(v, depth, max_depth)
    depth = depth or 0
    max_depth = max_depth or 8
    if depth > max_depth then
        return "\"(max_depth)\""
    end

    local tv = type(v)
    if tv == "nil" then
        return "null"
    elseif tv == "boolean" then
        return v and "true" or "false"
    elseif tv == "number" then
        if v ~= v or v == math.huge or v == -math.huge then
            return "null"
        end
        return tostring(v)
    elseif tv == "string" then
        return "\"" .. json_escape(v) .. "\""
    elseif tv == "table" then
        local arr, n = is_array(v)
        if arr then
            local out = {}
            for i = 1, n do
                out[#out + 1] = json_encode(v[i], depth + 1, max_depth)
            end
            return "[" .. table.concat(out, ",") .. "]"
        end
        local out = {}
        for k, val in pairs(v) do
            out[#out + 1] = "\"" .. json_escape(k) .. "\":" .. json_encode(val, depth + 1, max_depth)
        end
        return "{" .. table.concat(out, ",") .. "}"
    else
        return "\"" .. json_escape(tostring(v)) .. "\""
    end
end

-- ----------------------------
-- 快照采集：寄存器/调用栈/伪代码/内存
-- ----------------------------

local function collect_regs()
    if type(c_list_regs) ~= "function" or type(c_get_reg) ~= "function" then
        return {}, "c_list_regs/c_get_reg 不可用"
    end
    local out = {}
    local list = c_list_regs()
    if type(list) ~= "table" then
        return {}, "c_list_regs 返回非 table"
    end
    for _, desc in ipairs(list) do
        local val, size, rc = c_get_reg(desc.num)
        local item = {
            num = desc.num,
            name = desc.name,
            feature = desc.feature,
            size = size,
            rc = rc,
        }
        if rc == 0 then
            if type(val) == "string" then
                item.value = "hex:" .. to_hex(val, 64)
            else
                item.value = val
            end
        end
        out[#out + 1] = item
    end
    return out, nil
end

local function regs_to_text(regs)
    local lines = {}
    for _, r in ipairs(regs or {}) do
        lines[#lines + 1] = string.format("%s(%d) size=%s rc=%s value=%s",
            tostring(r.name or ""),
            tonumber(r.num) or -1,
            tostring(r.size),
            tostring(r.rc),
            tostring(r.value))
    end
    return table.concat(lines, "\n") .. "\n"
end

local function collect_backtrace()
    if type(c_get_shadowstack) ~= "function" then
        return {}, "c_get_shadowstack 不可用（可能未启用 -shadowstack）"
    end
    local bt = c_get_shadowstack()
    if type(bt) ~= "table" then
        return {}, "c_get_shadowstack 返回非 table"
    end
    return bt, nil
end

local function resolve_frames(bt, max_frames, max_pseudocode_bytes)
    local frames = {}
    if type(c_resolve_addr) ~= "function" then
        return frames, "c_resolve_addr 不可用（可能未启用 --sfanalysis）"
    end
    local n = math.min(#bt, max_frames)
    for i = 1, n do
        local addr = bt[i]
        local info, rc = c_resolve_addr(addr, max_pseudocode_bytes)
        local f = {
            idx = i,
            addr = addr,
            addr_hex = string.format("0x%x", addr),
            rc = rc,
        }
        if rc == 0 and type(info) == "table" then
            f.module_name = info.module_name
            f.module_real_path = info.module_real_path
            f.func_name = info.func_name
            f.prototype = info.prototype
            f.pseudocode = info.pseudocode
            f.pseudocode_truncated = info.pseudocode_truncated
            f.pseudocode_file = info.pseudocode_file
        end
        frames[#frames + 1] = f
    end
    return frames, nil
end

local function frames_to_text(frames)
    local lines = {}
    for _, f in ipairs(frames or {}) do
        local head = string.format("#%02d %s", tonumber(f.idx) or 0, tostring(f.addr_hex))
        local name = ""
        if f.module_name or f.func_name then
            name = string.format("  %s :: %s", tostring(f.module_name or "(unknown)"), tostring(f.func_name or "(unknown)"))
        end
        lines[#lines + 1] = head .. name
    end
    return table.concat(lines, "\n") .. "\n"
end

local function capture_memory_blob(guest_addr, nbytes, out_path)
    if type(c_read_guest_bytes) ~= "function" and type(c_read_bytes) ~= "function" then
        return nil, "c_read_guest_bytes/c_read_bytes 不可用"
    end
    local reader = c_read_guest_bytes or c_read_bytes
    local blob, rc = reader(guest_addr, nbytes)
    if rc ~= 0 then
        return nil, string.format("read rc=%s", tostring(rc))
    end
    local ok, err = write_file(out_path, blob)
    if not ok then
        return nil, tostring(err)
    end
    return {
        addr = guest_addr,
        addr_hex = string.format("0x%x", guest_addr),
        size = nbytes,
        file = out_path,
        fnv1a32 = string.format("0x%08x", fnv1a32(blob)),
    }, nil
end

local function try_read_string(guest_addr, max_len)
    if type(c_read_string) ~= "function" then
        return nil, "c_read_string 不可用"
    end
    local s, rc = c_read_string(guest_addr, max_len or 256)
    if rc ~= 0 then
        return nil, string.format("read rc=%s", tostring(rc))
    end
    if not s or s == "" then
        return nil, "empty"
    end
    return s, nil
end

local function guess_pointer(v)
    if type(v) ~= "number" then
        return false
    end
    if v == 0 then
        return false
    end
    -- 过小值多为常量/flags，默认不当作指针
    if v < 4096 then
        return false
    end
    return true
end

local function collect_memory_evidence(ctx, regs, mem_dir, cfg, prefix)
    local evidence = {}
    local max_items = cfg.mem_max_items
    local nbytes = cfg.mem_dump_bytes

    local function add_item(item)
        evidence[#evidence + 1] = item
    end

    local function capture_ptr(tag, ptr)
        if #evidence >= max_items then
            return
        end
        if not guess_pointer(ptr) then
            return
        end

        local name = tag
        if type(prefix) == "string" and prefix ~= "" then
            name = prefix .. "_" .. tag
        end

        local item = {
            tag = name,
            source = prefix,
            addr = ptr,
            addr_hex = string.format("0x%x", ptr),
        }

        local s, serr = try_read_string(ptr, 256)
        if s then
            local spath = string.format("%s/%s_str.txt", mem_dir, name)
            write_file(spath, s .. "\n")
            item.string = s
            item.string_file = spath
        else
            item.string_err = serr
        end

        local bpath = string.format("%s/%s.bin", mem_dir, name)
        local blob_meta, berr = capture_memory_blob(ptr, nbytes, bpath)
        if blob_meta then
            item.blob = blob_meta
        else
            item.blob_err = berr
        end

        add_item(item)
    end

    -- syscall 参数中的指针候选
    local args = (type(ctx) == "table" and type(ctx.args) == "table") and ctx.args or {}
    for i = 1, math.min(#args, 8) do
        capture_ptr(string.format("arg%d_%s", i, string.format("0x%x", args[i] or 0)), args[i])
        if #evidence >= max_items then
            break
        end
    end

    -- 栈顶/关键寄存器指针（优先 sp/rsp）
    if #evidence < max_items and type(regs) == "table" then
        local sp_val = nil
        for _, r in ipairs(regs) do
            local name = tostring(r.name or ""):lower()
            if name == "sp" or name == "rsp" or name == "esp" then
                if type(r.value) == "number" then
                    sp_val = r.value
                end
                break
            end
        end
        if sp_val then
            capture_ptr(string.format("reg_sp_%s", string.format("0x%x", sp_val)), sp_val)
        end
    end

    return evidence
end

-- ----------------------------
-- 诊断与规则生成（启发式/模板）
-- ----------------------------

local function summarize_recent_syscalls(ctxs, max_n)
    local out = {}
    if type(ctxs) ~= "table" then
        return out
    end
    local n = #ctxs
    local start = math.max(1, n - max_n + 1)
    for i = start, n do
        local c = ctxs[i]
        if type(c) == "table" then
            out[#out + 1] = {
                seq = c.seq,
                name = c.name,
                num = c.num,
                args = c.args,
                ret = c.ret,
                intercepted = c.intercepted,
            }
        end
    end
    return out
end

local function pick_last_error_syscall(ctxs)
    if type(ctxs) ~= "table" then
        return nil
    end
    for i = #ctxs, 1, -1 do
        local c = ctxs[i]
        if type(c) == "table" and type(c.ret) == "number" and c.ret < 0 then
            return c
        end
    end
    return nil
end

local function generate_log_rule(syscall_name, run_id, ctx)
    local header = {}
    header[#header + 1] = "-- 自动生成规则（AI 观测型）"
    header[#header + 1] = "-- run_id: " .. tostring(run_id)
    header[#header + 1] = "-- syscall: " .. tostring(syscall_name)
    header[#header + 1] = "-- 说明：默认不拦截，仅在“疑似同一上下文”时打印日志；可在此基础上逐步加入修复逻辑。"
    header[#header + 1] = ""

    local sig_args = {}
    if type(ctx) == "table" and type(ctx.args) == "table" then
        for i = 1, math.min(#ctx.args, 4) do
            sig_args[i] = ctx.args[i]
        end
    end

    header[#header + 1] = "local SIG = {"
    header[#header + 1] = string.format("    num = %d,", tonumber(ctx.num) or 0)
    header[#header + 1] = string.format("    args = { %s },", table.concat(sig_args, ", "))
    header[#header + 1] = "}"
    header[#header + 1] = ""
    header[#header + 1] = "local function match(num, arg1, arg2, arg3, arg4)"
    header[#header + 1] = "    if num ~= SIG.num then"
    header[#header + 1] = "        return false"
    header[#header + 1] = "    end"
    header[#header + 1] = "    local a = SIG.args"
    header[#header + 1] = "    if #a >= 1 and arg1 ~= a[1] then return false end"
    header[#header + 1] = "    if #a >= 2 and arg2 ~= a[2] then return false end"
    header[#header + 1] = "    if #a >= 3 and arg3 ~= a[3] then return false end"
    header[#header + 1] = "    if #a >= 4 and arg4 ~= a[4] then return false end"
    header[#header + 1] = "    return true"
    header[#header + 1] = "end"
    header[#header + 1] = ""
    header[#header + 1] = "function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)"
    header[#header + 1] = "    if type(c_log) == \"function\" and match(num, arg1, arg2, arg3, arg4) then"
    header[#header + 1] = string.format("        c_log(string.format(\"[ai-rule:%s] hit %s num=%%d arg1=0x%%x arg2=0x%%x\", num, arg1 or 0, arg2 or 0))",
        tostring(run_id), tostring(syscall_name))
    header[#header + 1] = "    end"
    header[#header + 1] = "    return 0, 0"
    header[#header + 1] = "end"
    header[#header + 1] = ""

    return table.concat(header, "\n")
end

-- ----------------------------
-- 对外入口：AI 干预（被 entry.lua 调用）
-- ----------------------------

if not _G._sfemu_ai_state then
    _G._sfemu_ai_state = {
        runs = 0,
        verify = nil,      -- {active, run_id, start_seq, verify_syscalls, stable_root, ...}
        last_stable = nil, -- 最近一次导出的稳定规则信息
    }
end
local S = _G._sfemu_ai_state

function M.handle(ctx, entry_state, meta)
    meta = meta or {}

    local cfg = {
        enable = str_bool(rawget(_G, "SFEMU_AI_ENABLE"), true),
        max_runs = clamp_int(rawget(_G, "SFEMU_AI_MAX_RUNS"), 0, 10000, 100),
        recent_syscalls = clamp_int(rawget(_G, "SFEMU_AI_RECENT_SYSCALLS"), 1, 4096, 64),
        frames = clamp_int(rawget(_G, "SFEMU_AI_FRAMES"), 0, 256, 16),
        pseudocode_bytes = clamp_int(rawget(_G, "SFEMU_AI_PSEUDOCODE_BYTES"), 0, 1 << 20, 4096),
        mem_dump_bytes = clamp_int(rawget(_G, "SFEMU_AI_MEM_BYTES"), 0, 1 << 20, 256),
        mem_max_items = clamp_int(rawget(_G, "SFEMU_AI_MEM_MAX"), 0, 4096, 16),
        -- 默认启用：仅“创建新规则文件”，不覆盖已有规则；且默认仅应用“修复型”规则
        apply_rules = str_bool(rawget(_G, "SFEMU_AI_APPLY_RULES"), true),
        apply_observe = str_bool(rawget(_G, "SFEMU_AI_APPLY_OBSERVE"), false),
        overwrite_rules = str_bool(rawget(_G, "SFEMU_AI_OVERWRITE_RULES"), false),
        auto_continue = str_bool(rawget(_G, "SFEMU_AI_AUTO_CONTINUE"), false),
        verify_syscalls = clamp_int(rawget(_G, "SFEMU_AI_VERIFY_SYSCALLS"), 0, 100000000, 2048),
        stable_root = rawget(_G, "SFEMU_AI_STABLE_ROOT"),
        export_observe = str_bool(rawget(_G, "SFEMU_AI_EXPORT_OBSERVE"), false),
        disable_after_stable = str_bool(rawget(_G, "SFEMU_AI_DISABLE_AFTER_STABLE"), true),
        ai_cmd = rawget(_G, "SFEMU_AI_CMD"),
    }

    if not cfg.enable then
        return { auto_continue = false }
    end
    if cfg.max_runs == 0 then
        return { auto_continue = false }
    end
    if (S.runs or 0) >= cfg.max_runs then
        log("已达到 AI 干预上限：%d/%d，跳过", tonumber(S.runs) or 0, tonumber(cfg.max_runs) or 0)
        return { auto_continue = false }
    end

    -- 推导 rules 根目录（基于本文件位置）
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    local rules_dir = script_dir:gsub("base/?$", "")
    local data_root = rules_dir .. "data"
    local run_id = now_run_id((type(ctx) == "table" and ctx.seq) or 0)

    local stable_root = cfg.stable_root
    if type(stable_root) ~= "string" or stable_root == "" then
        stable_root = data_root .. "/stable_rules"
    end

    local run_dir = string.format("%s/ai_runs/%s", data_root, run_id)
    local pseudo_dir = run_dir .. "/pseudocode"
    local mem_dir = run_dir .. "/memory"
    local patch_dir = run_dir .. "/rules_patch"
    local patch_fix_syscall_dir = patch_dir .. "/fix/syscall"
    local patch_observe_syscall_dir = patch_dir .. "/observe/syscall"
    -- 兼容旧接口：外部工具仍可把规则输出到 rules_patch/syscall/
    local patch_legacy_syscall_dir = patch_dir .. "/syscall"

    local ok = true
    ok = ok and select(1, mkdir_p(data_root, 493))
    ok = ok and select(1, mkdir_p(stable_root, 493))
    ok = ok and select(1, mkdir_p(run_dir, 493))
    ok = ok and select(1, mkdir_p(pseudo_dir, 493))
    ok = ok and select(1, mkdir_p(mem_dir, 493))
    ok = ok and select(1, mkdir_p(patch_fix_syscall_dir, 493))
    ok = ok and select(1, mkdir_p(patch_observe_syscall_dir, 493))
    ok = ok and select(1, mkdir_p(patch_legacy_syscall_dir, 493))

    if not ok then
        log("创建 ai_runs 目录失败，可能无法落盘：%s", tostring(run_dir))
    end

    S.runs = (S.runs or 0) + 1

    local retry_log_path = run_dir .. "/retry.log"
    append_file(retry_log_path, string.format("run_id=%s reason=%s\n", tostring(run_id), tostring(meta.reason or "")))

    -- A) 快照：寄存器/调用栈/伪代码/近期 syscall
    local regs, regs_err = collect_regs()
    local bt, bt_err = collect_backtrace()
    local frames, frames_err = resolve_frames(bt, cfg.frames, cfg.pseudocode_bytes)

    local regs_path = run_dir .. "/regs.txt"
    write_file(regs_path, regs_to_text(regs))

    local bt_path = run_dir .. "/backtrace.txt"
    write_file(bt_path, frames_to_text(frames))

    local pseudocode_index = {}
    for _, f in ipairs(frames) do
        if f.pseudocode and f.pseudocode ~= "" then
            local p = string.format("%s/frame%02d_%s.txt", pseudo_dir, tonumber(f.idx) or 0, tostring(f.addr_hex or "0x0"))
            write_file(p, tostring(f.pseudocode))
            pseudocode_index[#pseudocode_index + 1] = { frame = f.idx, addr_hex = f.addr_hex, file = p, truncated = f.pseudocode_truncated }
            -- 避免 snapshot.json 过大：只在 JSON 中保留路径，不保留伪代码正文
            f.pseudocode_path = p
            f.pseudocode = nil
        end
    end

    local recent = summarize_recent_syscalls(entry_state and entry_state.ctxs, cfg.recent_syscalls)
    local last_err = pick_last_error_syscall(entry_state and entry_state.ctxs)

    -- C) 补采内存证据（指针/字符串/栈顶）
    local mem_evidence = {}
    local function merge_evidence(list)
        if type(list) ~= "table" then
            return
        end
        for _, it in ipairs(list) do
            mem_evidence[#mem_evidence + 1] = it
        end
    end
    -- exit 场景下，触发点本身通常没有指针参数，因此额外补采“最近一次错误 syscall”的指针内存，有助于定位根因
    merge_evidence(collect_memory_evidence(ctx or {}, regs, mem_dir, cfg, "trigger"))
    if type(last_err) == "table" then
        merge_evidence(collect_memory_evidence(last_err, regs, mem_dir, cfg, "last_err"))
    end

    -- B) 最小诊断（启发式）
    local diagnosis = {}
    diagnosis[#diagnosis + 1] = "# AI 诊断报告（启发式）"
    diagnosis[#diagnosis + 1] = ""
    diagnosis[#diagnosis + 1] = string.format("- run_id: `%s`", tostring(run_id))
    diagnosis[#diagnosis + 1] = string.format("- reason: `%s`", tostring(meta.reason or "unknown"))
    diagnosis[#diagnosis + 1] = string.format("- trigger syscall: `%s` (%s)", tostring(ctx and ctx.name), tostring(ctx and ctx.num))
    if type(ctx) == "table" and type(ctx.args) == "table" then
        diagnosis[#diagnosis + 1] = string.format("- trigger args: `%s`", table.concat((function()
            local out = {}
            for i = 1, #ctx.args do
                out[i] = tostring(ctx.args[i])
            end
            return out
        end)(), ", "))
    end
    if type(ctx) == "table" and type(ctx.ret) == "number" then
        diagnosis[#diagnosis + 1] = string.format("- last ret (if available): `%s`", tostring(ctx.ret))
    end
    if regs_err then
        diagnosis[#diagnosis + 1] = string.format("- regs note: %s", tostring(regs_err))
    end
    if bt_err then
        diagnosis[#diagnosis + 1] = string.format("- backtrace note: %s", tostring(bt_err))
    end
    if frames_err then
        diagnosis[#diagnosis + 1] = string.format("- pseudocode note: %s", tostring(frames_err))
    end
    if meta.loop_seq_len and meta.loop_repeats then
        diagnosis[#diagnosis + 1] = string.format("- deadloop: seq_len=%s repeats=%s", tostring(meta.loop_seq_len), tostring(meta.loop_repeats))
    end
    if meta.loop_report_path then
        diagnosis[#diagnosis + 1] = string.format("- deadloop report: `%s`", tostring(meta.loop_report_path))
    end
    diagnosis[#diagnosis + 1] = ""

    if last_err then
        diagnosis[#diagnosis + 1] = "## 最近一次错误 syscall（启发式）"
        diagnosis[#diagnosis + 1] = string.format("- seq=%s syscall=%s(%s) ret=%s",
            tostring(last_err.seq), tostring(last_err.name), tostring(last_err.num), tostring(last_err.ret))
        diagnosis[#diagnosis + 1] = ""
        diagnosis[#diagnosis + 1] = "建议：优先围绕该 syscall 生成更精确的 hook（先观测，再逐步收敛到修复规则），并尽量限定到“参数+调用栈特征”。"
        diagnosis[#diagnosis + 1] = ""
    end

    diagnosis[#diagnosis + 1] = "## 下一步（可选）"
    diagnosis[#diagnosis + 1] = "- 若要接入外部 AI：设置 `SFEMU_AI_CMD`，由外部工具读取 `snapshot.json` 并输出 `rules_patch/`。"
    diagnosis[#diagnosis + 1] = "- 若要自动应用 patch：设置 `SFEMU_AI_APPLY_RULES=1`（默认只生成，不覆盖现有规则）。"
    diagnosis[#diagnosis + 1] = ""

    local diagnosis_path = run_dir .. "/diagnosis.md"
    write_file(diagnosis_path, table.concat(diagnosis, "\n") .. "\n")

    -- snapshot.json（结构化索引）
    local snapshot = {
        run_id = run_id,
        reason = meta.reason,
        created_at = os.date("%Y-%m-%d %H:%M:%S"),
        rules_dir = rules_dir,
        trigger = {
            seq = ctx and ctx.seq,
            syscall_name = ctx and ctx.name,
            syscall_num = ctx and ctx.num,
            args = ctx and ctx.args,
            ts_sec = ctx and ctx.ts_sec,
            ts_nsec = ctx and ctx.ts_nsec,
            ret = ctx and ctx.ret,
            intercepted = ctx and ctx.intercepted,
        },
        outputs = {
            regs_txt = regs_path,
            backtrace_txt = bt_path,
            diagnosis_md = diagnosis_path,
            retry_log = retry_log_path,
        },
        regs = regs,
        backtrace = {
            raw = (function()
                local out = {}
                for i = 1, #bt do
                    out[i] = string.format("0x%x", bt[i])
                end
                return out
            end)(),
            frames = frames,
            pseudocode_index = pseudocode_index,
        },
        memory = mem_evidence,
        recent_syscalls = recent,
    }

    local snapshot_path = run_dir .. "/snapshot.json"
    write_file(snapshot_path, json_encode(snapshot, 0, 10) .. "\n")

    -- D) rules_patch：本模块只生成“观测型规则”骨架；不在框架中硬编码具体 syscall 的干预措施
    --
    -- 修复型规则应由外部工具生成（SFEMU_AI_CMD），推荐输出到：
    -- - rules_patch/fix/syscall/<name>.lua
    -- 观测型规则输出到：
    -- - rules_patch/observe/syscall/<name>.lua
    -- 兼容旧接口（视为 fix）：
    -- - rules_patch/syscall/<name>.lua
    local env_path = rawget(_G, "SFEMU_AI_ENV")
    if type(env_path) ~= "string" or env_path == "" then
        env_path = rules_dir .. "config/env"
    end

    -- 内置“类 MCP”：无需用户额外写脚本，直接用 OpenAI 兼容 API 生成规则文件
    -- 触发条件：SFEMU_AI_MCP_ENABLE=1 且未显式设置 SFEMU_AI_CMD
    do
        local mcp_on = str_bool(rawget(_G, "SFEMU_AI_MCP_ENABLE"), false)
        if mcp_on and (type(cfg.ai_cmd) ~= "string" or cfg.ai_cmd == "") then
            local py = rawget(_G, "SFEMU_AI_MCP_PY")
            if type(py) ~= "string" or py == "" then
                py = "python3"
            end
            local script = rawget(_G, "SFEMU_AI_MCP_SCRIPT")
            if type(script) ~= "string" or script == "" then
                script = rules_dir .. "tools/ai_mcp_openai.py"
            end
            cfg.ai_cmd = tostring(py) .. " " .. sh_quote(script)
            append_file(retry_log_path, string.format("mcp_enable=1 mcp_py=%s mcp_script=%s\n", tostring(py), tostring(script)))
        end
    end

    local want_syscalls = {}
    local function add_want(name)
        if type(name) ~= "string" or name == "" then
            return
        end
        want_syscalls[name] = true
    end

    add_want(ctx and ctx.name)
    if last_err and last_err.name then
        add_want(last_err.name)
    end

    -- 死循环时：把循环片段内的 syscall 都加入候选（更利于“观测->定位”）
    if meta.loop_names and type(meta.loop_names) == "table" then
        for _, n in ipairs(meta.loop_names) do
            add_want(n)
        end
    end

    -- 1) 最小观测规则：便于定位（默认不自动应用）
    for name, _ in pairs(want_syscalls) do
        local rule_path = string.format("%s/%s.lua", patch_observe_syscall_dir, name)
        local content = generate_log_rule(name, run_id, ctx or {})
        write_file(rule_path, content)
    end

    -- 2) 外部 AI 工具：读取 snapshot 并输出 rules_patch（不在本模块中硬编码任何 syscall 修复策略）
    if type(cfg.ai_cmd) == "string" and cfg.ai_cmd ~= "" then
        local cmd = string.format("%s %s %s %s",
            cfg.ai_cmd,
            sh_quote(snapshot_path),
            sh_quote(patch_dir),
            sh_quote(env_path))
        append_file(retry_log_path, string.format(
            "ai_cmd: %s\nsnapshot_path=%s\npatch_dir=%s\nenv_path=%s\n",
            tostring(cfg.ai_cmd),
            tostring(snapshot_path),
            tostring(patch_dir),
            tostring(env_path)))
        local r1, r2, r3 = os.execute(cmd)
        append_file(retry_log_path, string.format("ai_cmd_done: r1=%s r2=%s r3=%s\n", tostring(r1), tostring(r2), tostring(r3)))
    end

    local function list_lua_files(dir)
        local function popen_lines(cmd)
            local p = io.popen(cmd, "r")
            if not p then
                return nil
            end
            local out = {}
            for line in p:lines() do
                if line and line ~= "" then
                    out[#out + 1] = line
                end
            end
            p:close()
            table.sort(out)
            return out
        end

        if type(dir) ~= "string" or dir == "" then
            return {}
        end

        -- 重要：QEMU 常在 chroot(rootfs) 内运行，此时 /usr/bin/find 可能是 guest(ARM) 的二进制，
        -- host 无法直接执行，导致“目录列举为空”，进而无法应用 rules_patch。
        -- 因为我们已经为 AI MCP 注入了 host 侧 python3（x86_64），这里优先用 python3 做 glob 列举。
        do
            local py = rawget(_G, "SFEMU_AI_MCP_PY")
            if type(py) ~= "string" or py == "" then
                py = "python3"
            end
            local code = "import glob,os,sys; d=sys.argv[1]; print('\\n'.join(sorted(glob.glob(os.path.join(d, '*.lua')))))"
            local cmd = tostring(py) .. " -c " .. sh_quote(code) .. " " .. sh_quote(dir) .. " 2>/dev/null"
            local out = popen_lines(cmd)
            if out and #out > 0 then
                return out
            end
        end

        -- 兜底：非 chroot 场景下通常有 host 侧 find 可用
        do
            local cmd = "find " .. sh_quote(dir) .. " -maxdepth 1 -type f -name \"*.lua\" 2>/dev/null"
            local out = popen_lines(cmd)
            if out then
                return out
            end
        end

        return {}
    end

    local generated = {}
    local seen = {}
    local function add_from_dir(kind, dir)
        for _, path in ipairs(list_lua_files(dir)) do
            local name = path:match("/([^/]+)%.lua$")
            if name and name ~= "" then
                local key = tostring(kind) .. ":" .. tostring(name)
                if not seen[key] then
                    seen[key] = true
                    generated[#generated + 1] = { syscall = name, file = path, kind = kind }
                end
            end
        end
    end

    -- 优先使用 fix/syscall；legacy 仅在同名 fix 不存在时补充
    add_from_dir("fix", patch_fix_syscall_dir)
    add_from_dir("fix", patch_legacy_syscall_dir)
    add_from_dir("observe", patch_observe_syscall_dir)

    local function lua_pat_escape(s)
        return (tostring(s):gsub("([^%w])", "%%%1"))
    end
    local patch_dir_pat = lua_pat_escape(patch_dir)
    local function relpath(p)
        return tostring(p):gsub("^" .. patch_dir_pat .. "/?", "")
    end

    local patch_readme = {}
    patch_readme[#patch_readme + 1] = "# rules_patch"
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = string.format("- run_id: `%s`", tostring(run_id))
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = "## 目录结构"
    patch_readme[#patch_readme + 1] = "- fix/syscall/: 修复型规则（默认会自动应用，并参与 stable_rules 导出）"
    patch_readme[#patch_readme + 1] = "- observe/syscall/: 观测型规则（默认不自动应用，仅用于定位）"
    patch_readme[#patch_readme + 1] = "- syscall/: 兼容旧接口（视为 fix）"
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = "## 修复型规则（fix）"
    for _, g in ipairs(generated) do
        if g.kind == "fix" then
            patch_readme[#patch_readme + 1] = string.format("- %s", relpath(g.file))
        end
    end
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = "## 观测型规则（observe）"
    for _, g in ipairs(generated) do
        if g.kind ~= "fix" then
            patch_readme[#patch_readme + 1] = string.format("- %s", relpath(g.file))
        end
    end
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = "## 外部工具接口（SFEMU_AI_CMD）"
    patch_readme[#patch_readme + 1] = "- 调用：$SFEMU_AI_CMD <snapshot.json> <rules_patch_dir> <env_path>"
    patch_readme[#patch_readme + 1] = "- 说明：外部工具可读取 env_path 获取 OPENAI_* 等配置，并输出 fix/syscall 规则。"
    patch_readme[#patch_readme + 1] = ""
    patch_readme[#patch_readme + 1] = "## 应用方式（默认不自动覆盖现有规则）"
    patch_readme[#patch_readme + 1] = string.format("1) 将 fix/syscall 下的规则拷贝到 `%s/syscall_override/`（优先级高于 syscall/）", rules_dir:gsub("/$", ""))
    patch_readme[#patch_readme + 1] = "2) observe 规则仅用于定位问题，正式使用通常不需要"
    patch_readme[#patch_readme + 1] = ""
    write_file(patch_dir .. "/README.md", table.concat(patch_readme, "\n") .. "\n")

    -- 可选：自动应用规则（默认仅应用 fix 规则；默认不覆盖已有文件）
    local applied = {}
    local applied_fix = {}
    local backup_dir = run_dir .. "/backup_syscall"

    if cfg.apply_rules then
        local backup_ready = false
        local function ensure_backup_dir()
            if backup_ready then
                return
            end
            mkdir_p(backup_dir, 493)
            backup_ready = true
        end

        local backed_up = {}
        local fix_set = {}
        for _, g in ipairs(generated) do
            if g.kind == "fix" then
                fix_set[tostring(g.syscall)] = true
            end
        end

        local function apply_one(g)
            if type(g) ~= "table" or type(g.syscall) ~= "string" or g.syscall == "" then
                return
            end

            -- 先做语法校验，避免把无效 Lua 覆盖到正式规则目录
            do
                local chunk, err = loadfile(tostring(g.file))
                if not chunk then
                    append_file(retry_log_path, string.format("skip apply (bad lua): %s kind=%s err=%s\n",
                        tostring(g.syscall), tostring(g.kind), tostring(err)))
                    return
                end
            end

            local base_dst = string.format("%ssyscall/%s.lua", rules_dir, tostring(g.syscall))
            local override_dst = string.format("%ssyscall_override/%s.lua", rules_dir, tostring(g.syscall))

            -- 默认不覆盖：所有修复规则统一落到 syscall_override/（由 entry.lua 优先加载），避免污染/覆盖基础规则
            local dst = base_dst
            local used_override = false
            if not cfg.overwrite_rules then
                mkdir_p(rules_dir .. "syscall_override", 493)
                dst = override_dst
                used_override = true
            end

            -- 备份：覆盖（或更新 override）前备份一次，便于回滚
            local existed = false
            do
                local df = io.open(dst, "rb")
                if df then
                    existed = true
                    df:close()
                end
            end
            if existed and not backed_up[tostring(g.syscall) .. (used_override and ":override" or ":base")] then
                ensure_backup_dir()
                local suffix = used_override and "__override" or ""
                local bak = string.format("%s/%s%s.lua", backup_dir, tostring(g.syscall), suffix)
                copy_file(dst, bak)
                backed_up[tostring(g.syscall) .. (used_override and ":override" or ":base")] = true
                append_file(retry_log_path, string.format("backup: %s -> %s\n", dst, bak))
            end

            local ok2 = copy_file(g.file, dst)
            if ok2 then
                applied[#applied + 1] = g.syscall
                if g.kind == "fix" then
                    applied_fix[#applied_fix + 1] = g.syscall
                end
                append_file(retry_log_path, string.format("applied: %s kind=%s dst=%s\n",
                    tostring(g.syscall), tostring(g.kind), used_override and "syscall_override" or "syscall"))
            else
                append_file(retry_log_path, string.format("apply failed: %s kind=%s\n", tostring(g.syscall), tostring(g.kind)))
            end
        end

        -- observe 先应用且不覆盖 fix（避免 observe 抢占/阻塞修复规则）
        if cfg.apply_observe then
            for _, g in ipairs(generated) do
                if g.kind ~= "fix" then
                    if fix_set[tostring(g.syscall)] then
                        append_file(retry_log_path, string.format("skip apply observe (fix exists): %s\n", tostring(g.syscall)))
                    else
                        apply_one(g)
                    end
                end
            end
        end

        for _, g in ipairs(generated) do
            if g.kind == "fix" then
                apply_one(g)
            end
        end
    end

    -- E) 自动重试与评估（闭环）：进入“验证窗口”，通过后导出稳定规则
    --
    -- 说明：
    -- - 这里的“重试”指在同一进程内继续运行，让后续 syscall 命中新规则；
    -- - 验证通过后，会把“修复型规则”导出到 stable_root/run_id 目录，供正式使用直接拷贝。
    if #applied_fix > 0 then
        S.verify = {
            active = true,
            run_id = run_id,
            reason = meta.reason or "unknown",
            rules_dir = rules_dir,
            data_root = data_root,
            stable_root = stable_root,
            start_seq = (type(ctx) == "table" and ctx.seq) or 0,
            verify_syscalls = cfg.verify_syscalls,
            generated = generated,
            applied_syscalls = applied,
            applied_fix_syscalls = applied_fix,
            export_observe = cfg.export_observe,
            disable_after_stable = cfg.disable_after_stable,
        }
        append_file(retry_log_path, string.format("verify_start: start_seq=%d verify_syscalls=%d stable_root=%s\n",
            tonumber(S.verify.start_seq) or 0,
            tonumber(S.verify.verify_syscalls) or 0,
            tostring(S.verify.stable_root)))
    else
        -- 本轮未应用修复型规则：不启动验证窗口（仍保留 rules_patch 供人工挑选/合并）
        S.verify = nil
    end

    return {
        run_id = run_id,
        run_dir = run_dir,
        snapshot_path = snapshot_path,
        diagnosis_path = diagnosis_path,
        generated = generated,
        applied_syscalls = applied,
        applied_fix_syscalls = applied_fix,
        stable_root = stable_root,
        -- 自动继续：
        -- - SFEMU_AI_AUTO_CONTINUE=1：无论本轮是否产出修复，都继续运行（避免无人值守时卡在提示）
        -- - SFEMU_AI_AUTO_CONTINUE=0：保持暂停，等待人工确认（entry.lua 会提示输入 YES）
        auto_continue = (cfg.auto_continue == true),
    }
end

local function list_to_set(list)
    local s = {}
    if type(list) ~= "table" then
        return s
    end
    for _, v in ipairs(list) do
        if type(v) == "string" and v ~= "" then
            s[v] = true
        end
    end
    return s
end

local function export_stable_rules(v)
    if type(v) ~= "table" then
        return nil
    end
    local out_dir = string.format("%s/%s", tostring(v.stable_root or ""), tostring(v.run_id or "run"))
    local out_syscall = out_dir .. "/syscall_override"

    mkdir_p(out_syscall, 493)

    local applied_fix_set = list_to_set(v.applied_fix_syscalls)
    local exported = {}

    local function is_transient_rule(path)
        local f = io.open(tostring(path), "rb")
        if not f then
            return false
        end
        local head = f:read(1024) or ""
        f:close()
        -- 约定：规则文件头部包含 `sfemu:transient=1` 时，不导出到 stable_rules（仅用于本轮重试）
        if tostring(head):find("sfemu:transient=1", 1, true) then
            return true
        end
        if tostring(head):find("sfemu_transient=1", 1, true) then
            return true
        end
        return false
    end

    for _, g in ipairs(v.generated or {}) do
        local is_fix = (g.kind == "fix")
        local should_export = false

        -- 正式使用默认只需要“修复型且已应用”的规则
        if is_fix and applied_fix_set[tostring(g.syscall)] then
            should_export = true
        end

        -- 调试模式：可额外导出 observe 规则
        if not should_export and v.export_observe == true then
            should_export = true
        end

        -- 默认不导出 exit/exit_group：这类规则通常仅用于“本轮重试/防退出”，正式使用不应依赖它
        local is_exit = (tostring(g.syscall) == "exit") or (tostring(g.syscall) == "exit_group")
        if should_export and not is_exit then
            if is_transient_rule(g.file) then
                -- 临时规则不导出（例如 exit_group 抑制一次）
                goto continue_export
            end
            local dst = string.format("%s/%s.lua", out_syscall, tostring(g.syscall))
            copy_file(g.file, dst)
            exported[#exported + 1] = { syscall = g.syscall, kind = g.kind, file = dst }
        end
        ::continue_export::
    end

    local readme = {}
    readme[#readme + 1] = "# stable_rules"
    readme[#readme + 1] = ""
    readme[#readme + 1] = string.format("- run_id: `%s`", tostring(v.run_id))
    readme[#readme + 1] = string.format("- reason: `%s`", tostring(v.reason))
    readme[#readme + 1] = ""
    readme[#readme + 1] = "## 使用方式（正式使用）"
    readme[#readme + 1] = string.format("将本目录下的 `syscall_override/*.lua` 拷贝到你的规则目录 `%s/syscall_override/`（不覆盖原有 syscall/），即可复现本次修复。", tostring(v.rules_dir):gsub("/$", ""))
    readme[#readme + 1] = ""
    readme[#readme + 1] = "## 导出内容"
    for _, e in ipairs(exported) do
        readme[#readme + 1] = string.format("- syscall_override/%s.lua (%s)", tostring(e.syscall), tostring(e.kind))
    end
    readme[#readme + 1] = ""
    write_file(out_dir .. "/README.md", table.concat(readme, "\n") .. "\n")

    local manifest = {
        run_id = v.run_id,
        reason = v.reason,
        created_at = os.date("%Y-%m-%d %H:%M:%S"),
        rules_dir = v.rules_dir,
        start_seq = v.start_seq,
        verify_syscalls = v.verify_syscalls,
        applied_fix_syscalls = v.applied_fix_syscalls,
        exported = exported,
    }
    write_file(out_dir .. "/manifest.json", json_encode(manifest, 0, 8) .. "\n")

    return {
        dir = out_dir,
        exported = exported,
    }
end

-- 每个 syscall 进入 entry.lua 后调用：用于“验证窗口”判定通过并导出稳定规则
function M.on_syscall(ctx, entry_state)
    local v = S.verify
    if type(v) ~= "table" or v.active ~= true then
        return nil
    end

    if type(ctx) ~= "table" or type(ctx.seq) ~= "number" then
        return nil
    end

    -- exit/exit_group：不会绕过验证门槛；但当达到导出条件时允许在 exit 点导出（便于“运行结束即产出规则”）

    local start_seq = tonumber(v.start_seq) or ctx.seq
    local verify_syscalls = tonumber(v.verify_syscalls) or 0

    -- 手工标记：设置 SFEMU_AI_MARK_STABLE=1 可在下一次 syscall 直接导出
    local mark = rawget(_G, "SFEMU_AI_MARK_STABLE")
    local manual_mark = (mark == true) or (mark == 1) or (tostring(mark) == "1")

    if not manual_mark and verify_syscalls > 0 then
        if (ctx.seq - start_seq) < verify_syscalls then
            return nil
        end
    end

    local out = export_stable_rules(v)
    v.active = false
    S.last_stable = out

    if v.disable_after_stable == true then
        _G.SFEMU_AI_ENABLE = false
    end

    if out and out.dir then
        log("验证通过：固件已稳定运行，稳定规则已导出：%s", tostring(out.dir))
        if type(out.exported) == "table" then
            for _, e in ipairs(out.exported) do
                log("stable: syscall_override/%s.lua (%s)", tostring(e.syscall), tostring(e.kind))
            end
        end
    end

    return out
end

return M
