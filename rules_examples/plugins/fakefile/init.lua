-- fakefile/init.lua - 缺失文件/设备/Unix Socket 的“伪资源”补全框架
--
-- 设计目标：
-- 1) 当目标程序访问缺失文件时，自动初始化三件套：
--    - <path>.fakefile        : 元数据（状态/类型/映射信息等），放在目标路径同目录
--    - *.fakecontent          : 实际内容存储（可按状态/规则读取），放在插件目录 plugins/fakefile/data 下
--    - *.fakeconfig.lua       : 行为/状态定义（open/read/write/ioctl/connect 等），放在插件目录 plugins/fakefile/config 下
-- 2) open/connect 等 syscall hook 调用本模块的 handle_*，由 fakeconfig 驱动行为。
-- 3) 默认规则：文本/dev 读写为空；socket 缺失时将 fd 交由 fakefile 托管（不创建真实 socket 文件）。

local M = {}

-- 统一日志（在非 QEMU 环境下避免报错）
local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[fakefile] " .. fmt, ...))
    else
        c_log("[fakefile] " .. tostring(fmt))
    end
end

-- 全局状态：确保跨多个 syscall 脚本共享
if not _G._sfemu_fakefile_state then
    _G._sfemu_fakefile_state = {
        path_map = {},       -- orig_path -> record
        fd_map = {},         -- fd -> record
        fd_pos = {},         -- fd -> offset
        config_cache = {},   -- config_path -> cfg(table)
        socket_servers = {}, -- socket_path -> {server_fd=..., accepted_fds={...}}
    }
end
local S = _G._sfemu_fakefile_state

-- 规则目录定位：基于本文件所在目录推导 rules 根目录
local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("plugins/fakefile/?$", "")
local PLUGIN_DIR = rules_dir .. "plugins/fakefile"
local CONFIG_DIR = PLUGIN_DIR .. "/config"
local DATA_DIR = PLUGIN_DIR .. "/data"
local DEFAULT_DIR = PLUGIN_DIR .. "/default"

-- 常量：常见 errno / flags（Linux 通用）
local ENOENT = -2
local O_CREAT = 0x40

local AF_UNIX = 1
local SOCK_STREAM = 1

-- 对少数“必须真实存在且内容正确”的关键文件，避免误创建 fakefile 占位导致程序早退。
-- 典型：固件 httpd 在启动时会读取 /etc/cert.pem（证书），若被 fakefile 替换为元数据文件会触发 OpenSSL 错误。
local function is_ssl_critical_path(path)
    return path == "/etc/cert.pem"
        or path == "/etc/key.pem"
        or path == "/etc/server.pem"
        or path == "/etc/cert.crt"
end

local bootstrap_checked = false
local bootstrap_mod = nil

local function get_bootstrap_mod()
    if bootstrap_checked then
        return bootstrap_mod
    end
    bootstrap_checked = true
    local ok, mod = pcall(require, rules_dir .. "base/bootstrap_fs")
    if ok and type(mod) == "table" then
        bootstrap_mod = mod
        return bootstrap_mod
    end
    bootstrap_mod = nil
    return nil
end

-- ---------- 小工具：shell/路径/文件 ----------

local function sh_quote(s)
    -- 单引号安全转义：' -> '"'"'
    return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end

local function sh_ok(cmd)
    local ok, _, code = os.execute(cmd)
    if ok == true then
        return true
    end
    if type(ok) == "number" then
        return ok == 0
    end
    if type(code) == "number" then
        return code == 0
    end
    return false
end

local function ensure_dir(dir)
    if not dir or dir == "" then
        return false
    end
    -- BusyBox 兼容：部分固件内置的 mkdir/test/ln 不支持 “--” 结束参数
    -- 这里目录/路径均来自固件内绝对路径（通常以 / 开头），不依赖 -- 也足够安全。
    return sh_ok("mkdir -p " .. sh_quote(dir))
end

local function dirname(path)
    local d = tostring(path):match("^(.*)/[^/]+$") or "."
    if d == "" then
        d = "/"
    end
    return d
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function path_exists_any(path)
    -- BusyBox test 可能不支持 “--”，会输出 “unknown operand”，导致误判不存在
    return sh_ok("test -e " .. sh_quote(path))
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

local function migrate_fakeconfig_rules_dir(config_path)
    local f = io.open(config_path, "rb")
    if not f then
        return false
    end
    local content = f:read("*a") or ""
    f:close()

    -- 兼容旧版：default 模板被拷贝到 config 目录后 rules_dir 计算不匹配，导致 require 失败。
    -- 旧模板常见写法：script_dir:gsub("plugins/fakefile/default/?$", "")
    -- 当 script_dir 实际为 plugins/fakefile/config/ 时，上述 gsub 不生效，rules_dir 变成 config 目录。
    if content:find("plugins/fakefile/config/?$", 1, true) then
        return false
    end

    local function replace_once(s, old, new)
        local i, j = s:find(old, 1, true)
        if not i then
            return s, false
        end
        return s:sub(1, i - 1) .. new .. s:sub(j + 1), true
    end

    local canonical = ":gsub(\"plugins/fakefile/config/?$\", \"\"):gsub(\"plugins/fakefile/default/?$\", \"\")"
    local variants = {
        ":gsub(\"plugins/fakefile/default/?$\", \"\")",
        ":gsub(\"plugins/fakefile/default/?$\",\"\")",
        ":gsub('plugins/fakefile/default/?$', '')",
        ":gsub('plugins/fakefile/default/?$','')",
    }

    local replaced = content
    local changed = false
    for _, old in ipairs(variants) do
        local out, ok = replace_once(replaced, old, canonical)
        if ok then
            replaced = out
            changed = true
            break
        end
    end

    if changed and replaced ~= content then
        write_file(config_path, replaced)
        return true
    end
    return false
end

local function copy_file(src, dst)
    local sf, err = io.open(src, "rb")
    if not sf then
        return false, err
    end
    local df, err2 = io.open(dst, "wb")
    if not df then
        sf:close()
        return false, err2
    end
    local data = sf:read("*a")
    sf:close()
    df:write(data or "")
    df:close()
    return true
end

local function sanitize_filename(s)
    s = tostring(s or ""):gsub("[^%w%.%-_]", "_")
    if s == "" then
        s = "unnamed"
    end
    return s
end

local function fnv1a32(s)
    local hash = 0x811c9dc5
    for i = 1, #s do
        hash = hash ~ s:byte(i)
        hash = (hash * 0x01000193) & 0xffffffff
    end
    return hash
end

local function host_pid()
    local f = io.open("/proc/self/stat", "r")
    if not f then
        return -1
    end
    local line = f:read("*l") or ""
    f:close()
    local pid = tonumber(line:match("^(%d+)"))
    return pid or -1
end

-- 尝试把 orig_path 指向 fakefile_path（优先硬链接，失败再软链接）
local function ensure_link(orig_path, fakefile_path)
    if path_exists_any(orig_path) then
        return true
    end

    ensure_dir(dirname(orig_path))
    -- 硬链接：对“禁止软链/不跟随软链”的场景更友好
    if sh_ok("ln -f " .. sh_quote(fakefile_path) .. " " .. sh_quote(orig_path)) then
        return true
    end
    -- 软链接兜底
    if sh_ok("ln -sf " .. sh_quote(fakefile_path) .. " " .. sh_quote(orig_path)) then
        return true
    end
    return false
end

-- ---------- 记录/初始化 ----------

local function classify_path(path)
    if path:match("^/dev/") then
        return "dev"
    end
    -- /proc 一般表现为文本
    return "text"
end

local function is_shared_object_path(path)
    if type(path) ~= "string" or path == "" then
        return false
    end
    -- 典型：libc.so.6 / libpthread.so.0 / ld-uClibc.so.0 / libfoo.so
    return (path:match("%.so$") ~= nil) or (path:match("%.so%.") ~= nil)
end

local function resolve_config_and_content_paths(orig_path)
    local base = sanitize_filename((tostring(orig_path):match("([^/]+)$") or tostring(orig_path)))
    local key = base .. "__" .. string.format("%08x", fnv1a32(orig_path))

    local cfg_base = CONFIG_DIR .. "/" .. base .. ".fakeconfig.lua"
    local cfg_key = CONFIG_DIR .. "/" .. key .. ".fakeconfig.lua"
    local cfg = cfg_base
    if not file_exists(cfg) and file_exists(cfg_key) then
        cfg = cfg_key
    end

    local content_base = DATA_DIR .. "/" .. base .. ".fakecontent"
    local content_key = DATA_DIR .. "/" .. key .. ".fakecontent"
    local content = content_base
    if not file_exists(content) and file_exists(content_key) then
        content = content_key
    end

    return cfg, content, base, key
end

local function write_meta(record)
    ensure_dir(dirname(record.fakefile_path))
    local meta = {}
    meta[#meta + 1] = "fakefile_version=1"
    meta[#meta + 1] = "type=" .. tostring(record.type)
    meta[#meta + 1] = "state=" .. tostring(record.state)
    meta[#meta + 1] = "real_path=" .. tostring(record.orig_path)
    meta[#meta + 1] = "fakefile_path=" .. tostring(record.fakefile_path)
    meta[#meta + 1] = "fakeconfig_path=" .. tostring(record.config_path)
    meta[#meta + 1] = "fakecontent_path=" .. tostring(record.content_path)
    meta[#meta + 1] = "open_count=" .. tostring(record.open_count or 0)
    meta[#meta + 1] = "last_open_pid=" .. tostring(record.last_open_pid or -1)
    meta[#meta + 1] = "last_open_fd=" .. tostring(record.last_open_fd or -1)
    meta[#meta + 1] = "last_open_flags=0x" .. string.format("%x", record.last_open_flags or 0)
    meta[#meta + 1] = "rules_dir=" .. tostring(rules_dir)
    write_file(record.fakefile_path, table.concat(meta, "\n") .. "\n")
end

local function default_config_source(ftype)
    -- 生成一个“可立即工作的”默认 fakeconfig（当 default 模板文件不存在时兜底）
    return table.concat({
        "-- 自动生成的默认 fakeconfig（兜底）",
        "local script_dir = debug.getinfo(1, \"S\").source:match(\"@?(.*/)\") or \"\"",
        "local rules_dir = script_dir:gsub(\"plugins/fakefile/config/?$\", \"\"):gsub(\"plugins/fakefile/default/?$\", \"\")",
        "local fakefile = require(rules_dir .. \"plugins/fakefile\")",
        "",
        "local M = {",
        "    file_type = " .. string.format("%q", ftype) .. ",",
        "    default_state = \"init\",",
        "    states = { init = {} },",
        "}",
        "",
        "M.states.init.open  = function(ctx) return fakefile.default_open(ctx) end",
        "M.states.init.read  = function(ctx) return fakefile.default_read_empty(ctx) end",
        "M.states.init.write = function(ctx) return fakefile.default_write_discard(ctx) end",
        "M.states.init.ioctl = function(ctx) return fakefile.default_ioctl_empty(ctx) end",
        "M.states.init.connect = function(ctx) return fakefile.default_connect_socket(ctx) end",
        "",
        "return M",
        "",
    }, "\n")
end

local function ensure_config(record)
    ensure_dir(CONFIG_DIR)
    if file_exists(record.config_path) then
        return true
    end

    local tpl = DEFAULT_DIR .. "/" .. record.type .. ".fakeconfig.lua"
    if file_exists(tpl) then
        local ok, err = copy_file(tpl, record.config_path)
        if not ok then
            log("拷贝默认模板失败：%s -> %s (%s)", tpl, record.config_path, tostring(err))
        end
    else
        -- 没有默认模板时生成兜底配置
        write_file(record.config_path, default_config_source(record.type))
    end

    return file_exists(record.config_path)
end

local function ensure_content(record)
    ensure_dir(DATA_DIR)
    if file_exists(record.content_path) then
        return true
    end
    local ok, err = write_file(record.content_path, "")
    if not ok then
        log("创建 fakecontent 失败：%s (%s)", record.content_path, tostring(err))
        return false
    end
    return true
end

local function ensure_fakefile_meta(record)
    if file_exists(record.fakefile_path) then
        return true
    end
    write_meta(record)
    return file_exists(record.fakefile_path)
end

local function ensure_record(orig_path, ftype)
    local r = S.path_map[orig_path]
    if r then
        return r
    end

    local cfg_path, content_path, base, key = resolve_config_and_content_paths(orig_path)
    r = {
        orig_path = orig_path,
        type = ftype,
        state = "init",
        fakefile_path = orig_path .. ".fakefile",
        config_path = cfg_path,
        content_path = content_path,
        name_base = base,
        name_key = key,
        open_count = 0,
        last_open_pid = -1,
        last_open_fd = -1,
        last_open_flags = 0,
    }
    S.path_map[orig_path] = r
    return r
end

local function ensure_on_disk(record)
    local ok1 = ensure_config(record)
    local ok2 = ensure_content(record)
    local ok3 = ensure_fakefile_meta(record)
    return ok1 and ok2 and ok3
end

local function load_config(record)
    local cached = S.config_cache[record.config_path]
    if cached then
        return cached
    end

    migrate_fakeconfig_rules_dir(record.config_path)

    local chunk, err = loadfile(record.config_path)
    if not chunk then
        log("load fakeconfig 失败：%s (%s)", record.config_path, tostring(err))
        return {}
    end

    local ok, cfg = pcall(chunk)
    if not ok then
        log("执行 fakeconfig 失败：%s (%s)", record.config_path, tostring(cfg))
        return {}
    end
    if type(cfg) ~= "table" then
        cfg = {}
    end

    S.config_cache[record.config_path] = cfg
    return cfg
end

local function pick_handler(cfg, record, op)
    local st = record.state
    if type(cfg.default_state) == "string" and (not st or st == "") then
        st = cfg.default_state
    end
    st = st or "init"

    if type(cfg.states) == "table" and type(cfg.states[st]) == "table" then
        local f = cfg.states[st][op]
        if type(f) == "function" then
            return f
        end
    end

    local f2 = cfg[op]
    if type(f2) == "function" then
        return f2
    end

    return nil
end

-- ---------- 对外：状态/内容/应答辅助 ----------

function M.get_paths()
    return {
        rules_dir = rules_dir,
        config_dir = CONFIG_DIR,
        data_dir = DATA_DIR,
        default_dir = DEFAULT_DIR,
    }
end

-- 仅用于外部日志/调试：判断某 fd 是否由 fakefile 管理
function M.lookup_record_by_fd(fd)
    return S.fd_map[fd]
end

function M.is_fake_fd(fd)
    return S.fd_map[fd] ~= nil
end

function M.set_state(record_or_ctx, new_state)
    local record = record_or_ctx
    if type(record_or_ctx) == "table" and record_or_ctx.record then
        record = record_or_ctx.record
    end
    if type(record) ~= "table" then
        return false
    end
    record.state = tostring(new_state or "init")
    write_meta(record)
    return true
end

-- 读取 fakecontent 全量内容（文本/二进制均可）
function M.read_fakecontent(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end
    local data = f:read("*a") or ""
    f:close()
    return data, nil
end

-- 读取 fakecontent 的行区间（0-based，end_line 包含）
function M.read_fakecontent_lines(path, start_line, end_line)
    start_line = tonumber(start_line or 0) or 0
    end_line = tonumber(end_line or start_line) or start_line
    if start_line < 0 then
        start_line = 0
    end
    if end_line < start_line then
        end_line = start_line
    end

    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end

    local out = {}
    local idx = 0
    for line in f:lines() do
        if idx >= start_line and idx <= end_line then
            out[#out + 1] = line
        end
        if idx > end_line then
            break
        end
        idx = idx + 1
    end
    f:close()

    return table.concat(out, "\n") .. (next(out) and "\n" or ""), nil
end

-- read syscall：把 data 写回 guest buf，并按 fd 偏移截断
function M.reply_read_bytes(ctx, data)
    data = data or ""
    local fd = ctx.fd
    local buf = ctx.buf
    local count = tonumber(ctx.count or 0) or 0
    if count <= 0 then
        return 1, 0
    end

    local off = tonumber(ctx.offset or 0) or 0
    if off < 0 then
        off = 0
    end

    local chunk = ""
    if off < #data then
        chunk = data:sub(off + 1, off + count)
    end

    if chunk == "" then
        return 1, 0
    end

    local written, rc = c_write_bytes(buf, chunk)
    if rc ~= 0 then
        return 1, rc
    end

    local n = tonumber(written) or #chunk
    S.fd_pos[fd] = off + n
    return 1, n
end

-- ---------- 默认行为（可被 fakeconfig 覆盖） ----------

function M.default_open(ctx)
    -- ctx.pathname_ptr 必须仍指向“原路径字符串”
    -- 同时兼容 open/openat：
    --   open  : (pathname, flags, mode)
    --   openat: (dirfd, pathname, flags, mode)
    if ctx.dirfd ~= nil then
        return 1, c_do_syscall(ctx.num, ctx.dirfd, ctx.pathname_ptr, ctx.flags, ctx.mode,
                               ctx.arg5 or 0, ctx.arg6 or 0, ctx.arg7 or 0, ctx.arg8 or 0)
    end
    return 1, c_do_syscall(ctx.num, ctx.pathname_ptr, ctx.flags, ctx.mode,
                           ctx.arg4 or 0, ctx.arg5 or 0, ctx.arg6 or 0, ctx.arg7 or 0, ctx.arg8 or 0)
end

function M.default_read_empty(_ctx)
    return 1, 0
end

function M.default_write_discard(ctx)
    local n = tonumber(ctx.count or 0) or 0
    if n < 0 then
        n = 0
    end
    local off = tonumber(ctx.offset or 0) or 0
    if off < 0 then
        off = 0
    end
    S.fd_pos[ctx.fd] = off + n
    return 1, n
end

function M.default_ioctl_empty(_ctx)
    return 1, 0
end

local function socket_syscalls(connect_num)
    -- 最小必要：只覆盖常用架构（可按需扩展）
    -- ARM EABI: socket=281 bind=282 connect=283 listen=284 accept=285 close=6
    -- AArch64 : socket=198 bind=200 connect=203 listen=201 accept=202 close=57
    -- x86_64  : socket=41  bind=49  connect=42  listen=50  accept=43  close=3
    local map = {
        [283] = { socket = 281, bind = 282, listen = 284, accept = 285, close = 6 },
        [203] = { socket = 198, bind = 200, listen = 201, accept = 202, close = 57 },
        [42]  = { socket = 41,  bind = 49,  listen = 50,  accept = 43,  close = 3 },
    }
    return map[connect_num]
end

local function ensure_socket_server(ctx, socket_path)
    if S.socket_servers[socket_path] then
        return true, S.socket_servers[socket_path]
    end

    local sc = socket_syscalls(ctx.num)
    if not sc then
        return false, "unknown_arch"
    end

    ensure_dir(dirname(socket_path))
    -- 删除旧文件，避免 bind 失败（尽量用 shell，避免依赖 unlink syscall 号）
    sh_ok("rm -f " .. sh_quote(socket_path))

    local server_fd = c_do_syscall(sc.socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0, 0, 0)
    if server_fd < 0 then
        return false, server_fd
    end

    local brc = c_do_syscall(sc.bind, server_fd, ctx.addr, ctx.addrlen, 0, 0, 0, 0, 0)
    if brc < 0 then
        c_do_syscall(sc.close, server_fd, 0, 0, 0, 0, 0, 0, 0)
        return false, brc
    end

    local lrc = c_do_syscall(sc.listen, server_fd, 16, 0, 0, 0, 0, 0, 0)
    if lrc < 0 then
        c_do_syscall(sc.close, server_fd, 0, 0, 0, 0, 0, 0, 0)
        return false, lrc
    end

    local server = { server_fd = server_fd, accepted_fds = {} }
    S.socket_servers[socket_path] = server
    return true, server
end

function M.default_connect_socket(ctx)
    -- 默认策略：不创建真实 socket 文件，而是把 sockfd 交由 fakefile 托管，
    -- 后续 write/read/ioctl 等 syscall 可被 fakefile 拦截，避免未连接 socket 导致 ENOTCONN/EPIPE。
    local fd = tonumber(ctx.sockfd or -1) or -1
    if fd < 0 or type(ctx.record) ~= "table" then
        return 1, 0
    end

    S.fd_map[fd] = ctx.record
    S.fd_pos[fd] = 0

    ctx.record.open_count = (ctx.record.open_count or 0) + 1
    ctx.record.last_open_pid = host_pid()
    ctx.record.last_open_fd = fd
    ctx.record.last_open_flags = 0
    write_meta(ctx.record)

    log("socket 托管：fd=%d path=%s", fd, tostring(ctx.socket_path or ctx.record.orig_path))
    return 1, 0
end

function M.default_connect_socket_server(ctx)
    -- 可选策略：尽力创建 Unix domain socket server(bind/listen/accept) 并让 client 真正 connect 一次
    local ok, server_or_err = ensure_socket_server(ctx, ctx.socket_path)
    if not ok then
        log("无法创建 socket server(%s)，回退到 fake 托管；err=%s", tostring(ctx.socket_path), tostring(server_or_err))
        return M.default_connect_socket(ctx)
    end

    local crc = c_do_syscall(ctx.num, ctx.sockfd, ctx.addr, ctx.addrlen, 0, 0, 0, 0, 0)
    if crc < 0 then
        return 1, crc
    end

    local sc = socket_syscalls(ctx.num)
    if sc then
        local accepted = c_do_syscall(sc.accept, server_or_err.server_fd, 0, 0, 0, 0, 0, 0, 0)
        if accepted >= 0 then
            server_or_err.accepted_fds[#server_or_err.accepted_fds + 1] = accepted
        end
    end

    return 1, 0
end

-- ---------- fake_*：调用配置 ----------

function M.fake_open(ctx)
    local cfg = load_config(ctx.record)
    local handler = pick_handler(cfg, ctx.record, "open")
    if handler then
        local ok, a, b = pcall(handler, ctx)
        if ok then
            return a, b
        end
        log("fake_open handler 崩溃：%s", tostring(a))
    end
    return M.default_open(ctx)
end

function M.fake_read(ctx)
    local cfg = load_config(ctx.record)
    local handler = pick_handler(cfg, ctx.record, "read")
    if handler then
        local ok, a, b = pcall(handler, ctx)
        if ok then
            return a, b
        end
        log("fake_read handler 崩溃：%s", tostring(a))
    end
    return M.default_read_empty(ctx)
end

function M.fake_write(ctx)
    local cfg = load_config(ctx.record)
    local handler = pick_handler(cfg, ctx.record, "write")
    if handler then
        local ok, a, b = pcall(handler, ctx)
        if ok then
            return a, b
        end
        log("fake_write handler 崩溃：%s", tostring(a))
    end
    return M.default_write_discard(ctx)
end

function M.fake_ioctl(ctx)
    local cfg = load_config(ctx.record)
    local handler = pick_handler(cfg, ctx.record, "ioctl")
    if handler then
        local ok, a, b = pcall(handler, ctx)
        if ok then
            return a, b
        end
        log("fake_ioctl handler 崩溃：%s", tostring(a))
    end
    return M.default_ioctl_empty(ctx)
end

function M.fake_connect(ctx)
    local cfg = load_config(ctx.record)
    local handler = pick_handler(cfg, ctx.record, "connect")
    if handler then
        local ok, a, b = pcall(handler, ctx)
        if ok then
            return a, b
        end
        log("fake_connect handler 崩溃：%s", tostring(a))
    end
    return M.default_connect_socket(ctx)
end

-- ---------- syscall hook 入口：handle_* ----------

function M.handle_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    local path, rc = c_read_string(pathname, 4096)
    if rc ~= 0 or not path or path == "" then
        return 1, c_do_syscall(num, pathname, flags, mode, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    end

    -- 先尝试原始 open（只做一次，避免后续重复）
    local ret = c_do_syscall(num, pathname, flags, mode, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if ret >= 0 then
        return 1, ret
    end

    -- 仅对“缺失且非 O_CREAT”的场景初始化 fakefile
    if ret ~= ENOENT or ((flags or 0) & O_CREAT) ~= 0 then
        return 1, ret
    end

    -- 对证书文件：缺失时优先尝试 bootstrap 补齐，避免被 fakefile 空文件/元数据占位导致 OpenSSL 退出
    if is_ssl_critical_path(path) then
        local b = get_bootstrap_mod()
        if b and type(b.bootstrap) == "function" then
            pcall(b.bootstrap)
            local retry = c_do_syscall(num, pathname, flags, mode, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
            return 1, retry
        end
        return 1, ret
    end

    -- 外部动态库必须真实存在：避免对 .so 创建 fakefile 干扰动态链接
    if is_shared_object_path(path) then
        return 1, ret
    end

    local ftype = classify_path(path)
    local record = ensure_record(path, ftype)
    if not ensure_on_disk(record) then
        return 1, ret
    end

    -- 让原路径可打开到 <path>.fakefile（socket 类型不创建，避免影响 bind）
    if record.type ~= "socket" then
        ensure_link(path, record.fakefile_path)
    end

    local ctx = {
        num = num,
        dirfd = nil,
        pathname_ptr = pathname,
        flags = flags or 0,
        mode = mode or 0,
        arg4 = arg4, arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
        fd = -1,
        buf = 0,
        count = 0,
        offset = 0,
    }

    local action, fd = M.fake_open(ctx)
    if action ~= 1 then
        action, fd = M.default_open(ctx)
    end

    if type(fd) == "number" and fd >= 0 then
        record.open_count = (record.open_count or 0) + 1
        record.last_open_pid = host_pid()
        record.last_open_fd = fd
        record.last_open_flags = flags or 0
        write_meta(record)
        S.fd_map[fd] = record
        S.fd_pos[fd] = 0
    end

    return action, fd
end

-- openat：仅在 pathname 为绝对路径 或 dirfd == AT_FDCWD 时启用 fakefile（避免无法解析 dirfd 的相对路径）
function M.handle_openat(num, dirfd, pathname, flags, mode, arg5, arg6, arg7, arg8)
    local path, rc = c_read_string(pathname, 4096)
    if rc ~= 0 or not path or path == "" then
        return 1, c_do_syscall(num, dirfd, pathname, flags, mode, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    end

    local ret = c_do_syscall(num, dirfd, pathname, flags, mode, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if ret >= 0 then
        return 1, ret
    end

    local AT_FDCWD = -100
    local can_fake = (path:sub(1, 1) == "/") or (dirfd == AT_FDCWD)
    if not can_fake then
        return 1, ret
    end

    if ret ~= ENOENT or ((flags or 0) & O_CREAT) ~= 0 then
        return 1, ret
    end

    -- 对证书文件：缺失时优先尝试 bootstrap 补齐，避免被 fakefile 空文件/元数据占位导致 OpenSSL 退出
    if is_ssl_critical_path(path) then
        local b = get_bootstrap_mod()
        if b and type(b.bootstrap) == "function" then
            pcall(b.bootstrap)
            local retry = c_do_syscall(num, dirfd, pathname, flags, mode, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
            return 1, retry
        end
        return 1, ret
    end

    -- 外部动态库必须真实存在：避免对 .so 创建 fakefile 干扰动态链接
    if is_shared_object_path(path) then
        return 1, ret
    end

    local ftype = classify_path(path)
    local record = ensure_record(path, ftype)
    if not ensure_on_disk(record) then
        return 1, ret
    end

    if record.type ~= "socket" then
        ensure_link(path, record.fakefile_path)
    end

    local ctx = {
        num = num,
        dirfd = dirfd,
        pathname_ptr = pathname,
        flags = flags or 0,
        mode = mode or 0,
        arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
        fd = -1,
        buf = 0,
        count = 0,
        offset = 0,
    }

    local action, fd = M.fake_open(ctx)
    if action ~= 1 then
        action, fd = M.default_open(ctx)
    end

    if type(fd) == "number" and fd >= 0 then
        record.open_count = (record.open_count or 0) + 1
        record.last_open_pid = host_pid()
        record.last_open_fd = fd
        record.last_open_flags = flags or 0
        write_meta(record)
        S.fd_map[fd] = record
        S.fd_pos[fd] = 0
    end

    return action, fd
end

function M.handle_read(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    local record = S.fd_map[fd]
    if not record then
        return 0, 0
    end

    local ctx = {
        num = num,
        fd = fd,
        buf = buf,
        count = count,
        arg4 = arg4, arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
        offset = S.fd_pos[fd] or 0,
    }
    return M.fake_read(ctx)
end

function M.handle_write(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    local record = S.fd_map[fd]
    if not record then
        return 0, 0
    end

    local ctx = {
        num = num,
        fd = fd,
        buf = buf,
        count = count,
        arg4 = arg4, arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
        offset = S.fd_pos[fd] or 0,
    }
    return M.fake_write(ctx)
end

function M.handle_ioctl(num, fd, cmd, arg, arg4, arg5, arg6, arg7, arg8)
    local record = S.fd_map[fd]
    if not record then
        return 0, 0
    end

    local ctx = {
        num = num,
        fd = fd,
        cmd = cmd,
        arg = arg,
        arg4 = arg4, arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
    }
    return M.fake_ioctl(ctx)
end

-- connect：仅处理 AF_UNIX；非 Unix socket 放行
function M.handle_connect(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    if addr == 0 then
        return 0, 0
    end

    local family_bytes, frc = c_read_bytes(addr, 2)
    if frc ~= 0 or not family_bytes or #family_bytes < 2 then
        return 0, 0
    end
    local family = string.byte(family_bytes, 1) + (string.byte(family_bytes, 2) << 8)
    if family ~= AF_UNIX then
        return 0, 0
    end

    local socket_path, prc = c_read_string(addr + 2, 108)
    if prc ~= 0 or not socket_path then
        return 0, 0
    end
    socket_path = socket_path:match("^([^%z]*)")
    if socket_path == "" then
        return 0, 0
    end

    -- 先尝试原始 connect（只做一次）
    local ret = c_do_syscall(num, sockfd, addr, addrlen, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if ret == 0 then
        return 1, 0
    end

    -- 判断是否启用 fake socket：1) 目标路径缺失/拒绝 2) 路径在常见目录或已存在 fakefile/config
    local need_fake = socket_path:match("^/tmp/") or socket_path:match("^/var/") or socket_path:match("^/run/")
    if file_exists(socket_path .. ".fakefile") then
        need_fake = true
    end

    local record = ensure_record(socket_path, "socket")
    if file_exists(record.config_path) then
        need_fake = true
    end

    if not need_fake then
        return 1, ret
    end

    ensure_on_disk(record)

    local ctx = {
        num = num,
        sockfd = sockfd,
        addr = addr,
        addrlen = addrlen,
        socket_path = socket_path,
        arg4 = arg4, arg5 = arg5, arg6 = arg6, arg7 = arg7, arg8 = arg8,
        record = record,
    }

    return M.fake_connect(ctx)
end

function M.handle_close(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 先执行真实 close，再清理映射（避免 fd 复用导致误判）
    local ret = c_do_syscall(num, fd, arg2 or 0, arg3 or 0, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if type(ret) == "number" and ret == 0 then
        S.fd_map[fd] = nil
        S.fd_pos[fd] = nil
    end
    return 1, ret
end

function M.handle_lseek(num, fd, offset, whence, arg4, arg5, arg6, arg7, arg8)
    local record = S.fd_map[fd]
    if not record then
        return 0, 0
    end

    local ret = c_do_syscall(num, fd, offset, whence, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
    if type(ret) == "number" and ret >= 0 then
        S.fd_pos[fd] = ret
    end
    return 1, ret
end

return M
