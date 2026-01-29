-- bootstrap_fs.lua - 固件仿真启动前的“最小补齐”
--
-- 目标：
-- 1) 补齐 httpd 启动所需的关键目录（例如 /var/lock）
-- 2) 为固件提供一个可用的 SSL 证书/密钥（避免因 /etc/cert.pem 为空/占位导致 httpd 退出）
--
-- 设计约束：
-- - 默认仅在检测到“固件 rootfs”时生效（通过 .init_enable_core 标记文件判断）
-- - 避免在宿主机 /etc 写入：若不在固件根目录下则直接跳过
-- - 仅在目标文件不存在或明显不是 PEM 时才覆盖

local M = {}

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[bootstrap] " .. fmt, ...))
    else
        c_log("[bootstrap] " .. tostring(fmt))
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

local function read_file(path, max_bytes)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local data
    if max_bytes and max_bytes > 0 then
        data = f:read(max_bytes)
    else
        data = f:read("*a")
    end
    f:close()
    return data or ""
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

local function is_pem_like(data, keyword)
    if type(data) ~= "string" then
        return false
    end
    if #data < 32 then
        return false
    end
    if not data:find("-----BEGIN", 1, true) then
        return false
    end
    if keyword and keyword ~= "" then
        return data:find(keyword, 1, true) ~= nil
    end
    return true
end

local function normalize_root_prefix(prefix)
    if prefix == nil then
        return nil
    end
    if prefix == "" or prefix == "/" then
        return ""
    end
    prefix = tostring(prefix):gsub("/+$", "")
    if prefix == "." then
        return "."
    end
    return prefix
end

local function join_root(prefix, abs_path)
    abs_path = tostring(abs_path or "")
    if abs_path == "" then
        return abs_path
    end
    if abs_path:sub(1, 1) ~= "/" then
        abs_path = "/" .. abs_path
    end

    prefix = normalize_root_prefix(prefix)
    if prefix == nil or prefix == "" then
        return abs_path
    end
    if prefix == "." then
        return "." .. abs_path
    end
    return prefix .. abs_path
end

local function detect_root_prefix(rules_dir)
    -- 1) chroot 环境：固件根为 /
    if file_exists("/.init_enable_core") then
        return ""
    end

    -- 1.5) 启发式：若固件根目录下存在 /qemu-arm 且 /rules_examples/entry.lua 可见，
    -- 则大概率已 chroot 到固件 rootfs（允许写绝对路径 /etc /var 等，不会污染宿主机）。
    if file_exists("/qemu-arm") and file_exists("/rules_examples/entry.lua") then
        return ""
    end

    -- 2) 非 chroot，但当前工作目录就是 rootfs（便于本地调试）
    if file_exists("./.init_enable_core") then
        return "."
    end

    -- 2.5) 启发式：未放置 .init_enable_core 时，也允许通过“rootfs 指纹”判定当前 cwd 为 rootfs。
    -- 典型场景：在宿主机直接 cd 到 rootfs 目录运行 ./start.sh。
    if file_exists("./rules_examples/entry.lua") and (file_exists("./qemu-arm") or file_exists("./usr/sbin/httpd")) then
        return "."
    end

    -- 3) 根据 rules 目录推导 rootfs 根目录（rules_dir 通常为 <rootfs>/rules_examples/）
    if type(rules_dir) == "string" and rules_dir ~= "" then
        local rd = rules_dir:gsub("/+$", "")
        local root_guess = rd:gsub("/rules_examples$", "")
        if root_guess ~= rd then
            if file_exists(root_guess .. "/.init_enable_core") then
                return root_guess
            end

            -- 3.5) 启发式：root_guess 下存在典型固件文件，则视为 rootfs（避免强依赖 marker）。
            if file_exists(root_guess .. "/rules_examples/entry.lua") and (file_exists(root_guess .. "/qemu-arm") or file_exists(root_guess .. "/usr/sbin/httpd")) then
                return root_guess
            end
        end
    end

    return nil
end

local function ensure_dir(path)
    if type(c_mkdir_p) == "function" then
        local ok, rc = c_mkdir_p(path, 493) -- 0755
        if ok then
            return true
        end
        return false, rc
    end

    -- 兜底：依赖 /bin/mkdir（通常固件内为 busybox）
    -- BusyBox 兼容：部分固件内置的 mkdir 不支持 “--” 结束参数
    local cmd = string.format("mkdir -p %q >/dev/null 2>&1", path)
    local r1, r2, r3 = os.execute(cmd)
    if r1 == true or r1 == 0 or r3 == 0 then
        return true
    end
    return false, -1
end

local function ensure_executable(path)
    -- BusyBox 兼容：固件环境里一般只有 busybox chmod；用最简单的 “chmod +x” 即可。
    local cmd = string.format("chmod +x %q >/dev/null 2>&1", path)
    local r1, _r2, r3 = os.execute(cmd)
    if r1 == true or r1 == 0 or r3 == 0 then
        return true
    end
    return false, r3 or -1
end

function M.bootstrap()
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    local rules_dir = script_dir:gsub("base/?$", "")

    local root = detect_root_prefix(rules_dir)
    if not root then
        -- 不在固件环境：跳过，避免污染宿主机文件系统
        return false, "not_in_firmware_rootfs"
    end

    -- A) 目录补齐（尽量兼容 /etc -> /tmp/etc 与 /var -> /tmp/var 的固件布局）
    --
    -- 重要坑点：
    -- - 很多固件把 /var 做成 symlink（/var -> /tmp/var），但解包后的 /tmp/var 可能不存在；
    -- - 此时在宿主侧直接 mkdir -p /var/run 会失败（因为 /var 作为 symlink 已存在，但目标目录不存在），表现为 errno=EEXIST/ENOENT；
    -- - 因此这里优先补齐 /tmp/var，再补齐 /var/run /var/lock。

    -- A1) /tmp/etc（兼容 /etc -> /tmp/etc；若 /tmp 被挂 tmpfs，此目录常为空）
    do
        local tmp_etc_dir = join_root(root, "/tmp/etc")
        local ok, err = ensure_dir(tmp_etc_dir)
        if not ok then
            log("创建目录失败：%s err=%s", tmp_etc_dir, tostring(err))
        end
    end

    -- A2) /tmp/var/{run,lock}（为 /var -> /tmp/var 兜底）
    do
        local tmp_var_run = join_root(root, "/tmp/var/run")
        local ok, err = ensure_dir(tmp_var_run)
        if not ok then
            log("创建目录失败：%s err=%s", tmp_var_run, tostring(err))
        end
    end
    do
        local tmp_var_lock = join_root(root, "/tmp/var/lock")
        local ok, err = ensure_dir(tmp_var_lock)
        if not ok then
            log("创建目录失败：%s err=%s", tmp_var_lock, tostring(err))
        end
    end

    -- A3) /var/run（httpd 写 pidfile 常用路径）
    do
        local run_dir = join_root(root, "/var/run")
        local ok, err = ensure_dir(run_dir)
        if not ok then
            log("创建目录失败：%s err=%s", run_dir, tostring(err))
        end
    end

    -- A4) /var/lock（httpd file_lock 依赖）
    do
        local lock_dir = join_root(root, "/var/lock")
        local ok, err = ensure_dir(lock_dir)
        if not ok then
            log("创建目录失败：%s err=%s", lock_dir, tostring(err))
        end
    end

    -- B) 工具可执行位补齐：某些固件解包后可执行位丢失，会导致 httpd 调用脚本/openssl 失败（如 gencert.sh）。
    do
        local exec_candidates = {
            "/usr/sbin/gencert.sh",
            "/usr/sbin/openssl",
            "/bin/nvram",
        }
        for _, p in ipairs(exec_candidates) do
            local hp = join_root(root, p)
            if file_exists(hp) then
                local ok, err = ensure_executable(hp)
                if not ok then
                    log("chmod +x 失败：%s err=%s", hp, tostring(err))
                end
            end
        end
    end

    -- C) SSL 证书/密钥补齐：/etc/cert.pem /etc/key.pem /etc/server.pem /etc/cert.crt
    -- 约定：优先从 config/ssl/ 读取（配置的一部分）；兼容旧路径 assets/ssl/
    local function pick_ssl_asset(rel)
        local p1 = rules_dir .. "config/ssl/" .. rel
        if file_exists(p1) then
            return p1
        end
        return rules_dir .. "assets/ssl/" .. rel
    end

    local cert_src = pick_ssl_asset("cert.pem")
    local key_src = pick_ssl_asset("key.pem")

    local cert_data = read_file(cert_src)
    local key_data = read_file(key_src)
    if cert_data == "" or key_data == "" then
        log("缺少内置证书资源：cert=%s key=%s", tostring(cert_src), tostring(key_src))
        return false, "missing_ssl_assets"
    end

    local cert_dst = join_root(root, "/etc/cert.pem")
    local key_dst = join_root(root, "/etc/key.pem")
    local server_dst = join_root(root, "/etc/server.pem")
    local crt_dst = join_root(root, "/etc/cert.crt")

    local cur_cert = read_file(cert_dst, 8192) or ""
    local cur_key = read_file(key_dst, 8192) or ""
    local cur_server = read_file(server_dst, 8192) or ""
    local cur_crt = read_file(crt_dst, 8192) or ""

    -- 注意：部分固件（例如部分 ASUS）会用 OpenSSL 的 X509_AUX 路径读取 /etc/cert.pem，
    -- 这会要求 PEM 头为 “TRUSTED CERTIFICATE”。如果固件自带的是普通 “CERTIFICATE”，会直接报：
    --   Expecting: TRUSTED CERTIFICATE
    -- 因此这里对 cert.pem 更严格：优先保证是 “TRUSTED CERTIFICATE”。
    local need_cert = not is_pem_like(cur_cert, "TRUSTED CERTIFICATE")
    local need_key = not is_pem_like(cur_key, "PRIVATE KEY")
    local need_server = not is_pem_like(cur_server, "PRIVATE KEY")
    local need_crt = not is_pem_like(cur_crt, "CERTIFICATE")

    -- 仅当明显无效时才覆盖，避免破坏用户已有证书
    if need_cert then
        local ok, err = write_file(cert_dst, cert_data .. "\n")
        log("写入 cert.pem：%s ok=%s err=%s", cert_dst, tostring(ok), tostring(err))
    end
    if need_key then
        local ok, err = write_file(key_dst, key_data .. "\n")
        log("写入 key.pem：%s ok=%s err=%s", key_dst, tostring(ok), tostring(err))
    end
    if need_server or need_cert or need_key then
        local ok, err = write_file(server_dst, key_data .. "\n" .. cert_data .. "\n")
        log("写入 server.pem：%s ok=%s err=%s", server_dst, tostring(ok), tostring(err))
    end
    if need_crt or need_cert then
        local ok, err = write_file(crt_dst, cert_data .. "\n")
        log("写入 cert.crt：%s ok=%s err=%s", crt_dst, tostring(ok), tostring(err))
    end

    log("bootstrap 完成：root=%s", tostring(root))
    return true
end

return M
