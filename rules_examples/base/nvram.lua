-- nvram.lua - /dev/nvram 设备的最小可用仿真（ASUS/Broadcom 常见接口）
--
-- 目标：
-- - 让 libnvram.so 的 nvram_init/nvram_get/nvram_set 在仿真环境中“前进”，避免因 /dev/nvram 不可 mmap/read 导致崩溃
--
-- 关键行为（来自固件 libnvram 的伪C）：
-- - nvram_init():
--     fd = open("/dev/nvram", O_RDWR)
--     ioctl(fd, 1, &size)        -- 返回 mmap 大小
--     base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0)
-- - nvram_get(key):
--     buf = "key\\0"
--     n = read(fd, buf, len)
--     if n == 4: offset = *(u32*)buf; return base + offset
-- - nvram_set(key, val):
--     write(fd, "key=value\\0", len)  -- 期望返回 len
--
-- 因此我们需要同时兼容 ioctl/read/write/mmap。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("base/?$", "")

local fdmap = require(rules_dir .. "base/fdmap")

local M = {}

local PROT_READ = 0x1
local PROT_WRITE = 0x2
local MAP_PRIVATE = 0x2
local MAP_ANONYMOUS = 0x20

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[nvram] " .. fmt, ...))
    else
        c_log("[nvram] " .. tostring(fmt))
    end
end

local function u32_le(x)
    x = tonumber(x) or 0
    x = x & 0xffffffff
    return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff)
end

local function is_nvram_fd(fd)
    local info = fdmap.get(fd)
    return type(info) == "table" and info.path == "/dev/nvram"
end

local function state()
    if type(_G._sfemu_nvram_state) ~= "table" then
        _G._sfemu_nvram_state = {
            size = 0x1f000,     -- 固件常见默认（见 nvram_init 伪C）
            base = 0,           -- mmap 返回地址
            blob_size = 0,
            next_off = 1,       -- 0 预留给空字符串
            offsets = {},       -- key -> offset
            kv = {},            -- key -> value
        }
    end
    return _G._sfemu_nvram_state
end

local function ensure_defaults(st)
    -- 尽量给出“对 httpd 无害”的默认值：避免 nvram_get 返回 NULL 导致固件崩溃
    local defaults = {
        http_lanport = "80",
        https_lanport = "443",
        https_enable = "0",
        -- ASUS/Broadcom 常见约定：http_enable=0 表示启用，=1 表示禁用（否则 httpd 会跳过 bind 并进入 nfds=0 的 select 循环）
        http_enable = "0",
        lan_ipaddr = "192.168.1.1",
        lan_netmask = "255.255.255.0",
        lan_proto = "dhcp",
        wan_proto = "dhcp",
    }
    for k, v in pairs(defaults) do
        if st.kv[k] == nil then
            st.kv[k] = v
        end
    end
end

local function append_value(st, key, value)
    if st.base == 0 or st.blob_size <= 0 then
        st.offsets[key] = 0
        return 0
    end

    value = tostring(value or "")
    local payload = value .. "\0"
    local need = #payload
    local off = tonumber(st.next_off) or 1
    if off < 1 then
        off = 1
    end
    if off + need > st.blob_size then
        -- 空间不足：退回空字符串
        st.offsets[key] = 0
        return 0
    end

    local _, rc = c_write_bytes(st.base + off, payload)
    if rc ~= 0 then
        st.offsets[key] = 0
        return 0
    end

    st.offsets[key] = off
    st.next_off = off + need
    return off
end

local function rebuild_blob(st, size)
    if st.base == 0 or size <= 0 then
        return
    end
    st.blob_size = size
    st.next_off = 1
    st.offsets = {}

    -- offset=0：空字符串（保证 nvram_get 未命中时返回非 NULL 指针）
    pcall(c_write_bytes, st.base, "\0")

    ensure_defaults(st)
    for k, v in pairs(st.kv) do
        append_value(st, k, v)
    end
end

function M.handle_ioctl(_num, fd, request, arg)
    if not is_nvram_fd(fd) then
        return 0, 0
    end

    request = tonumber(request) or 0

    -- nvram_init: ioctl(fd, 1, &size)
    if request == 1 then
        local st = state()
        -- 固件会把 size 初始化为 0x1f000，这里保守沿用；也允许后续通过 env 覆盖
        local forced = tonumber(rawget(_G, "SFEMU_NVRAM_SIZE"))
        if forced and forced > 4096 and forced < (1 << 28) then
            st.size = forced
        end
        if arg and arg ~= 0 then
            pcall(c_write_bytes, arg, u32_le(st.size))
        end
        return 1, 0
    end

    -- nvram_commit/nvram_xfr 常见 magic（libnvram 伪C里出现 0x48534c46 'FLSH'）
    if request == 0x48534C46 then
        return 1, 0
    end

    -- 其它 request：保守返回成功，避免固件早退
    return 1, 0
end

function M.handle_mmap(num, addr, length, prot, flags, fd, offset, arg7, arg8)
    if not is_nvram_fd(fd) then
        return 0, 0
    end

    length = tonumber(length) or 0
    offset = tonumber(offset) or 0
    prot = tonumber(prot) or 0

    if length <= 0 or offset ~= 0 then
        return 0, 0
    end

    local st = state()
    st.size = length

    -- 用匿名映射代替设备映射：让固件能拿到一段可读内存作为“nvram 数据区”
    local new_prot = prot | PROT_WRITE -- 便于填充；比起读不到更重要
    local new_flags = MAP_PRIVATE | MAP_ANONYMOUS
    local base = c_do_syscall(num, addr, length, new_prot, new_flags, -1, 0, arg7 or 0, arg8 or 0)
    if type(base) ~= "number" or base < 0 then
        log("mmap 失败：ret=%s len=%d", tostring(base), length)
        return 1, base
    end

    st.base = base
    rebuild_blob(st, length)

    log("mmap ok：base=0x%x size=%d", base, length)
    return 1, base
end

function M.handle_read(_num, fd, buf, count)
    if not is_nvram_fd(fd) then
        return 0, 0
    end

    local st = state()
    if st.base == 0 then
        -- nvram_init 未成功 mmap：返回 0，让上层按失败处理（避免写野指针）
        return 1, 0
    end

    count = tonumber(count) or 0
    if not buf or buf == 0 or count <= 0 then
        return 1, 0
    end

    -- nvram_getall：调用方会先把 *buf=0，再 read(fd, buf, n)
    local first, rc1 = c_read_bytes(buf, 1)
    if rc1 == 0 and type(first) == "string" and #first == 1 and first == "\0" then
        local out = {}
        for k, v in pairs(st.kv) do
            out[#out + 1] = tostring(k) .. "=" .. tostring(v or "") .. "\0"
        end
        out[#out + 1] = "\0"
        local blob = table.concat(out)
        if #blob > count then
            blob = blob:sub(1, count)
        end
        pcall(c_write_bytes, buf, blob)
        return 1, #blob
    end

    -- nvram_get：buf 里是 key 字符串
    local key, rc = c_read_string(buf, count)
    if rc ~= 0 or not key then
        return 1, 0
    end
    key = key:match("^([^%z]*)") or ""
    if key == "" then
        return 1, 0
    end

    -- 命中则直接返回 offset；未命中则追加默认/空值，确保返回非 NULL
    local off = st.offsets[key]
    if off == nil then
        ensure_defaults(st)
        local val = st.kv[key]
        if val == nil then
            val = ""
        end
        off = append_value(st, key, val)
    end

    pcall(c_write_bytes, buf, u32_le(off))
    return 1, 4
end

function M.handle_write(_num, fd, buf, count)
    if not is_nvram_fd(fd) then
        return 0, 0
    end

    local st = state()
    count = tonumber(count) or 0
    if not buf or buf == 0 or count <= 0 then
        return 1, 0
    end

    local s, rc = c_read_string(buf, count)
    if rc ~= 0 or not s then
        return 1, -14 -- -EFAULT
    end
    s = s:match("^([^%z]*)") or ""

    local k, v = s:match("^([^=]+)=(.*)$")
    if k and k ~= "" then
        st.kv[k] = v or ""
        append_value(st, k, st.kv[k])
        return 1, count
    end

    -- unset：只写 key
    if s ~= "" then
        st.kv[s] = nil
        st.offsets[s] = 0
        return 1, count
    end

    return 1, count
end

return M
