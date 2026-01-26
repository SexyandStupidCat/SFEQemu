-- recvmsg.lua - 本地 override：netlink 兜底（recvmsg）
--
-- 目标：
-- 对 socket.lua 标记的 netlink fd，构造一个最小的 NLMSG_ERROR(ACK, error=0) 返回给固件，
-- 用于绕过“宿主不支持的 netlink 协议/消息导致 sendmsg/recvmsg 失败”的场景。
--
-- 说明：
-- - 这是“兼容兜底”，并不保证协议语义完整；
-- - ACK 中会尽量回填最近一次 sendmsg 捕获到的 request nlmsghdr（16B），以匹配 seq。

local function get_netlink_state(fd)
    local m = rawget(_G, "_sfemu_netlink_fds")
    if type(m) ~= "table" then
        return nil
    end
    local st = m[fd]
    if type(st) ~= "table" then
        return nil
    end
    return st
end

local function read_u32_le(bytes, off)
    off = off or 1
    if not bytes or #bytes < off + 3 then
        return nil
    end
    local b1 = string.byte(bytes, off)
    local b2 = string.byte(bytes, off + 1)
    local b3 = string.byte(bytes, off + 2)
    local b4 = string.byte(bytes, off + 3)
    return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)
end

local function u16_le(x)
    x = tonumber(x) or 0
    x = x & 0xffff
    return string.char(x & 0xff, (x >> 8) & 0xff)
end

local function u32_le(x)
    x = tonumber(x) or 0
    x = x & 0xffffffff
    return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff)
end

local function s32_le(x)
    x = tonumber(x) or 0
    -- 兼容负数：转为无符号 32-bit
    if x < 0 then
        x = (x + 0x100000000) & 0xffffffff
    end
    return u32_le(x)
end

local function build_nlmsg_error_ack(req_hdr16)
    -- struct nlmsghdr (16B) + struct nlmsgerr (4B error + 16B msg) = 36B
    local NLMSG_ERROR = 2
    local nlmsg_len = 36
    local seq = 0
    local pid = 0

    if type(req_hdr16) == "string" and #req_hdr16 >= 16 then
        seq = read_u32_le(req_hdr16, 9) or 0
        pid = read_u32_le(req_hdr16, 13) or 0
    else
        req_hdr16 = string.rep("\0", 16)
    end

    local hdr =
        u32_le(nlmsg_len) ..
        u16_le(NLMSG_ERROR) ..
        u16_le(0) .. -- flags
        u32_le(seq) ..
        u32_le(pid)

    local err = s32_le(0) .. req_hdr16
    return hdr .. err
end

local function calc_iov_addr_and_len(msghdr_ptr)
    if not msghdr_ptr or msghdr_ptr == 0 then
        return nil, nil
    end
    local hdr, rc = c_read_bytes(msghdr_ptr, 28)
    if rc ~= 0 or not hdr or #hdr < 28 then
        return nil, nil
    end
    local iov_ptr = read_u32_le(hdr, 9)
    local iov_len = read_u32_le(hdr, 13)
    if not iov_ptr or not iov_len or iov_ptr == 0 or iov_len <= 0 or iov_len > 64 then
        return nil, nil
    end
    return iov_ptr, iov_len
end

local function write_to_iov(iov_ptr, iov_len, data)
    if not iov_ptr or not iov_len or not data then
        return 0
    end
    local total = 0
    local off = 1
    for i = 0, iov_len - 1 do
        if off > #data then
            break
        end
        local iov, rc = c_read_bytes(iov_ptr + i * 8, 8)
        if rc ~= 0 or not iov or #iov < 8 then
            break
        end
        local base = read_u32_le(iov, 1) or 0
        local len = read_u32_le(iov, 5) or 0
        if base ~= 0 and len > 0 then
            local take = math.min(len, #data - off + 1)
            local chunk = data:sub(off, off + take - 1)
            local _, wrc = c_write_bytes(base, chunk)
            if wrc ~= 0 then
                break
            end
            off = off + take
            total = total + take
        end
    end
    return total
end

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format(fmt, ...))
    else
        c_log(tostring(fmt))
    end
end

function do_syscall(num, fd, msg, flags, arg4, arg5, arg6, arg7, arg8)
    local st = get_netlink_state(fd)
    if not st then
        return 0, 0
    end

    local payload = build_nlmsg_error_ack(st.last_req_hdr16)
    local iov_ptr, iov_len = calc_iov_addr_and_len(msg)
    if not iov_ptr then
        -- 无法写入用户缓冲区：返回 0（让上层当作无数据/EOF 处理）
        log("[fix:netlink] recvmsg fd=%d: msghdr parse failed (return 0)", fd or -1)
        return 1, 0
    end

    local n = write_to_iov(iov_ptr, iov_len, payload)
    log("[fix:netlink] recvmsg fd=%d -> ack bytes=%d", fd or -1, n)
    return 1, n
end

