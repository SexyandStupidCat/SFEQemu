-- sendmsg.lua - 本地 override：/dev/log syslog 兼容 + netlink 兜底（sendmsg）
--
-- 目标：
-- 1) 复用已有的 syslog 兼容逻辑：对 /dev/log fd 丢弃发送但返回成功；
-- 2) 对被 socket.lua 标记的 netlink fd：丢弃发送但返回成功，并记录最近一次请求头，供 recvmsg 生成 ACK。
--
-- 注意：此处“返回成功”是为了让固件继续运行；真正的协议语义由更高层规则/分析决定。

local function is_syslog_fd(fd)
    local m = rawget(_G, "_sfemu_syslog_fds")
    return type(m) == "table" and m[fd] == true
end

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

local function read_u16_le(bytes, off)
    off = off or 1
    if not bytes or #bytes < off + 1 then
        return nil
    end
    local b1 = string.byte(bytes, off)
    local b2 = string.byte(bytes, off + 1)
    return b1 + (b2 << 8)
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

local function calc_sendmsg_len(msghdr_ptr)
    if not msghdr_ptr or msghdr_ptr == 0 then
        return 0
    end
    -- 针对 32-bit ARM 的 struct msghdr 布局（指针/size_t 均 4B）
    local hdr, rc = c_read_bytes(msghdr_ptr, 28)
    if rc ~= 0 or not hdr or #hdr < 28 then
        return 0
    end
    local iov_ptr = read_u32_le(hdr, 9)
    local iov_len = read_u32_le(hdr, 13)
    if not iov_ptr or not iov_len then
        return 0
    end
    if iov_ptr == 0 or iov_len <= 0 or iov_len > 64 then
        return 0
    end
    local total = 0
    for i = 0, iov_len - 1 do
        local iov, rc2 = c_read_bytes(iov_ptr + i * 8, 8)
        if rc2 ~= 0 or not iov or #iov < 8 then
            break
        end
        local one = read_u32_le(iov, 5) or 0
        if one < 0 then
            one = 0
        end
        total = total + one
    end
    if total < 0 then
        total = 0
    end
    return total
end

local function capture_netlink_req_header(msghdr_ptr)
    if not msghdr_ptr or msghdr_ptr == 0 then
        return nil
    end
    local hdr, rc = c_read_bytes(msghdr_ptr, 28)
    if rc ~= 0 or not hdr or #hdr < 28 then
        return nil
    end
    local iov_ptr = read_u32_le(hdr, 9)
    local iov_len = read_u32_le(hdr, 13)
    if not iov_ptr or not iov_len or iov_ptr == 0 or iov_len <= 0 then
        return nil
    end
    local iov0, rc2 = c_read_bytes(iov_ptr, 8)
    if rc2 ~= 0 or not iov0 or #iov0 < 8 then
        return nil
    end
    local base = read_u32_le(iov0, 1)
    local len = read_u32_le(iov0, 5)
    if not base or not len or base == 0 or len < 16 then
        return nil
    end
    local nl, rc3 = c_read_bytes(base, 16)
    if rc3 ~= 0 or not nl or #nl < 16 then
        return nil
    end
    local seq = read_u32_le(nl, 9)
    local pid = read_u32_le(nl, 13)
    local ntype = read_u16_le(nl, 5)
    local nflags = read_u16_le(nl, 7)
    return {
        hdr16 = nl,
        seq = seq,
        pid = pid,
        ntype = ntype,
        nflags = nflags,
        len = read_u32_le(nl, 1),
    }
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
    if is_syslog_fd(fd) then
        local n = calc_sendmsg_len(msg)
        log("[fix:/dev/log] sendmsg fd=%d len=%d (discard)", fd or -1, n)
        return 1, n
    end

    local st = get_netlink_state(fd)
    if st then
        local n = calc_sendmsg_len(msg)
        local req = capture_netlink_req_header(msg)
        if req and req.hdr16 then
            st.last_req_hdr16 = req.hdr16
            st.last_req_seq = req.seq
            st.last_req_pid = req.pid
            st.last_req_type = req.ntype
            st.last_req_flags = req.nflags
        end
        log("[fix:netlink] sendmsg fd=%d len=%d (discard as success)", fd or -1, n)
        return 1, n
    end

    return 0, 0
end

