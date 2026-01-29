-- base/netlink.lua - netlink/msghdr/WLCSM 解析与伪造的通用 API
--
-- 设计目标：
-- 1) 把“结构体解析/字节序/写回 iov”等通用逻辑收敛到 base，避免单个 syscall 规则过长
-- 2) 兼容 QEMU-user + 32-bit ARM 目标（指针/size_t 为 4 字节）
-- 3) 失败时尽量返回 nil/0，不在此处强依赖日志（由上层规则决定是否 log）

local M = {}

-- ---------- 小工具：LE 读写 ----------

function M.read_u16_le(bytes, off)
    off = off or 1
    if type(bytes) ~= "string" or #bytes < off + 1 then
        return nil
    end
    local b1 = string.byte(bytes, off)
    local b2 = string.byte(bytes, off + 1)
    return b1 + (b2 << 8)
end

function M.read_u32_le(bytes, off)
    off = off or 1
    if type(bytes) ~= "string" or #bytes < off + 3 then
        return nil
    end
    local b1 = string.byte(bytes, off)
    local b2 = string.byte(bytes, off + 1)
    local b3 = string.byte(bytes, off + 2)
    local b4 = string.byte(bytes, off + 3)
    return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)
end

function M.u16_le(x)
    x = tonumber(x) or 0
    x = x & 0xffff
    return string.char(x & 0xff, (x >> 8) & 0xff)
end

function M.u32_le(x)
    x = tonumber(x) or 0
    x = x & 0xffffffff
    return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff)
end

function M.s32_le(x)
    x = tonumber(x) or 0
    if x < 0 then
        x = (x + 0x100000000) & 0xffffffff
    end
    return M.u32_le(x)
end

function M.align4(n)
    n = tonumber(n) or 0
    if n < 0 then
        n = 0
    end
    return (n + 3) & 0xfffffffc
end

-- ---------- msghdr / iovec（32-bit ARM） ----------

-- struct msghdr:
--   void*   msg_name;       0
--   int     msg_namelen;    4
--   iovec*  msg_iov;        8
--   size_t  msg_iovlen;     12
--   void*   msg_control;    16
--   size_t  msg_controllen; 20
--   int     msg_flags;      24
-- 共 28 字节（32-bit）
function M.parse_msghdr(msghdr_ptr)
    if not msghdr_ptr or msghdr_ptr == 0 then
        return nil
    end
    local hdr, rc = c_read_bytes(msghdr_ptr, 28)
    if rc ~= 0 or type(hdr) ~= "string" or #hdr < 28 then
        return nil
    end
    return {
        msg_name = M.read_u32_le(hdr, 1) or 0,
        msg_namelen = M.read_u32_le(hdr, 5) or 0,
        iov_ptr = M.read_u32_le(hdr, 9) or 0,
        iov_len = M.read_u32_le(hdr, 13) or 0,
    }
end

function M.read_iov_entry(iov_ptr, idx)
    if not iov_ptr or iov_ptr == 0 then
        return nil, nil
    end
    idx = tonumber(idx) or 0
    if idx < 0 then
        return nil, nil
    end
    local iov, rc = c_read_bytes(iov_ptr + idx * 8, 8)
    if rc ~= 0 or type(iov) ~= "string" or #iov < 8 then
        return nil, nil
    end
    local base = M.read_u32_le(iov, 1) or 0
    local len = M.read_u32_le(iov, 5) or 0
    if base == 0 or len <= 0 then
        return nil, nil
    end
    return base, len
end

function M.read_msghdr_iov0(msghdr_ptr)
    local f = M.parse_msghdr(msghdr_ptr)
    if not f then
        return nil, nil
    end
    if f.iov_ptr == 0 or f.iov_len <= 0 then
        return nil, nil
    end
    return M.read_iov_entry(f.iov_ptr, 0)
end

function M.calc_iov_total_len(msghdr_ptr, max_iov)
    max_iov = tonumber(max_iov) or 64
    if max_iov <= 0 then
        max_iov = 64
    end

    local f = M.parse_msghdr(msghdr_ptr)
    if not f then
        return 0
    end
    if f.iov_ptr == 0 or f.iov_len <= 0 then
        return 0
    end
    local iov_len = math.min(tonumber(f.iov_len) or 0, max_iov)
    if iov_len <= 0 then
        return 0
    end

    local total = 0
    for i = 0, iov_len - 1 do
        local iov, rc = c_read_bytes(f.iov_ptr + i * 8, 8)
        if rc ~= 0 or type(iov) ~= "string" or #iov < 8 then
            break
        end
        local one = M.read_u32_le(iov, 5) or 0
        if one > 0 then
            total = total + one
        end
    end
    if total < 0 then
        total = 0
    end
    return total
end

function M.write_to_iov(iov_ptr, iov_len, data, max_iov)
    if not iov_ptr or iov_ptr == 0 then
        return 0
    end
    iov_len = tonumber(iov_len) or 0
    if iov_len <= 0 then
        return 0
    end
    data = data or ""
    if type(data) ~= "string" or data == "" then
        return 0
    end
    max_iov = tonumber(max_iov) or 64
    if max_iov <= 0 then
        max_iov = 64
    end
    iov_len = math.min(iov_len, max_iov)

    local total = 0
    local off = 1
    for i = 0, iov_len - 1 do
        if off > #data then
            break
        end
        local iov, rc = c_read_bytes(iov_ptr + i * 8, 8)
        if rc ~= 0 or type(iov) ~= "string" or #iov < 8 then
            break
        end
        local base = M.read_u32_le(iov, 1) or 0
        local len = M.read_u32_le(iov, 5) or 0
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

-- 填写 msg_name 指向的 sockaddr_nl，并回填 msg_namelen=12
function M.fill_sockaddr_nl(msghdr_ptr, msghdr_fields, pid, groups)
    if not msghdr_fields then
        return false
    end
    local msg_name = tonumber(msghdr_fields.msg_name) or 0
    local msg_namelen = tonumber(msghdr_fields.msg_namelen) or 0
    if msg_name == 0 or msg_namelen < 12 then
        return false
    end

    local AF_NETLINK = 16
    pid = tonumber(pid) or 0
    groups = tonumber(groups) or 0
    local sockaddr = M.u16_le(AF_NETLINK) .. M.u16_le(0) .. M.u32_le(pid) .. M.u32_le(groups)
    pcall(c_write_bytes, msg_name, sockaddr)
    pcall(c_write_bytes, msghdr_ptr + 4, M.u32_le(12))
    return true
end

-- ---------- netlink 基础 ACK ----------

function M.capture_nlmsghdr16(msghdr_ptr)
    local base, blen = M.read_msghdr_iov0(msghdr_ptr)
    if not base or not blen or blen < 16 then
        return nil
    end
    local nl, rc = c_read_bytes(base, 16)
    if rc ~= 0 or type(nl) ~= "string" or #nl < 16 then
        return nil
    end
    return {
        hdr16 = nl,
        len = M.read_u32_le(nl, 1),
        ntype = M.read_u16_le(nl, 5),
        nflags = M.read_u16_le(nl, 7),
        seq = M.read_u32_le(nl, 9),
        pid = M.read_u32_le(nl, 13),
    }
end

function M.build_nlmsg_error_ack(req_hdr16)
    -- struct nlmsghdr (16B) + struct nlmsgerr (4B error + 16B msg) = 36B
    local NLMSG_ERROR = 2
    local nlmsg_len = 36

    local seq = 0
    local pid = 0
    if type(req_hdr16) == "string" and #req_hdr16 >= 16 then
        seq = M.read_u32_le(req_hdr16, 9) or 0
        pid = M.read_u32_le(req_hdr16, 13) or 0
    else
        req_hdr16 = string.rep("\0", 16)
    end

    local hdr =
        M.u32_le(nlmsg_len) ..
        M.u16_le(NLMSG_ERROR) ..
        M.u16_le(0) ..
        M.u32_le(seq) ..
        M.u32_le(pid)

    local err = M.s32_le(0) .. req_hdr16
    return hdr .. err
end

-- ---------- WLCSM（ASUS libnvram）最小解析/构造 ----------

-- 解析请求：
-- - nlmsg_type=u16@0x04（应为 5）
-- - seq=u32@0x08, pid=u32@0x0c
-- - cmd=u16@0x10（本项目关注 nvram_get=3）
-- - data_len=u16@0x12
-- - key=str@0x18（以 \\0 结尾）
function M.parse_wlcsm_netlink_msg(msghdr_ptr, max_bytes)
    max_bytes = tonumber(max_bytes) or 2048
    if max_bytes < 64 then
        max_bytes = 64
    end
    if max_bytes > 65536 then
        max_bytes = 65536
    end

    local base, blen = M.read_msghdr_iov0(msghdr_ptr)
    if not base then
        return nil
    end

    local head, rc = c_read_bytes(base, 24)
    if rc ~= 0 or type(head) ~= "string" or #head < 24 then
        return nil
    end

    local nlmsg_type = M.read_u16_le(head, 5) or 0
    local nlmsg_seq = M.read_u32_le(head, 9) or 0
    local nlmsg_pid = M.read_u32_le(head, 13) or 0
    local cmd = M.read_u16_le(head, 17) or 0
    local data_len = M.read_u16_le(head, 19) or 0
    local param4 = M.read_u32_le(head, 21) or 0

    local key = ""
    if data_len > 0 then
        local want = 24 + data_len
        if blen and want > blen then
            want = blen
        end
        if want > max_bytes then
            want = max_bytes
        end
        local full, rc2 = c_read_bytes(base, want)
        if rc2 == 0 and type(full) == "string" and #full >= 24 then
            local payload = full:sub(25, 24 + math.min(data_len, #full - 24))
            key = (payload:match("^([^%z]*)") or "")
        end
    end

    return {
        nlmsg_type = nlmsg_type,
        nlmsg_seq = nlmsg_seq,
        nlmsg_pid = nlmsg_pid,
        cmd = cmd,
        data_len = data_len,
        param4 = param4,
        key = key,
    }
end

function M.build_wlcsm_nvram_get_reply(req, value)
    local WLCSM_NLMSG_TYPE = 5

    local key = tostring(req and req.key or "")
    local cmd = tonumber(req and req.cmd) or 3
    local seq = tonumber(req and req.nlmsg_seq) or 1
    local pid = tonumber(req and req.nlmsg_pid) or 0

    value = tostring(value or "0")
    if value == "" then
        value = "0"
    end

    local key_z = key .. "\0"
    local key_pad_len = M.align4(#key_z)
    local key_pad = key_z .. string.rep("\0", key_pad_len - #key_z)

    local val_z = value .. "\0"
    local val_len = #value
    if val_len <= 0 then
        val_len = 1
    end

    -- payload: u32 0 + key(str) + pad + u32 val_len + value(str)
    local payload = M.u32_le(0) .. key_pad .. M.u32_le(val_len) .. val_z
    local data_len = #payload

    local total_len = M.align4(24 + data_len)

    local hdr =
        M.u32_le(total_len) ..
        M.u16_le(WLCSM_NLMSG_TYPE) ..
        M.u16_le(0) ..
        M.u32_le(seq) ..
        M.u32_le(pid)

    local body = M.u16_le(cmd) .. M.u16_le(data_len) .. M.u32_le(0) .. payload
    local msg = hdr .. body
    if #msg < total_len then
        msg = msg .. string.rep("\0", total_len - #msg)
    end
    return msg
end

return M

