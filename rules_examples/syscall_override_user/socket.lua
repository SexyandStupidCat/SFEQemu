-- socket.lua - 本地 override：netlink 兼容 + 标记 fd（用于 sendmsg/recvmsg 兜底）
--
-- 背景：
-- 部分固件会创建 netlink socket 使用非标准/宿主不支持的协议号，导致 socket() 失败或后续 sendmsg 报错。
-- 本规则在“精确匹配”场景下：
-- 1) 将 proto 从 BAD_PROTO 映射到 FALLBACK_PROTO 创建真实 fd；
-- 2) 记录该 fd 到 _sfemu_netlink_fds，供 sendmsg/recvmsg 规则做更进一步的兼容处理。
--
-- 注意：该规则只处理 netlink 特定模式，其它 socket 仍走原生 syscall。

local AF_NETLINK = 16
local SOCK_RAW = 3
local BAD_PROTO = 31
local FALLBACK_PROTO = 0 -- NETLINK_ROUTE

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

local function mark_netlink_fd(fd, meta)
    if type(_G._sfemu_netlink_fds) ~= "table" then
        _G._sfemu_netlink_fds = {}
    end
    _G._sfemu_netlink_fds[fd] = meta or {}
end

function do_syscall(num, domain, stype, proto, arg4, arg5, arg6, arg7, arg8)
    if domain == AF_NETLINK and stype == SOCK_RAW and proto == BAD_PROTO then
        local fd = c_do_syscall(num, domain, stype, FALLBACK_PROTO,
            arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
        if type(fd) == "number" and fd >= 0 then
            mark_netlink_fd(fd, {
                domain = domain,
                stype = stype,
                orig_proto = BAD_PROTO,
                proto = FALLBACK_PROTO,
            })
            log("[fix:netlink] socket(AF_NETLINK,SOCK_RAW,%d) -> proto=%d fd=%d (mark)", BAD_PROTO, FALLBACK_PROTO, fd)
            return 1, fd
        end
        log("[fix:netlink] fallback socket failed ret=%s (pass-through)", tostring(fd))
    end
    return 0, 0
end

