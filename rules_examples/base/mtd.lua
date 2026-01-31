-- mtd.lua - /proc/mtd 与 /dev/mtd* 的最小仿真
--
-- 背景：
-- - 一些固件的 Web 服务（例如 mini_httpd / boa）会读取 /proc/mtd 或打开 /dev/mtd 来获取 flash 分区信息。
-- - 在容器/chroot 环境里，这些节点通常不存在，程序可能直接退出或走异常路径（自旋/崩溃）。
--
-- 策略：
-- - open.lua 在打开失败(ENOENT)时，把 /proc/mtd、/dev/mtd* 映射到 host 的 /dev/zero（得到一个可用 fd）
-- - read.lua 根据 fdmap 标记拦截 read()，对 /proc/mtd 返回固定文本；对 /dev/mtd* 返回全 0 数据
--
-- 注意：
-- - 这是“通性兜底”，并不等价于真实 MTD 设备；只用于让服务前进并启动监听。

local M = {}

local EFAULT = -14
local EINVAL = -22

if not _G._sfemu_mtd_state then
    _G._sfemu_mtd_state = {
        pos = {}, -- fd -> offset（仅用于 /proc/mtd）
    }
end

local S = _G._sfemu_mtd_state

local function proc_mtd_content()
    -- 典型 Linux /proc/mtd 格式：dev/size/erasesize/name
    -- 这里给最小两分区，避免部分程序解析失败。
    return table.concat({
        "dev:    size   erasesize  name\n",
        "mtd0: 00040000 00010000 \"boot\"\n",
        "mtd1: 003b0000 00010000 \"rootfs\"\n",
    })
end

function M.mark_fd(fd)
    fd = tonumber(fd) or -1
    if fd < 0 then
        return false
    end
    if S.pos[fd] == nil then
        S.pos[fd] = 0
    end
    return true
end

function M.unmark_fd(fd)
    fd = tonumber(fd) or -1
    if fd < 0 then
        return false
    end
    S.pos[fd] = nil
    return true
end

function M.handle_read(fd, path, buf, count)
    fd = tonumber(fd) or -1
    buf = tonumber(buf) or 0
    count = tonumber(count) or 0
    if fd < 0 or buf == 0 or count <= 0 then
        return 0, 0
    end

    if path == "/proc/mtd" then
        local content = proc_mtd_content()
        local off = tonumber(S.pos[fd]) or 0
        if off >= #content then
            return 1, 0
        end

        local n = count
        if n > (#content - off) then
            n = #content - off
        end
        if n > 4096 then
            n = 4096
        end

        local chunk = content:sub(off + 1, off + n)
        local _, rc = c_write_bytes(buf, chunk)
        if rc ~= 0 then
            return 1, EFAULT
        end

        S.pos[fd] = off + n
        return 1, n
    end

    if type(path) == "string" and path:match("^/dev/mtd") then
        local n = count
        if n > 4096 then
            n = 4096
        end
        local _, rc = c_write_bytes(buf, string.rep("\0", n))
        if rc ~= 0 then
            return 1, EFAULT
        end
        return 1, n
    end

    return 0, 0
end

function M.handle_lseek(fd, path, offset, whence)
    fd = tonumber(fd) or -1
    offset = tonumber(offset) or 0
    whence = tonumber(whence) or 0
    if fd < 0 then
        return 0, 0
    end

    if path ~= "/proc/mtd" then
        return 0, 0
    end

    local content = proc_mtd_content()
    local size = #content
    local cur = tonumber(S.pos[fd]) or 0
    local new_off = cur

    if whence == 0 then
        new_off = offset
    elseif whence == 1 then
        new_off = cur + offset
    elseif whence == 2 then
        new_off = size + offset
    else
        return 1, EINVAL
    end

    if new_off < 0 then
        new_off = 0
    end
    if new_off > size then
        new_off = size
    end

    S.pos[fd] = new_off
    return 1, new_off
end

return M
