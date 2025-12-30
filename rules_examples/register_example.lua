-- register_example.lua - 展示如何读取和修改 CPU 寄存器
-- 这个示例展示了寄存器访问功能

local log = require("rules_examples.base.log")

log.enable_file_logging()
log.set_level(log.LEVEL.INFO)

log.info("=== Register Operations Example ===")

-- 记录是否已经显示过寄存器列表
local regs_listed = false

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 只在第一次调用时显示所有寄存器
    if not regs_listed then
        log.separator("=", 60)
        log.info("Listing all available registers:")
        log.separator("-", 60)

        local regs = c_list_regs()
        if regs then
            for i, reg_name in ipairs(regs) do
                local value, size, rc = c_get_reg(reg_name)
                if rc == 0 then
                    if type(value) == "number" then
                        log.info("  [%3d] %-10s = 0x%-16x (size: %d bytes)",
                                i-1, reg_name, value, size)
                    else
                        log.info("  [%3d] %-10s = <raw bytes> (size: %d bytes)",
                                i-1, reg_name, size)
                    end
                end
            end
        end

        log.separator("=", 60)
        regs_listed = true
    end

    -- 对于每次系统调用，显示关键寄存器
    log.count("syscall_count")

    -- 读取 PC/IP 寄存器（不同架构名称不同）
    local pc, size, rc = c_get_reg("pc")
    if rc ~= 0 then
        pc, size, rc = c_get_reg("rip")  -- x86_64
    end
    if rc ~= 0 then
        pc, size, rc = c_get_reg("ip")   -- x86
    end

    if rc == 0 then
        log.syscall("syscall", "num=%d, PC=0x%x", num, pc)
    else
        log.syscall("syscall", "num=%d", num)
    end

    -- 示例：修改寄存器（谨慎使用！）
    -- 这里演示如何设置寄存器，但实际不修改以避免影响程序执行
    --[[
    if num == 39 then  -- getpid
        -- 读取当前 x0/rax 值
        local ret_reg, size, rc = c_get_reg("x0")  -- ARM
        if rc ~= 0 then
            ret_reg, size, rc = c_get_reg("rax")   -- x86_64
        end

        if rc == 0 then
            log.info("  Original return register value: 0x%x", ret_reg)

            -- 设置返回值寄存器为假的 PID
            -- local written, rc = c_set_reg("x0", 99999)
            -- if rc == 0 then
            --     log.info("  Modified return register to 99999")
            -- end
        end
    end
    ]]--

    -- 继续正常执行
    return 0, 0
end

log.info("Register example loaded")
log.info("Will display all registers on first syscall")
