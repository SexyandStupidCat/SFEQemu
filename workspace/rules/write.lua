function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
	print("hoho\n")
    print(string.format("0x%x\n", arg2))
    -- while (true)
    -- do
    --     os.execute("sleep 1")
    -- end
    c_do_syscall(num, arg1, arg2, 9, arg4, arg5, arg6, arg7, arg8)
    return 5  -- 1=已处理, 99999=返回值
end