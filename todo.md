当前目录为魔改后的qemu，主要改动点在于tcg和qemu-user，目的是用于嵌入式系统的单服务仿真，主体思路是通过劫持系统调用，判断系统调用是否需要hook，系统调用内存的修改和返回值的修改，劫持系统调用过程的方法是通过lua脚本，在启动时指定lua脚本的目录来进行加载。当前加载的逻辑是，当遇到系统调用时，在指定的目录下寻找同系统调用名的lua脚本。你的任务是，按照下面所讲的，去修改代码


# 目录结构

config/ // 配置信息
base/ // 如log, sftrace.lua模块等
data/ // 数据信息
plugins/ // 各种插件的目录
plugins/fakefile/ // fakefile模块
syscall/  // 包含各种对系统调用的hook, 按照系统调用的名称命名, 如open.lua
entry.lua // 当进入到系统调用时，先进入entry.lua脚本
finish.lua // 系统调用结束时，进入finish.lua，记录返回值，执行结果等信息


# 修改内容

当进入到系统调用时，先进入entry.lua脚本，该脚本大体流程如下

if( need_hook() ) { // 判断是否需要hook，如果需要返回true。这里面hook的判定是指定的某几个系统调用来算的，这个可以从qemu测的syscall.c看到
    
    save_content(args...)  // 用于保存系统调用上下文
    if (check_status() == False) // 这里是要添加的内容！！！我希望在这里添加检查仿真状态的内容，后面描述有详细更改的内容
        {
        pause_and_wait_handle() // 暂停仿真过程，打印对应的日志（后文所述）
        if (need_ai)
            ai_handle() // 增加ai干预的, 这里只预留出函数接口即可
        else
            handle() // 等待人手工干预结束，这里就是暂停，等待人按下Yes继续运行
    }
    need_change, ret = do_syscall() // 这个从syscall目录下，找到对应名字的syscall.lua, 两个返回值分别对应：如果need_change的值为True, 则ret有效，不执行syscall.c的系统调用；如果need_change的值为False， 则ret无效，执行syscall.c的系统调用
}

修改的地方：
1. 将系统调用上下文写到data目录下进行保留(在启动参数上设置保留的数量)
2. check_status: 检查仿真状态根据两个方面：(1) 前进性，根据保存的系统调用上下文，看系统调用上下文序列（包括系统调用号、参数以及函数调用的backtrace）是否有重复序列，如果有代表陷入死循环 （2）在确定陷入死循环的前提下，对仿真的目标服务尝试交互，看是否可以打破死循环（比如httpd服务，就向80/443端口发送数据包，注意发送数据包这个过程是单启动一个线程去做的），如果可以打破系统调用循环，代表运行正常，否则说明仿真失败，打印log（包括系统调用序列和对应backtrace的伪C代码）
3. 增加ai干预和人手工干预的接口
