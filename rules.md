# SFEmu 仿真规则总结（rules.md）

> 目标：把“通性问题”沉淀为 `rules_examples/syscall/*.lua` 或通用插件逻辑；  
> 固件特有差异（路径/型号差异/私有 ioctl 等）放到固件 rootfs 下的 `rules_examples/syscall_override_user/`。

## 1. 已沉淀的通用规则（基线）

### 1.1 文件系统与目录补齐

- `open/openat + O_CREAT`：父目录不存在时先 `mkdir -p dirname(path)`，再放行原始 syscall  
  - 典型场景：`/var/run/httpd.pid`、`/var/lock/*` 等  
  - 文件：`rules_examples/syscall/open.lua`、`rules_examples/syscall/openat.lua`

- 启动前最小补齐（目录/证书/可执行位）  
  - 目录：`/var/lock`、`/var/run`、`/tmp/etc`  
  - SSL：写入 `/etc/cert.pem`、`/etc/key.pem`、`/etc/server.pem`、`/etc/cert.crt`（使用 `rules_examples/config/ssl/` 模板）  
  - 文件：`rules_examples/base/bootstrap_fs.lua`

### 1.2 SSL/证书读取失败（/etc -> /tmp/etc + tmpfs）

- 现象：固件 `httpd` 或 `gencert.sh/openssl` 读取 `/etc/cert.pem` 报 `ENOENT`，可能进入交互/退出。
- 策略：bootstrap 先补齐证书；fakefile 对关键证书路径不做“空文件占位”，而是优先触发 bootstrap 重试。
- 文件：`rules_examples/base/bootstrap_fs.lua`、`rules_examples/plugins/fakefile/init.lua`

### 1.3 NVRAM 设备缺失（/dev/nvram）

- 现象：
  - 典型：`/dev/nvram` 不存在，或 `ioctl` 返回 `EINVAL/ENOTTY`，导致配置读取失败
  - 特殊但高频（privileged docker）：容器内可能自带真实字符设备 `/dev/nvram`，但 `open()` 返回 `-EBUSY/-EINVAL`；
    在 ASUS `httpd/2.0` 这类固件里，往往会在处理“非 loopback 来访”路径上触发该分支并崩溃/退出（表现为宿主机访问端口后连接被重置、qemu/core dump）
- 策略：
  - 规则侧：`open/openat` 对 `/dev/nvram` 统一“重定向打开 `/dev/zero`”，并在 `fdmap` 里把该 fd 标记成 `/dev/nvram`
  - 行为侧：后续 `ioctl/mmap/read/write` 由 `rules_examples/base/nvram.lua` 接管，提供最小可用的 nvram_get/nvram_set 前进性
  - 引擎侧：新增 Lua helper `c_open_host()`（只允许打开 `/dev/zero|/dev/null|/dev/urandom|/dev/random`），避免 Lua 改写只读 rodata 中的 pathname 指针失败
- 文件：
  - 规则：`rules_examples/syscall/open.lua`、`rules_examples/syscall/openat.lua`、`rules_examples/syscall/ioctl.lua`、`rules_examples/syscall/mmap.lua`、`rules_examples/syscall/mmap2.lua`
  - 逻辑：`rules_examples/base/nvram.lua`、`rules_examples/base/fdmap.lua`
  - 引擎：`linux-user/syscall.c`（`c_open_host` + `get_syscall_name` 补齐 `execveat`）

#### 1.3.1 ASUS `httpd` 的 `http_enable` 语义（易踩坑）

- 现象（批量高频）：`httpd` 完成 SSL/NVRAM 初始化并写入 `/var/run/httpd.pid`，但始终不 `listen()`，`ss -lntp` 为空；
  日志中可观测到 `select(nfds=0)` 周期性返回（60s timeout 或 timeout==NULL），看起来像“卡住/死循环”。
- 根因：部分 ASUS 固件里 `http_enable` 的语义是 **0=启用，1=禁用**。若默认给成 `1`，`httpd` 会跳过 `bind()/listen()` 分支，
  最终进入 “nfds=0 的 select 等待” 分支（不会对外提供服务）。
- 修复（通用）：`rules_examples/base/nvram.lua` 将默认 `http_enable` 改为 `"0"`（启用 HTTP）。

### 1.4 /dev/log 缺失（syslog socket）

- 现象：`connect("/dev/log") = -ENOENT`，部分固件会因此异常退出。
- 策略：fakefile 提供最小可用的 UNIX socket 行为或忽略连接失败（保持程序前进）。
- 文件：`rules_examples/syscall/connect.lua`、`rules_examples/plugins/fakefile/init.lua`

### 1.5 网络接口枚举差异（/proc/net/dev 等）

- 现象：`if_nameindex()` 等路径依赖 `/proc/net/dev`、`/sys/class/net`；在容器/仿真环境下可能缺失/不可读。
- 策略：对“接口枚举类路径”做窄匹配修复（必要时返回空/ENOENT 触发固件 fallback）。
- 文件：默认可通过固件 `rules_examples/syscall_override_user/` 放置；通用版本视批次结果再上收。

### 1.6 规则优先级与遗留 override（批量跑必踩）

- 现象：数据集里的 rootfs 可能残留历史 `rules_examples/syscall_override/*`（旧 AI 规则）。  
  由于 `entry.lua` 默认优先加载 `syscall_override_user:syscall_override`，这些遗留文件会覆盖基线 `syscall/*`，表现为：
  - 关键基线规则“不生效”（例如 `open/openat` 看不到 `[open.target]`、`intercepted=false`）
  - 依赖 fd 跟踪的规则（如 `/dev/nvram`）无法命中，可能导致崩溃或服务不启动
- 策略（推荐）：批量注入时在 `rules_examples/config/env` 固定：
  - `SFEMU_RULES_OVERRIDE_DIR=syscall_override_user`
  - 需要 AI 临时规则时，再显式设置为：`syscall_override_user:syscall_override`
- 备选：注入阶段清理 rootfs 的 `rules_examples/syscall_override/`（保留 `syscall_override_user/`）。

### 1.7 监控盲区：未映射 syscall（日志突然停止）

- 背景：当前 `linux-user/syscall.c:get_syscall_name()` 是白名单映射，未命中的 syscall 会把 `syscall_name=nil` 传给 Lua。
  默认情况下 `entry.lua/finish.lua` 会跳过这类 syscall，表现为“程序可能还在跑，但日志突然停止”。
- 策略：排障时可在 `rules_examples/config/env` 打开：
  - `SFEMU_LOG_UNKNOWN_SYSCALLS=1`
  - 使未映射 syscall 也会以 `sys_<num>` 的形式进入 entry/finish 流程（仅观测，不做规则加载/AI 修复）。

### 1.8 Web UI 全 404：httpd 的 webroot 依赖 cwd

- 现象：`curl http://127.0.0.1/` 有回包（常见是内置 CGI 返回 JS 重定向），但访问任何静态资源/页面都 404：
  - `/QIS_wizard.htm`、`/images/*`、`/*.css`、`/*.js`、`/*.asp` 等
- 原因：不少固件（尤其 ASUS 的 `httpd/2.0`）会把“当前工作目录”当作 web 根目录，并用相对路径打开资源。
  如果我们在 `/` 启动它，而真正的 webroot 在 `/www`，就会出现“根路径能返回但所有文件 404”的假成功。
- 策略：启动时把 cwd 切到 webroot（优先 `/www`），同时用绝对路径运行 `qemu-arm` 并保持 `-L` 指向固件根。
  - 批量脚本已内置：`lab/run_batch_001.sh` 会在生成的 `start.sh` 里自动选择 webroot（也可用 `SFEMU_WEBROOT` 覆盖）。

### 1.9 exec 系列 syscall 观测（仅打印命令行）

- 目标：排障时快速看到固件在 `execve/execveat` 里到底拉起了哪些脚本/辅助程序（例如 `gencert.sh`、`openssl`、`rc` 等），不改变行为。
- 文件：
  - `rules_examples/syscall/execve.lua`
  - `rules_examples/syscall/execveat.lua`
  - 规则行为：仅打印 `[execve] ...` / `[execveat] ...`，随后 `return 0,0` 放行原始 syscall。

## 2. 规则收敛方法（每 10 个固件执行一次）

1. 统计失败原因 TopN（ENOENT/EINVAL/EPROTONOSUPPORT…）与高频路径（cert.pem、nvram、/var/run…）
2. 判断是否“可通用”：
   - 仅依赖 syscall 参数与少量路径特征（不含固件绝对路径、不含硬编码 pid/地址）→ 可上收为默认规则
   - 与具体型号强绑定（私有 ioctl、特定配置文件语义）→ 留在固件 `syscall_override_user`
3. 写入本文件新增条目，并在 `do.md` 记录“为什么上收/为什么不上收”。
