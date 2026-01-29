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

- 现象：`/dev/nvram` 打开/`ioctl` 返回 `EINVAL/ENOTTY`，导致配置读取失败。
- 策略：使用 fakefile + ioctl 兼容（按需扩展具体 ioctl 编号与结构体）。
- 文件：`rules_examples/plugins/fakefile/init.lua`、`rules_examples/syscall/ioctl.lua`（以及固件侧 override 如需要）

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

## 2. 规则收敛方法（每 10 个固件执行一次）

1. 统计失败原因 TopN（ENOENT/EINVAL/EPROTONOSUPPORT…）与高频路径（cert.pem、nvram、/var/run…）
2. 判断是否“可通用”：
   - 仅依赖 syscall 参数与少量路径特征（不含固件绝对路径、不含硬编码 pid/地址）→ 可上收为默认规则
   - 与具体型号强绑定（私有 ioctl、特定配置文件语义）→ 留在固件 `syscall_override_user`
3. 写入本文件新增条目，并在 `do.md` 记录“为什么上收/为什么不上收”。
