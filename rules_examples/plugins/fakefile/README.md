# fakefile - 缺失文件资源补全框架（Lua 规则）

## 目标

在 QEMU-user 的 syscall Lua 预拦截中，当目标程序访问到缺失的文件/设备/Unix socket 时，自动生成并接管这些资源的行为，避免因为 `ENOENT` 等错误导致固件单服务仿真中断。

## 三件套约定

对“真实路径”`<path>`（例如 `/tmp/test.config`）约定生成：

1. `<path>.fakefile`
   - **元数据文件**（纯文本），默认写入：类型、状态、真实路径、fakeconfig/fakecontent 位置、最近一次 open 的 pid/fd 等。
   - 位置：与 `<path>` 同目录（例如 `/tmp/test.config.fakefile`）。

2. `*.fakecontent`
   - **实际内容文件**（可按状态/规则读取），用于为 read 提供可控内容来源。
   - 位置：`rules_examples/plugins/fakefile/data/` 下（默认按 basename 命名，必要时带 hash 唯一 key）。

3. `*.fakeconfig.lua`
   - **行为/状态定义**：按 state 分发 `open/read/write/ioctl/connect` 行为。
   - 位置：`rules_examples/plugins/fakefile/config/` 下（同上命名规则）。

## 入口与接入点

本仓库已将 fakefile 接入以下 syscall hook（对应同名 `.lua` 文件）：

- `open.lua` / `openat.lua`：缺失文件自动初始化并打开 fakefile
- `read.lua` / `write.lua`：对 fake fd 进行内容注入/丢弃写入
- `ioctl.lua`：对 fake fd 优先处理（未命中则继续网络 ioctl 模拟）
- `connect.lua`：Unix domain socket 缺失时将 fd 交由 fakefile 托管（不创建真实 socket 文件）
- `close.lua`：清理 fake fd 映射，避免 fd 复用误判
- `lseek.lua`：同步 fake fd 的 offset（便于按偏移读取 fakecontent）

## 默认规则（rules_examples/plugins/fakefile/default/*.fakeconfig.lua）

- `text.fakeconfig.lua`（文本/普通文件）
  - `open`：返回 fakefile fd
  - `read`：永远返回 0（EOF）
  - `write`：丢弃写入但返回 `count`
- `dev.fakeconfig.lua`（/dev 下设备文件）
  - 同上，并额外 `ioctl` 返回 0
- `socket.fakeconfig.lua`（Unix domain socket）
  - `connect`：默认不创建 server，而是把 `sockfd` 交给 fakefile 托管并返回成功（便于后续 `write/read` 被拦截）
  - 如需旧行为（创建 server 并让 client 真正 connect），可在自定义 fakeconfig 中改用 `fakefile.default_connect_socket_server(ctx)`

## 自定义 fakeconfig（示例）

你可以在 `rules_examples/plugins/fakefile/config/<name>.fakeconfig.lua` 中覆盖默认行为，例如让 read 返回 fakecontent 的第 0~10 行：

```lua
local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("plugins/fakefile/config/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")

return {
  default_state = "init",
  states = {
    init = {
      open = function(ctx)
        return fakefile.default_open(ctx)
      end,
      read = function(ctx)
        local data = fakefile.read_fakecontent_lines(ctx.record.content_path, 0, 10)
        return fakefile.reply_read_bytes(ctx, data or "")
      end,
      write = function(ctx)
        return fakefile.default_write_discard(ctx)
      end,
    }
  }
}
```

## 注意事项

- fakefile 的实现依赖 `close.lua` 清理 fd 映射；如果你在自定义 rules 目录中漏拷贝它，fd 复用可能导致误判。
- `openat` 仅对 **绝对路径** 或 `dirfd == AT_FDCWD` 的场景启用 fakefile（相对路径+dirfd 的真实目录无法在纯 Lua 中可靠解析）。
- socket 默认规则的目标是“让 connect 走通”，并不保证业务协议可用；需要协议交互时建议在 fakeconfig 中扩展（例如对 send/recv 做进一步 hook）。
