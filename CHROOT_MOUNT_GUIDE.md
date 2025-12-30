# Chroot 环境挂载指南

## 问题
在 chroot 环境中运行程序时，需要挂载 `/proc`、`/dev`、`/sys`、`/tmp` 等特殊文件系统。

## 快速使用

### 方法 1: 使用脚本（推荐）

```bash
# 1. 给脚本添加执行权限
chmod +x mount_and_chroot.sh

# 2. 运行脚本（会自动挂载、chroot 并在退出时清理）
sudo ./mount_and_chroot.sh

# 脚本会自动进入 chroot 环境并运行 qemu-arm
```

### 方法 2: 手动挂载

```bash
# 1. 挂载文件系统
cd /rootfs
sudo mount -t proc proc ./proc
sudo mount -o bind /dev ./dev
sudo mount -o bind /dev/pts ./dev/pts
sudo mount -t sysfs sysfs ./sys
sudo mount -t tmpfs tmpfs ./tmp

# 2. 进入 chroot
sudo chroot . ./qemu-arm -L ./ -rules ./rules_examples ./bin/sh

# 3. 退出后卸载（重要！）
sudo umount ./tmp
sudo umount ./sys
sudo umount ./dev/pts
sudo umount ./dev
sudo umount ./proc
```

### 方法 3: 使用快速脚本

```bash
# 挂载
chmod +x quick_mount.sh
sudo ./quick_mount.sh

# 手动 chroot
cd /rootfs
sudo chroot . ./qemu-arm -L ./ -rules ./rules_examples ./bin/sh

# 退出后卸载
sudo ../umount_all.sh
```

## 各挂载点说明

| 挂载点 | 类型 | 说明 |
|--------|------|------|
| `/proc` | proc | 进程信息文件系统 |
| `/dev` | bind | 设备文件 |
| `/dev/pts` | bind | 伪终端 |
| `/sys` | sysfs | 系统信息文件系统 |
| `/tmp` | tmpfs | 临时文件（内存文件系统）|

## 检查挂载状态

```bash
# 查看当前挂载
mount | grep rootfs

# 或者
df -h | grep rootfs
```

## 常见问题

### 1. "mount point does not exist"
确保目标目录存在：
```bash
mkdir -p /rootfs/{proc,dev,sys,tmp,dev/pts}
```

### 2. "device is busy" 无法卸载
查找使用该挂载点的进程：
```bash
lsof | grep /rootfs
fuser -v /rootfs/proc
```

强制卸载：
```bash
umount -l /rootfs/proc  # lazy umount
```

### 3. Permission denied
确保以 root 运行：
```bash
sudo -i
# 然后运行挂载命令
```

## 在 Docker 容器中

如果在 Docker 容器中，可能需要特权模式：

```bash
docker run --privileged -it your_image
```

或者使用 `--cap-add SYS_ADMIN`：

```bash
docker run --cap-add SYS_ADMIN -it your_image
```

## 自动化示例

```bash
#!/bin/bash
# 完整的自动化流程

ROOTFS="/rootfs"

# 挂载
mount -t proc proc ${ROOTFS}/proc
mount -o bind /dev ${ROOTFS}/dev
mount -o bind /dev/pts ${ROOTFS}/dev/pts
mount -t sysfs sysfs ${ROOTFS}/sys
mount -t tmpfs tmpfs ${ROOTFS}/tmp

# 进入 chroot 并执行命令
chroot ${ROOTFS} /bin/sh -c "
    ./qemu-arm -L ./ -rules ./rules_examples ./bin/httpd &
    sleep 5
    # 测试
    wget -O- http://localhost:80
"

# 清理
umount ${ROOTFS}/tmp
umount ${ROOTFS}/sys
umount ${ROOTFS}/dev/pts
umount ${ROOTFS}/dev
umount ${ROOTFS}/proc
```

## 注意事项

1. ⚠️ **必须使用 root 权限**挂载文件系统
2. ⚠️ **退出时记得卸载**，避免系统资源占用
3. ⚠️ 在 Docker 中可能需要特权模式
4. ✅ 使用 `mount_and_chroot.sh` 脚本可以自动处理清理
5. ✅ 脚本包含 trap 清理，Ctrl+C 退出也会自动卸载
