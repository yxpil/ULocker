# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-03

首个版本。

### 加密与格式

- `.ulocker` 容器格式 v1，字节级规范见 [docs/FORMAT.md](docs/FORMAT.md)
- 信封加密：Argon2id（默认 64 MiB / 3 轮）或 scrypt 派生 KEK，KEK 只用来包裹
  随机的 `data_key`，数据区由 `data_key` 加密
- 数据区按 1 MiB 分块，每块独立随机 nonce，AAD 为 `chunk_id ‖ 分块序号`，
  块无法跨文件搬移、无法调换顺序
- 头部从第 0 字节到索引密文之前的全部内容参与 AEAD 认证，头部任意篡改都会
  导致解密失败
- 每个条目记录明文 SHA-256，解包时校验
- 索引经 zlib 压缩后加密，文件名与目录结构不泄漏

### 功能

- `new` / `add` / `list` / `extract` / `del` / `passwd` / `verify` / `info` /
  `drives` / `find` / `shred` / `gui` 共 12 个子命令
- U 盘绑定：按卷序列号锁定容器，换盘拒绝打开，`--ignore-drive-binding` 可强制
- 改口令只重新包裹 `data_key`，数据区不动，秒级完成
- `--shred-source`：加密后覆写并删除源文件
- 只读介质（写保护的 U 盘）上自动降级为只读打开，仍可查看与解包

### 界面

- PyQt6 图形界面：磁盘选择、容器列表、条目表格、实时进度、操作日志、
  文件拖放、后台线程执行

### 工程

- Windows 磁盘识别通过 ctypes 调用 `kernel32`，不依赖 pywin32 / psutil
- 解包时拒绝绝对路径、目录穿越与 Windows 保留设备名
- 176 个测试，覆盖分块边界、篡改检测、目录穿越、追加回滚、改口令与绑定校验
- `ULocker.spec` + `scripts/build_exe.py` 一键打包单文件 exe

### 已知限制

- 闪存介质上的 `shred` 无法保证物理块被覆盖，不是取证级安全擦除
- 容器整体大小会暴露明文总量；分块固定 1 MiB，单个文件大小可被大致推算
- 卷序列号不是硬件防篡改的标识
- 不支持增量同步，`add` 是整目录重新收集后追加
