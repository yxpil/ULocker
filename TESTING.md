# ULocker 测试说明
- 测试完成：是（2026-10-04）
- 测试日期：2026-10-04
- 测试内容：单元测试覆盖 crypto 层（Argon2id/scrypt 派生、HKDF、AES-256-GCM 加解密、篡改/错误 AAD/错误密钥拒绝）、vault 容器全链路（建/开/解/验、分块流、截断篡改检出、重名拒绝、追加回滚、U盘绑定）、util（条目名规范化与穿越拒绝、containment、安全擦除）、drives、CLI 子命令端到端、PyQt6 GUI 信号与进度回调；注入测试覆盖路径穿越（../、绝对路径、盘符、UNC、NUL、Windows 保留设备名、混用反斜杠）与分块密码层攻击（块重排、跨文件密文移植、翻转字节均被 GCM/verify 检出）；钩子测试验证 progress 回调按序触发、回调抛异常被 `_Progress` 隔离不破坏主流程。涉及模块：ulocker/crypto、vault、util、drives、cli、gui。
- 运行命令：python -m pytest tests/ -v（QT_QPA_PLATFORM=offscreen）
- 测试框架：pytest（PyQt6 offscreen）
- 模型：豆包（Doubao）生成

## 运行方式

```powershell
# 在仓库根目录（已 pip install -e . 或至少装好 cryptography / argon2-cffi / pytest）
python -m pytest tests/ -v
```

GUI 相关测试在无显示器环境自动走 offscreen 平台：

```powershell
$env:QT_QPA_PLATFORM = "offscreen"; python -m pytest tests/ -v
```

- 预期：**199 passed**（Python 3.14 / Windows）。
- `tests/conftest.py` 里把 Argon2id / scrypt 调到了极低参数（16 KiB / 1 轮），
  整套测试几百毫秒跑完；生产默认参数见 `ulocker/crypto.py`。

## 覆盖了什么

| 文件 | 覆盖点 |
| --- | --- |
| `test_crypto.py` | Argon2id/scrypt 派生确定性、不同盐/口令隔离、未知 KDF 拒绝、HKDF 域分离、AES-256-GCM 加解密、篡改密文/错误 AAD/错误密钥被拒、base64 与随机数 |
| `test_vault.py` | 建/开/解/验容器全链路、分块流、mtime 保留、空口令拒绝、错误口令、截断/篡改头部与索引、数据篡改检出、重名源拒绝、追加/回滚/压缩删除、改名、改密、U盘绑定、只读容器 |
| `test_util.py` | 体积格式化、对齐、表格宽度、条目名规范化与穿越拒绝、解包 containment、重名避让、安全擦除、魔数识别 |
| `test_drives.py` | 盘符匹配、绑定/解绑、列出盘符、递归查找容器 |
| `test_cli.py` | CLI 各子命令端到端（new/list/add/del/extract/verify/passwd/info/shred） |
| `test_gui.py` | PyQt6 GUI 窗口状态、信号转发、进度回调、文件句柄释放 |
| `test_hooks_progress.py` | **回调（钩子）机制**：进度回调按序收到 `(done,total,label)`、done 单调递增；**回调抛异常被 `_Progress` 包装层隔离**——create/extract/verify/add 全部照常完成且数据完好；`progress=None` 正常 |
| `test_injection_extra.py` | **注入测试**：NUL 字节、Windows 保留设备名（CON/NUL/COM1/LPT1/PRN/AUX）、尾部点、UNC、混用反斜杠的 `..` 穿越均被 `safe_relative_name` 拒绝；**分块密码层攻击**：块重排、跨文件密文块移植、翻转单个密文字节，均被 GCM 认证 / `verify()` 检出 |

## 注入与钩子测试说明

- **路径穿越注入**：容器条目名可能来自不可信的源文件/索引。`safe_relative_name`
  是唯一防线，测试覆盖 `../`、`a/../b`、绝对路径、驱动器号、UNC、NUL、保留字等
  向量，断言它们抛出 `PathSafetyError` 而不是被拼进解包路径。
- **分块 AAD 攻击**：每块 AAD = `chunk_id || 块序号`。测试手动改写容器文件，
  把第二块密文挪到第一块位置（重排）、把另一文件的密文块贴进来（移植），
  断言解包抛出 `IntegrityError`——证明攻击者既不能重排块、也不能跨文件移植块。
- **钩子失败隔离**：`progress` 回调相当于用户可挂的钩子。`_Progress` 吞掉回调内
  异常，测试用"每次回调都抛 RuntimeError"的钩子跑完整建/解包流程，断言容器内容
  与原始字节一致——一个坏掉的钩子不会影响其它工作。
