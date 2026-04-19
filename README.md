# 某云电脑保活客户端 (C语言版)

自动登录某云电脑平台，获取桌面列表，对运行中的桌面建立WebSocket保活连接，对未运行的桌面定时检测状态，开机后自动切换为保活模式。

## 致谢

感谢 [Amamiyashi0n/ctyun_keepalive](https://github.com/Amamiyashi0n/ctyun_keepalive) 提供的 Python 版本实现，本项目在此基础上用 C 语言进行了重构，以获得更低的系统资源占用和更好的自运行能力。

## 平台支持

当前版本仅支持 **Windows** 平台运行，依赖 WinHTTP、Winsock2、CryptoAPI、CNG 等 Windows 系统库。

## 功能特性

- 自动登录某云电脑（支持验证码OCR识别）
- 加密存储用户凭据到 config.json（ChaCha20-Poly1305 AEAD）
- 对运行中桌面建立WebSocket保活连接
- 对未运行桌面每3分钟检测状态，开机后自动保活
- 极低内存占用（保活阶段约 5MB）
- 支持后台运行模式

## 后台运行

添加 `--background` 或 `-b` 选项，程序在进入保活阶段后自动切换到后台运行，日志写入 `run.log` 文件：

```bash
# 前台运行
ctyun_keepalive.exe

# 后台运行
ctyun_keepalive.exe --background
ctyun_keepalive.exe -b
```

日志文件特性：
- 每次启动时清空 `run.log`
- 文件超过 1MB 时自动截断，保留末尾 512KB

## 编译说明

### 环境要求

- Windows 10/11
- Visual Studio 2019+ (需安装 C/C++ 桌面开发工作负载)
- Windows SDK 10.0.26100.0+

### 编译命令 (MSVC x64)

打开"x64 Native Tools Command Prompt"，执行：

```batch
cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS ctyun_keepalive.c ^
   /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF ^
   winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib
```

### 极限优化编译（更小体积）

```batch
cl /O2 /MD /GS- /DNDEBUG /DWIN32 /D_CRT_SECURE_NO_WARNINGS ctyun_keepalive.c ^
   /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF ^
   /MERGE:.rdata=.text /SECTION:.text,ER ^
   /NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib ^
   /NODEFAULTLIB:libvcruntime.lib /DEFAULTLIB:vcruntime.lib ^
   shell32.lib advapi32.lib winhttp.lib ws2_32.lib crypt32.lib iphlpapi.lib bcrypt.lib ^
   kernel32.lib user32.lib msvcrt.lib
```

## 内存优化说明

| 优化项 | 说明 |
|--------|------|
| Desktop 动态指针 | 证书等字段改为 char*，保活阶段 free() 真正释放物理内存 |
| DesktopLight 轻量结构 | 状态轮询使用 132 字节轻量结构，减少内存占用 |
| connect_msg 精确分配 | 按需计算大小，替代固定 12KB 缓冲区 |
| ws_uri 预构建 | 保活阶段释放 host/port/clink_host |
| trim_working_set | 定期将物理内存页归还操作系统 |
| 线程栈缩小 | 128KB 栈替代默认 1MB |

## 首次使用

1. 运行程序，输入某云电脑的账户和密码
2. 程序自动加密保存凭据到 `config.json`
3. 后续运行自动读取 `config.json` 登录，无需重复输入

## License

Apache License 2.0
