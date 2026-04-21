# 天翼云电脑保活客户端 (C语言版)

如题。

为尽可能低占用系统资源，尽管已有rust版本，还是用了C语言重构。

## 致谢

感谢 [Amamiyashi0n/ctyun\_keepalive](https://github.com/Amamiyashi0n/ctyun_keepalive) 提供的 Python 版本实现，本项目在此基础上用 C 语言进行了重构，再添加特性。

OCR接口直接照搬原脚本，根据github记录，有可能是@leleji提供的服务（如果不是请在issue里提醒我），对大神无私提供的api服务表示表示感谢！

## 平台支持

当前版本仅支持 **Windows** 平台运行，依赖 WinHTTP、Winsock2、CryptoAPI、CNG、WIC 等 Windows 系统库。

## 功能特性

- 自动登录天翼云电脑
- 验证码识别失败后支持手工输入
- 加密存储用户凭据
- 动态监控未运行主机
- 极低内存占用（保活阶段约 5MB）
- 支持后台运行模式
- 支持隐私模式（不保存用户名/密码）

## 验证码处理机制

程序采用 **自动识别 + 手工回退** 的验证码处理策略：

1. **自动识别**
2. **手工输入触发条件**（满足任一即触发）：
   - 识别接口连接失败
   - 识别接口返回错误响应
   - 连续3次自动识别验证失败
3. **手工输入模式**：
   - 前台弹出验证码图片窗口
   - 命令行输出提示："验证码自动识别失败，请手工输入："
   - 用户输入后自动关闭窗口
4. **失败退出**：手工输入连续3次失败，输出"验证码识别错误"并退出程序

## 命令行参数

```
ctyun_keepalive.exe [OPTIONS]

OPTIONS:
  /background, /b  后台运行，日志写入run.log
  /privacy,    /p  隐私模式，不保存用户名/密码到config.json
  /random,     /r  随机生成设备码(默认基于机器指纹生成唯一的设备码，以避免重复短信验证)
  /version,    /v  显示版本号
  /help,       /h  显示帮助信息
```

运行中操作：

- `Ctrl+C` — 退出程序
- `Ctrl+B` — 转后台运行

## 后台运行

添加 `/background` 或 `/b` 选项，程序在进入保活阶段后自动切换到后台运行，或者可在运行过程中，通过按Ctrl+B转后台运行，日志写入 `run.log` 文件：

```bash
ctyun_keepalive.exe /b
```

日志文件特性：

- 每次启动时清空 `run.log`
- 文件超过 1MB 时自动截断，保留末尾 512KB

## 隐私说明

第一次成功登录后，程序会将用户名、密码等相关信息加密保存到 `config.json` 文件中。`config.json` 中的数据经过 ChaCha20-Poly1305 AEAD 加密，并非明文存储，但由于加密算法不是不对称的强加密算法，用户仍需保护好自己的 `config.json` 文件，避免密码泄露。

如果不想程序保存用户名/密码信息，请使用 `/privacy` 或 `/p` 参数启用隐私模式：

```bash
ctyun_keepalive.exe /privacy
ctyun_keepalive.exe /p
```

隐私模式下，程序不会将凭据写入 `config.json`，每次运行都需要手动输入账户和密码。

## 编译说明

### 环境要求

- Windows 10/11
- Visual Studio 2019+ (需安装 C/C++ 桌面开发工作负载)
- Windows SDK 10.0.26100.0+

### 编译命令 (MSVC x64)

<br />

```batch
cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ctyun_keepalive.c ^
   /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG ^
   winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib
```

<br />

### 输出到bin目录

```batch
mkdir bin 2>nul
cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL /Fo"bin\ctyun_keepalive.obj" ctyun_keepalive.c ^
   /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG /OUT:"bin\ctyun_keepalive.exe" ^
   winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib
```

## 首次使用

1. 运行程序，输入天翼云电脑的账户和密码
2. 程序自动加密保存凭据到 `config.json`
3. 后续运行自动读取 `config.json` 登录，无需重复输入

## License

Apache License 2.0
