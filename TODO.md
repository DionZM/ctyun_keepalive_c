# TODO - eaichat AI对话功能 待办事项

## 当前状态

eaichat AI对话功能已**功能完整并实测通过**：账密登录 → 换 ticket → 派生 sk → 签名 → 发消息 → 收到 AI 回复。

实测日志（2026-06-18）：
```
[eaichat] cas/login status=302
[eaichat] 登录成功，sk=c51fb9c1e95c4575...
[eaichat] 收到回复(24字符): 《肖申克的救赎》
```

## [临时方案] cas/login 调用系统 curl.exe

### 问题

`cas/login` 请求的 URL 形如：
```
https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/cas/login?service=https%3A%2F%2Feaichat.ctyun.cn%3A443%2Fchat%2F%23%2Faichat
```

其 query 参数 `service` 的值里含 `https://`，其中的 `//` 会触发 **WinHTTP 的 URL 规范化**：WinHTTP 把 query 里的 `//` 当作路径分隔符，把整条请求路径破坏成 `/cloudB/dy/iam/`，导致服务端返回登录页 HTML 而非 302+ticket。

实测：同样 URL + cookie，Python 的 requests/http.client、系统 curl.exe 都能正确返回 302，唯独 WinHTTP（无论用哪个 flag、怎么 URL 编码）都会截断路径。这是 WinHTTP 的已知行为，`http_req` / `http_get_via_curl` 之外的 WinHTTP 调用都受影响——只是保活程序的其他 URL 都没在 query 里出现 `//`，所以没暴露。

### 临时方案

`http_get_via_curl()`（`ctyun_keepalive.c` 约 1308 行）用 `CreateProcess` 启动系统 `curl.exe`（Windows 10 1803+ / Windows 11 自带，Schannel 版），`curl -s -i -k` 输出响应头到 stdout，从中解析 `Location:` 提取 ticket。

**仅 cas/login 这一个请求**用 curl.exe，其他请求（iam/login、ticketAuthorize、chat/completions）仍用项目原有的 WinHTTP（它们的 URL 不含 `//`，不受影响）。

### 该临时方案的风险/局限

1. **依赖系统 curl.exe**：Windows 10 1803 (2018年4月) 起自带，绝大多数用户机器都有。但：
   - 旧版 Windows（Win10 1803 之前、未更新过的 Win10）可能没有 → cas/login 失败，对话功能不可用，但不影响保活主功能
   - 部分精简版/企业定制版系统可能裁剪了 curl.exe
2. **可观测性差**：通过子进程调用，错误诊断不如直接 API 调用清晰
3. **进程开销**：每次登录启动一个 curl 进程（登录不频繁，开销可忽略）

### 长期改进方案（按推荐度排序）

#### 方案 1：libcurl 静态链接（推荐）
- 用 vcpkg / msys2 安装 libcurl，静态链接进 exe
- 把 `http_get_via_curl` 改为调用 libcurl API（`curl_easy_*`）
- 优点：进程内调用、无外部依赖、可移植性最好、能复用 cookie/连接
- 缺点：增加约 300KB 体积，需配置构建依赖
- 改动：build.bat 加 `libcurl.lib`，新增 `curl_easy_init/perform/cleanup` 代码

#### 方案 2：WinHTTP 的替代 URL 构造方式
- 探索 WinHTTP 是否有禁用 URL 规范化的选项（如 `WinHttpCreateUrl` + 特定 flag）
- 或把 service 参数的值换成不含 `//` 的形式（需确认服务端是否接受）
- 优点：无新依赖
- 缺点：不确定能否成功，WinHTTP 行为较难绕过

#### 方案 3：保留 curl.exe 但加降级 + 检测
- 启动时检测 curl.exe 是否存在（`where curl`）
- 不存在时给出明确提示，或回退到其他方案
- 作为短期稳定性增强

## 其他已知限制

### eaichat 登录凭据复用（已优化）
- 对话线程与保活**复用同一套账号密码**，用户无需为对话功能重复输入
- 实现方式：`resolve_credentials` 通过 out 参数输出**账号明文 + 密码 SHA256 哈希**，对话线程（`ChatParam`）只持有这两样
- 安全设计：**只存 SHA256 哈希，不存明文密码**。eaichat 登录只需 `SHA256(明文)`（POST 的 password 字段），明文密码在算完哈希后立即清零，不长期驻留内存
- 隐私模式 `/p` 下也能复用：明文密码经 `resolve_credentials` 算完 SHA256 输出后即清零，对话线程凭哈希登录，全程不留明文
- 回退路径：极少数情况下（`resolve_credentials` 未输出）才从 config.json 解密复用

### 会话有效期
- YL-Token / sk 有效期约 7 天
- 当前每次启动重新登录（cookie 不持久化）
- 改进点：可复用 config.json 加密机制持久化 chat cookie/sk/clientKey，避免频繁登录

### clientKey 持久化
- 当前每次启动 `gen_client_key` 生成新的随机 clientKey
- 改进点：可持久化到 config.json，登录更稳定（同一 clientKey 服务端可能更易识别）

### 对话线程的每日调度
- 每天首次启动后随机延迟 1-60 分钟发一条预设消息
- 用 `last_sent_date` 避免重启后当天重复发送
- 未持久化 `last_sent_date`，重启后当天会重新发（但有随机延迟，不会立即发）

## 测试覆盖情况

- [x] 编译通过（MinGW gcc）
- [x] `/chatnow` 立即发一条消息，收到 AI 回复
- [x] 登录链路完整（iam/login → cas/login → ticketAuthorize → sk）
- [x] 签名验证（与抓包数据数学一致）
- [x] AES/RSA 加解密验证
- [ ] 常驻运行 24h 验证每日定时触发
- [ ] cookie 过期后自动重登
- [ ] 与保活线程并行无死锁（需长时运行验证）
- [ ] 不加 `/chat` 时行为与原版完全一致（回归）
- [ ] MSVC `build.bat` 编译验证（当前用 MinGW）
