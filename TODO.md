# TODO - eaichat AI对话功能 待办事项

## 当前状态

eaichat AI对话功能已**功能完整并实测通过**：账密登录 → 换 ticket → 派生 sk → 签名 → 发消息 → 收到 AI 回复。

实测日志（2026-06-18）：
```
[eaichat] cas/login status=302
[eaichat] 登录成功，sk=c51fb9c1e95c4575...
[eaichat] 收到回复(24字符): 《肖申克的救赎》
```

## [已解决] cas/login WinHTTP 方案 2（单斜杠 service）

### 问题

`cas/login` 请求的 URL 形如：
```
https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/cas/login?service=https%3A%2F%2Feaichat.ctyun.cn%3A443%2Fchat%2F%23%2Faichat
```

其 query 参数 `service` 的值里含 `https://`，其中的 `//` 会触发 **WinHTTP 的 URL 规范化**：WinHTTP 把 query 里的 `//` 当作路径分隔符，把整条请求路径破坏成 `/cloudB/dy/iam/`，导致服务端返回登录页 HTML 而非 302+ticket。

### 方案 2 实现

把 `service` 参数的值改成不含连续双斜杠的形式，服务端仍能识别并返回 302：
```
https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/cas/login?service=https:/eaichat.ctyun.cn:443/chat/%23/aichat
```

新增 `http_get_with_winhttp()`（`ctyun_keepalive.c`），用 WinHTTP 直接发起该 GET 请求并提取 `Location` 头。`cas/login` 现在**优先走 WinHTTP 方案 2**；若未拿到 302 再回退到原 `curl.exe` 方案，作为安全网。

### 验证结果（2026-06-22）

- MSVC `build.bat` 编译通过
- 实机运行 `/chatnow`：
  - `[eaichat] cas/login 尝试 WinHTTP 方案 2(单斜杠 service)...`
  - `[eaichat] cas/login status=302`
  - `[eaichat] 获取ticket成功(240字符)`
  - `[eaichat] 登录成功，sk=...`
  - `[eaichat] 收到回复(356字符): 今天（2026年6月22日）北京白天晴转多云...`
- 完整链路（iam/login → cas/login → ticketAuthorize → sk → chat/completions）实测通过

### 该方案的优势/注意

- **无外部依赖**：不再依赖系统 `curl.exe`（回退逻辑仍保留，但主路径已不使用）
- **无新增体积**：继续使用 WinHTTP，无需 libcurl
- **服务端兼容性**：当前服务端会把 `https:/host` 规范化回 `https://host` 再匹配；若未来服务端收紧严格匹配，可能需要重新评估

### 历史临时方案（curl.exe）

`http_get_via_curl()` 仍保留在代码中作为降级：当 WinHTTP 方案 2 失败时，使用原双斜杠 URL 调用系统 `curl.exe` 获取 302。保留原因：单斜杠 service 的兼容性取决于服务端行为，保留降级可避免突然失效。

### 其他长期改进方案（已降为备选）

#### 方案 1：libcurl 静态链接
- 用 vcpkg / msys2 安装 libcurl，静态链接进 exe
- 把 `http_get_via_curl` 改为调用 libcurl API（`curl_easy_*`）
- 优点：进程内调用、无外部依赖、可移植性最好、能复用 cookie/连接
- 缺点：增加约 300KB 体积，需配置构建依赖
- 当前状态：方案 2 已可用，暂不需要

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
