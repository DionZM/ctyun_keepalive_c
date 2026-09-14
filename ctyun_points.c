/*
 * ctyun_points.c - 天翼云电脑积分挂机程序 (C语言版) v1.5.0
 *
 * 公共逻辑见 ctyun_common.c / ctyun_common.h；eaichat 每日对话段自
 * ctyun_keepalive 迁入。v1.5.0 起不再自注册计划任务：由常驻的
 * ctyun_keepalive 每日05:00以子进程方式调用本程序(直接运行keepalive即部署)。
 * 本程序带单实例互斥量，重复启动会静默退出，避免同账号重复登录顶号。
 *
 * 编译 (MSVC x64):
 *   cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ^
 *      /DWS_RECV_TIMEOUT_MS=60000 ctyun_common.c ctyun_points.c /Fe:ctyun_points.exe ^
 *      /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG ^
 *      winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib user32.lib shell32.lib
 */

#include "ctyun_common.h"

#define APP_VERSION   "1.5.0"

#define KEEPALIVE_SECONDS  5400
#define WS_POLL_TIMEOUT_MS  300    /* 单通道轮询接收超时(毫秒) */
#define CLINK_HB_MAIN_MS    5000   /* MAIN通道应用层心跳间隔 */
#define CLINK_HB_CHAN_MS    30000  /* DISPLAY/INPUTS通道应用层心跳间隔 */
#define ADAPTIVE_MAX_SECONDS    21600  /* 硬上限6小时: keepalive 05:00拉起 -> 11:00 */
#define TASK_CHECK_INTERVAL_SEC 270
#define TASK_1003_TARGET        3600
#define SESSION_ROTATE_SECONDS  300

static FILE *g_logfp = NULL;
static volatile LONG g_keep_seconds = KEEPALIVE_SECONDS;

/* ---- 自适应挂机(默认) + 会话周期轮换 ----
 * 实测根因(2026-09-12): 服务端只对"新鲜的桌面connect会话"计量使用时长；单条 clink
 *   MAIN 会话长期存活(实测连续12870秒)虽三通道心跳/子通道重连正常，却全程不计1003；
 *   一旦重新 connect 建立新会话，立即按约1:1恢复计分(新会话60秒即计67)。
 *   DISPLAY/INPUTS 子通道45秒被服务端踢除并重连无效，因桌面会话租约(connect token)未更新。
 * 对策: 每 g_session_rotate_secs(默认300秒) 主动整体重连(重新 connect，无需重新登录)，
 *   使每段都处于会计量的新鲜会话；同时每 g_task_check_secs 自查1003，拿满即止。 */
#define ADAPTIVE_MAX_SECONDS    21600  /* 硬上限6小时: keepalive 05:00拉起 -> 11:00 兜底 */
#define TASK_CHECK_INTERVAL_SEC 270    /* 约4.5分钟自查一次任务1003 */
#define TASK_1003_TARGET        3600   /* 任务1003 "使用1小时" 目标秒数 */
#define SESSION_ROTATE_SECONDS  300    /* 单条clink桌面会话最长连续秒数，到点主动整体重连 */
static volatile LONG g_adaptive = 0;            /* 1=自适应模式(默认), 0=固定时长 */
static volatile LONG g_adaptive_max = ADAPTIVE_MAX_SECONDS;
static volatile LONG g_task_check_secs = TASK_CHECK_INTERVAL_SEC;
static volatile LONG g_session_rotate_secs = SESSION_ROTATE_SECONDS;
static volatile LONG g_task_complete = 0;       /* 任务1003 已达标 */

static void log_open(void) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char log_path[MAX_PATH];
    snprintf(log_path, sizeof(log_path), "%s\\points.log", exe_path);
    FILE *f = fopen(log_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fclose(f);
        if (sz > 2 * 1024 * 1024) {
            f = fopen(log_path, "wb");
            if (f) fclose(f);
        }
    }
    g_logfp = fopen(log_path, "a");
}

static void log_line(const char *fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[2048];
    int prefix = _snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] ",
                           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (prefix < 0 || prefix >= (int)sizeof(buf)) prefix = (int)sizeof(buf) - 1;
    va_list ap;
    va_start(ap, fmt);
    int msglen = vsnprintf(buf + prefix, sizeof(buf) - prefix - 2, fmt, ap);
    va_end(ap);
    if (msglen < 0) msglen = 0;
    int total = prefix + msglen;
    if (total > (int)sizeof(buf) - 2) total = (int)sizeof(buf) - 2;
    buf[total++] = '\n';
    buf[total] = 0;

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD bpos = {0, csbi.srWindow.Bottom};
        DWORD written;
        FillConsoleOutputCharacterW(hOut, L' ', csbi.dwSize.X, bpos, &written);
        FillConsoleOutputAttribute(hOut, csbi.wAttributes, csbi.dwSize.X, bpos, &written);
    }
    WCHAR wbuf[2048];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)(sizeof(wbuf) / sizeof(wbuf[0])));
    if (wlen > 0) {
        DWORD written;
        WriteConsoleW(hOut, wbuf, wlen - 1, &written, NULL);
    }
    if (g_logfp) {
        fputs(buf, g_logfp);
        fflush(g_logfp);
    }
}
static int decrypt_credentials_from_json(const char *json, const uint8_t key[32],
                                          char *user, size_t user_sz,
                                          char *pass, size_t pass_sz,
                                          char *device_code, size_t dc_sz) {
    const char *acc = strstr(json, "\"accounts\"");
    if (!acc) return 0;
    acc = strchr(acc, '[');
    if (!acc) return 0;
    const char *obj = strchr(acc, '{');
    if (!obj) return 0;

    char ua[2048], pw[2048], dc[2048];
    jstr(obj, "user_account", ua, sizeof(ua));
    jstr(obj, "password", pw, sizeof(pw));
    jstr(obj, "device_code", dc, sizeof(dc));

    char u[256], p[256], d[256];
    int du = decrypt_data(ua, key, u, sizeof(u));
    int dp = decrypt_data(pw, key, p, sizeof(p));
    int dd = decrypt_data(dc, key, d, sizeof(d));

    if (du && dp && dd) {
        if (user) {
            size_t ulen = strlen(u) < user_sz - 1 ? strlen(u) : user_sz - 1;
            memcpy(user, u, ulen);
            user[ulen] = '\0';
        }
        if (pass) {
            size_t plen = strlen(p) < pass_sz - 1 ? strlen(p) : pass_sz - 1;
            memcpy(pass, p, plen);
            pass[plen] = '\0';
        }
        if (device_code) {
            size_t dlen = strlen(d) < dc_sz - 1 ? strlen(d) : dc_sz - 1;
            memcpy(device_code, d, dlen);
            device_code[dlen] = '\0';
        }
        SecureZeroMemory(p, sizeof(p));
        SecureZeroMemory(u, sizeof(u));
        SecureZeroMemory(d, sizeof(d));
        return 1;
    }
    SecureZeroMemory(p, sizeof(p));
    SecureZeroMemory(u, sizeof(u));
    SecureZeroMemory(d, sizeof(d));
    return 0;
}

static int try_decrypt_config_legacy(const char *content, const char *fp,
                                      char *user, size_t user_sz,
                                      char *pass, size_t pass_sz,
                                      char *device_code, size_t dc_sz) {
    char salt[65];
    jstr(content, "salt", salt, sizeof(salt));
    if (!salt[0]) return 0;
    uint8_t key[32];
    derive_key_legacy(fp, salt, key);
    int r = decrypt_credentials_from_json(content, key, user, user_sz, pass, pass_sz, device_code, dc_sz);
    SecureZeroMemory(key, sizeof(key));
    return r;
}

static int try_decrypt_config_dpapi(const char *content, const char *fp,
                                     char *user, size_t user_sz,
                                     char *pass, size_t pass_sz,
                                     char *device_code, size_t dc_sz) {
    const char *dpapi_start = strstr(content, "\"dpapi\"");
    if (!dpapi_start) return 0;
    dpapi_start += strlen("\"dpapi\"");
    while (*dpapi_start == ' ' || *dpapi_start == ':') dpapi_start++;
    if (*dpapi_start != '"') return 0;
    dpapi_start++;
    const char *dpapi_end = strchr(dpapi_start, '"');
    if (!dpapi_end) return 0;
    size_t dpapi_len = (size_t)(dpapi_end - dpapi_start);

    uint8_t *dpapi_ct = (uint8_t *)malloc(dpapi_len);
    if (!dpapi_ct) return 0;
    size_t dpapi_ct_len = b64dec(dpapi_start, dpapi_len, dpapi_ct);
    if (dpapi_ct_len == 0) { free(dpapi_ct); return 0; }

    uint8_t *inner_data = NULL;
    DWORD inner_len = 0;
    if (!unprotect_data_dpapi(dpapi_ct, (DWORD)dpapi_ct_len, fp, &inner_data, &inner_len)) {
        free(dpapi_ct);
        return 0;
    }
    free(dpapi_ct);

    char *inner_json = (char *)malloc(inner_len + 1);
    if (!inner_json) { LocalFree(inner_data); return 0; }
    memcpy(inner_json, inner_data, inner_len);
    inner_json[inner_len] = '\0';
    LocalFree(inner_data);

    char salt[65];
    jstr(inner_json, "salt", salt, sizeof(salt));
    if (!salt[0]) { free(inner_json); return 0; }

    uint8_t key[32];
    derive_key(fp, salt, key);
    int result = decrypt_credentials_from_json(inner_json, key, user, user_sz, pass, pass_sz, device_code, dc_sz);
    SecureZeroMemory(key, sizeof(key));
    free(inner_json);
    return result;
}

static int try_decrypt_config(const char *content, const char *fp,
                               char *user, size_t user_sz,
                               char *pass, size_t pass_sz,
                               char *device_code, size_t dc_sz) {
    int result = try_decrypt_config_dpapi(content, fp, user, user_sz, pass, pass_sz, device_code, dc_sz);
    if (result != 0) return result;
    return try_decrypt_config_legacy(content, fp, user, user_sz, pass, pass_sz, device_code, dc_sz);
}

static int load_encrypted_credentials(char *user, size_t user_sz, char *pass, size_t pass_sz,
                                       char *device_code, size_t dc_sz) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);
    log_line("尝试加载加密配置文件: %s", config_path);

    FILE *f = fopen(config_path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 1024 * 1024) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *content = (char *)malloc(fsize + 1);
    if (!content) { fclose(f); return 0; }
    size_t clen = fread(content, 1, fsize, f);
    content[clen] = 0;
    fclose(f);

    char fp[65];
    get_fingerprint(fp);

    int dec_result = try_decrypt_config(content, fp, user, user_sz, pass, pass_sz, device_code, dc_sz);
    if (dec_result == 1) {
        log_line("加密配置解密成功 (主指纹)");
        free(content);
        return 1;
    }

    log_line("主指纹解密失败，尝试所有MAC地址...");
    char macs[32][32];
    int nmacs = get_all_macs(macs, 32);
    for (int i = 0; i < nmacs; i++) {
        char alt_fp[65];
        mac_to_fingerprint(macs[i], alt_fp);
        if (strcmp(alt_fp, fp) == 0) continue;
        int r = try_decrypt_config(content, alt_fp, user, user_sz, pass, pass_sz, device_code, dc_sz);
        if (r == 1) {
            log_line("加密配置解密成功 (MAC: %s)", macs[i]);
            free(content);
            return 1;
        }
    }

    free(content);
    log_line("所有指纹均无法解密配置");
    return 0;
}
static void desktop_prepare(Desktop *d) {
    if (!d->connect_msg && d->ca_cert) {
        const char *msg_host = d->host ? d->host : "";
        const char *msg_port = d->port ? d->port : "";
        char clink_h_buf[256] = "", clink_p_buf[32] = "";
        if (d->clink_host && d->clink_host[0]) {
            strncpy(clink_h_buf, d->clink_host, sizeof(clink_h_buf) - 1);
            clink_h_buf[sizeof(clink_h_buf) - 1] = '\0';
            char *colon = strchr(clink_h_buf, ':');
            if (colon) {
                *colon = '\0';
                strncpy(clink_p_buf, colon + 1, sizeof(clink_p_buf) - 1);
                clink_p_buf[sizeof(clink_p_buf) - 1] = '\0';
            } else {
                snprintf(clink_p_buf, sizeof(clink_p_buf), "%s", msg_port);
            }
            msg_host = clink_h_buf;
            msg_port = clink_p_buf;
        }
        size_t need = 256 + strlen(d->ca_cert) + strlen(d->client_cert) + strlen(d->client_key);
        d->connect_msg = (char *)malloc(need);
        if (d->connect_msg) {
            snprintf(d->connect_msg, need,
                     "{\"type\":1,\"ssl\":1,\"host\":\"%s\",\"port\":\"%s\","
                     "\"ca\":\"%s\",\"cert\":\"%s\",\"key\":\"%s\","
                     "\"servername\":\"%s:%s\",\"oqs\":0}",
                     msg_host, msg_port,
                     d->ca_cert, d->client_cert, d->client_key,
                     d->host ? d->host : "", d->port ? d->port : "");
        }
    }
    if (!d->ws_uri && d->host) {
        d->ws_uri = (char *)malloc(512);
        if (d->ws_uri) {
            const char *p_str = (d->port && d->port[0]) ? d->port : "443";
            if (d->clink_host && d->clink_host[0] && strchr(d->clink_host, ':') == NULL)
                snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->clink_host, p_str, d->desktop_id);
            else if (d->clink_host && d->clink_host[0])
                snprintf(d->ws_uri, 512, "wss://%s/clinkProxy/%s/MAIN", d->clink_host, d->desktop_id);
            else
                snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->host, p_str, d->desktop_id);
        }
    }
}
static int api_get_text(const Session *s, const char *url, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("GET", url, NULL, 0, NULL, hdrs, nhdrs, resp, rsz);
}
/* ===================== multi-channel clink support ===================== */

typedef struct {
    WSConn ws;
    int up;
    char name[16];
} ClinkChan;

/* Build the clink HDR (spice link) message by patching the known-good MAIN
 * initial_payload with the target connection_id / channel_type / channel_id. */
static size_t build_hdr_msg(uint8_t *out, uint32_t connection_id,
                            uint8_t channel_type, uint8_t channel_id) {
    memcpy(out, initial_payload, sizeof(initial_payload));
    out[16] = (uint8_t)(connection_id & 0xFF);
    out[17] = (uint8_t)((connection_id >> 8) & 0xFF);
    out[18] = (uint8_t)((connection_id >> 16) & 0xFF);
    out[19] = (uint8_t)((connection_id >> 24) & 0xFF);
    out[20] = channel_type;
    out[21] = channel_id;
    return sizeof(initial_payload);
}

/* CLINK_MSGC_MAIN_ATTACH_CHANNELS (client 104): empty body, 6-byte header only. */
static size_t build_attach_channels_msg(uint8_t *out) {
    out[0] = 104; out[1] = 0;
    out[2] = out[3] = out[4] = out[5] = 0;
    return 6;
}

/* 构造一个无body的clink mini-header消息: [u16 type][u32 size=0]，共6字节。
 * 用于 CLINK_MSGC_HEARTBEAT(7) 等。 */
static size_t build_empty_msg(uint8_t *out, uint16_t type) {
    out[0] = (uint8_t)(type & 0xFF);
    out[1] = (uint8_t)((type >> 8) & 0xFF);
    out[2] = out[3] = out[4] = out[5] = 0;
    return 6;
}

/* 处理在任意通道(MAIN/DISPLAY/INPUTS)上收到的一条完整WebSocket消息：
 *  - REDQ 认证请求 -> 回 Ticket
 *  - clink PING(server type=4) -> 回 PONG(client type=3)，回显body前12字节
 * 其余消息(视频帧/ACK/通知等)忽略。 */
static void clink_on_recv(WSConn *wsc, const char *tag,
                          const uint8_t *buf, size_t total, int is_text) {
    if (is_text) return;
    if (total >= 16 && memcmp(buf, "REDQ", 4) == 0) {
        uint8_t resp[512]; size_t rlen = 0;
        if (handle_redq(buf, total, resp, &rlen)) {
            ws_send_bytes(wsc, resp, rlen);
            log_line("[%s] REDQ认证响应已发送", tag);
        }
        return;
    }
    size_t off = 0;
    while (off + 6 <= total) {
        uint16_t mt = (uint16_t)(buf[off] | (buf[off + 1] << 8));
        int32_t dl = (int32_t)(buf[off+2] | (buf[off+3]<<8) |
                               (buf[off+4]<<16) | (buf[off+5]<<24));
        if (dl < 0 || off + 6 + (size_t)dl > total) break;
        if (mt == 4) {
            /* CLINK_MSG_PING -> CLINK_MSGC_PONG，回显最多12字节body */
            size_t echo = (size_t)dl < 12 ? (size_t)dl : 12;
            uint8_t pong[24];
            pong[0] = 3; pong[1] = 0;
            pong[2] = (uint8_t)(echo & 0xFF);
            pong[3] = (uint8_t)((echo >> 8) & 0xFF);
            pong[4] = (uint8_t)((echo >> 16) & 0xFF);
            pong[5] = (uint8_t)((echo >> 24) & 0xFF);
            if (echo) memcpy(pong + 6, buf + off + 6, echo);
            if (ws_send_bytes(wsc, pong, 6 + echo) == 0)
                log_line("[%s] 收到clink PING，已回PONG(%zuB)", tag, 6 + echo);
        }
        off += 6 + (size_t)dl;
    }
}

/* CLINK_MSGC_MAIN_CLIENT_LOGIN_INFO (112) body (class "ja"):
 *   u32 desktopId
 *   then 4 strings (session token, deviceType, deviceCode, userAccount), each
 *   preceded by (u32 len+1, u32 offset) and stored NUL-terminated in a trailing
 *   blob. The fixed header portion is 36 bytes. */
static size_t build_login_info_msg(Session *s, Desktop *d, uint8_t *out, size_t outsz) {
    const char *tok   = d->token ? d->token : "";
    const char *dtype = "60";
    const char *dcode = s->device_code[0] ? s->device_code : "";
    const char *uacct = s->user_account[0] ? s->user_account : "";
    const char *strs[4] = { tok, dtype, dcode, uacct };
    size_t lens[4];
    for (int i = 0; i < 4; i++) lens[i] = strlen(strs[i]);

    size_t body = 36;
    for (int i = 0; i < 4; i++) body += lens[i] + 1;
    size_t total = 6 + body;
    if (total > outsz) return 0;
    memset(out, 0, total);

    unsigned long desktop_num = strtoul(d->desktop_id, NULL, 10);

    out[0] = (uint8_t)(112 & 0xFF);
    out[1] = (uint8_t)((112 >> 8) & 0xFF);
    out[2] = (uint8_t)(body & 0xFF);
    out[3] = (uint8_t)((body >> 8) & 0xFF);
    out[4] = (uint8_t)((body >> 16) & 0xFF);
    out[5] = (uint8_t)((body >> 24) & 0xFF);

    uint8_t *p = out + 6;
    p[0] = (uint8_t)(desktop_num & 0xFF);
    p[1] = (uint8_t)((desktop_num >> 8) & 0xFF);
    p[2] = (uint8_t)((desktop_num >> 16) & 0xFF);
    p[3] = (uint8_t)((desktop_num >> 24) & 0xFF);
    p += 4;

    uint32_t off = 36;
    for (int i = 0; i < 4; i++) {
        uint32_t l = (uint32_t)lens[i] + 1;
        p[0] = (uint8_t)(l & 0xFF);        p[1] = (uint8_t)((l >> 8) & 0xFF);
        p[2] = (uint8_t)((l >> 16) & 0xFF); p[3] = (uint8_t)((l >> 24) & 0xFF);
        p += 4;
        p[0] = (uint8_t)(off & 0xFF);        p[1] = (uint8_t)((off >> 8) & 0xFF);
        p[2] = (uint8_t)((off >> 16) & 0xFF); p[3] = (uint8_t)((off >> 24) & 0xFF);
        p += 4;
        off += l;
    }
    for (int i = 0; i < 4; i++) {
        memcpy(p, strs[i], lens[i]);
        p += lens[i];
        *p++ = 0; /* NUL terminator */
    }
    return total;
}

/* d->ws_uri ends with "/MAIN"; build a sibling channel URL (.../<NAME>). */
static void clink_channel_uri(Desktop *d, const char *name, char *out, size_t outsz) {
    size_t l = strlen(d->ws_uri);
    size_t base = (l >= 4) ? l - 4 : l; /* strip trailing "MAIN" (keep the '/') */
    snprintf(out, outsz, "%.*s%s", (int)base, d->ws_uri, name);
}

/* Open a clink sub-channel (DISPLAY / INPUTS): connect WSS, send the connect
 * JSON (with matching channel type) + HDR, answer the REDQ/SPICE ticket, then
 * wait for the auth reply / first channel message indicating READY. */
static int clink_open_channel(Session *s, Desktop *d, ClinkChan *ch,
                              const char *name, int chan_type,
                              uint8_t chan_id, uint32_t conn_id) {
    memset(ch, 0, sizeof(*ch));
    strncpy(ch->name, name, sizeof(ch->name) - 1);

    char uri[700];
    clink_channel_uri(d, name, uri, sizeof(uri));

    if (!ws_connect(uri, &ch->ws, d->desktop_code)) return 0;

    char cmsg[9000];
    strncpy(cmsg, d->connect_msg, sizeof(cmsg) - 1);
    cmsg[sizeof(cmsg) - 1] = 0;
    char *tp = strstr(cmsg, "\"type\":");
    if (tp) tp[7] = (char)('0' + chan_type); /* {"type":N ... */

    if (ws_send_text(&ch->ws, cmsg) != 0) { ws_close(&ch->ws); return 0; }
    Sleep(WS_SEND_DELAY_MS);

    uint8_t hdr[64];
    size_t hl = build_hdr_msg(hdr, conn_id, (uint8_t)chan_type, chan_id);
    if (ws_send_bytes(&ch->ws, hdr, hl) != 0) { ws_close(&ch->ws); return 0; }
    log_line("[%s/%s] 通道HDR已发送(conn=%u,type=%d,id=%u)", d->desktop_code, name,
             (unsigned)conn_id, chan_type, (unsigned)chan_id);

    uint8_t *buf = (uint8_t *)malloc(16384);
    if (!buf) { ws_close(&ch->ws); return 0; }

    DWORD start = GetTickCount();
    int ticket_sent = 0, ready = 0;
    DWORD rt = WS_POLL_TIMEOUT_MS;
    WinHttpSetOption(ch->ws.hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));

    while (GetTickCount() - start < 10000) {
        size_t total = 0; int is_text = 0, over = 0;
        int r = ws_read_frame(&ch->ws, buf, 16384, &total, &is_text, &over);
        if (r == -2) {
            /* 短轮询超时：Ticket已发则认为认证完成(通道就绪)；否则继续等REDQ */
            if (ticket_sent) { ready = 1; break; }
            continue;
        }
        if (r == -1) { log_line("[%s/%s] 通道连接被关闭", d->desktop_code, name); break; }
        if (!is_text && total >= 16 && memcmp(buf, "REDQ", 4) == 0) {
            uint8_t resp[512]; size_t rlen = 0;
            if (handle_redq(buf, total, resp, &rlen)) {
                if (ws_send_bytes(&ch->ws, resp, rlen) == 0) {
                    ticket_sent = 1;
                    log_line("[%s/%s] 通道认证(Ticket)已发送", d->desktop_code, name);
                }
            } else {
                log_line("[%s/%s] 通道REDQ处理失败", d->desktop_code, name);
            }
        } else if (ticket_sent) {
            ready = 1; /* auth reply / first channel message => READY */
            break;
        }
    }
    free(buf);

    if (ticket_sent && ready) {
        ch->up = 1;
        log_line("[%s/%s] 通道已就绪", d->desktop_code, name);
        return 1;
    }
    log_line("[%s/%s] 通道建立失败(ticket=%d,ready=%d)", d->desktop_code, name, ticket_sent, ready);
    ws_close(&ch->ws);
    memset(ch, 0, sizeof(*ch));
    return 0;
}

/* 前向声明: ws_keepalive 周期自查任务1003，定义在后面(避免C4013隐式声明) */
static int fetch_task_1003(const Session *s, long *progress, long *status);

static int ws_keepalive(Session *s, Desktop *d, int session_seconds) {
    uint8_t *ws_buf = (uint8_t *)malloc(65536);
    if (!ws_buf) return 0;
    uint8_t *aux_buf = (uint8_t *)malloc(8192);
    if (!aux_buf) { free(ws_buf); return 0; }

    uint8_t user_payload_buf[1024];
    size_t user_payload_len = build_user_payload(s, user_payload_buf, sizeof(user_payload_buf));
    desktop_prepare(d);

    if (!d->ws_uri || !d->connect_msg) {
        log_line("连接参数准备失败");
        free(ws_buf);
        free(aux_buf);
        return 0;
    }

    WSConn wsc;
    if (!ws_connect(d->ws_uri, &wsc, d->desktop_code)) {
        free(ws_buf);
        free(aux_buf);
        return 0;
    }

    if (ws_send_text(&wsc, d->connect_msg) != 0) {
        log_line("connect_msg发送失败");
        ws_close(&wsc);
        free(ws_buf);
        free(aux_buf);
        return 0;
    }
    log_line("connect_msg已发送(%dB)", (int)strlen(d->connect_msg));
    Sleep(WS_SEND_DELAY_MS);

    if (ws_send_bytes(&wsc, initial_payload, sizeof(initial_payload)) != 0) {
        log_line("MAIN initial_payload发送失败");
        ws_close(&wsc);
        free(ws_buf);
        free(aux_buf);
        return 0;
    }
    log_line("MAIN initial_payload已发送(%zuB)", sizeof(initial_payload));

    ClinkChan disp, inp;
    memset(&disp, 0, sizeof(disp));
    memset(&inp, 0, sizeof(inp));
    uint32_t session_id = 0;
    int init_seen = 0, have_chan_list = 0, channels_opened = 0;
    int disp_id = -1, inp_id = -1;
    DWORD init_tick = 0, last_reopen = 0;

    log_line("开始挂机，本次连接目标时长: %d秒 (%.1f小时)", session_seconds, session_seconds / 3600.0);
    DWORD start_tick = GetTickCount();
    DWORD last_ping = start_tick;
    DWORD last_hb_main = start_tick, last_hb_chan = start_tick;
    /* 自适应模式: 首次约30s取基线，其后每 g_task_check_secs 自查一次1003 */
    DWORD last_task_check = start_tick - (DWORD)g_task_check_secs * 1000u + 30000u;
    char tag_main[64];
    snprintf(tag_main, sizeof(tag_main), "%s/MAIN", d->desktop_code);
    int elapsed = 0;

    while (g_running) {
        DWORD now = GetTickCount();
        elapsed = (int)((now - start_tick) / 1000);

        if (elapsed >= session_seconds) {
            log_line("挂机时间已到(%d秒)，正常退出", session_seconds);
            break;
        }

        /* 周期性整体轮换: 实测服务端只对"新鲜桌面会话"计量，单条clink会话长期不重新
         * connect 会停止累计(DISPLAY/INPUTS子通道45s重连无效，因桌面会话租约未更新)。
         * 到点主动断开，由 hang_for_points 重新 connect_desktop 建新会话，无需重新登录。 */
        if (elapsed >= (int)g_session_rotate_secs) {
            log_line("[%ds] clink桌面会话已连续存活%d秒，主动整体重连以维持服务端计量",
                     elapsed, (int)g_session_rotate_secs);
            break;
        }

        /* Fallback: if the channel list never arrives, assume default ids. */
        if (init_seen && !have_chan_list && (now - init_tick) > 12000) {
            disp_id = 0; inp_id = 0; have_chan_list = 1;
            log_line("[%ds] 未收到CHANNELS_LIST，使用默认通道id(display=0,inputs=0)", elapsed);
        }

        /* Open DISPLAY/INPUTS once the session advertises its channels. */
        if (!channels_opened && have_chan_list) {
            int d_id = disp_id < 0 ? 0 : disp_id;
            int i_id = inp_id < 0 ? 0 : inp_id;
            log_line("[%ds] 打开子通道以建立真实观看会话(DISPLAY/INPUTS)...", elapsed);
            if (clink_open_channel(s, d, &disp, "DISPLAY", 2, (uint8_t)d_id, session_id))
                log_line("[%ds] DISPLAY 通道连接成功", elapsed);
            if (clink_open_channel(s, d, &inp, "INPUTS", 3, (uint8_t)i_id, session_id))
                log_line("[%ds] INPUTS 通道连接成功", elapsed);
            channels_opened = 1;
            last_reopen = GetTickCount();
        }

        /* Re-open a dropped sub-channel periodically (best effort). */
        if (channels_opened && (now - last_reopen) > 20000) {
            if (!disp.up) { if (clink_open_channel(s, d, &disp, "DISPLAY", 2,
                    (uint8_t)(disp_id < 0 ? 0 : disp_id), session_id))
                    log_line("[%ds] DISPLAY 重连成功", elapsed); }
            if (!inp.up) { if (clink_open_channel(s, d, &inp, "INPUTS", 3,
                    (uint8_t)(inp_id < 0 ? 0 : inp_id), session_id))
                    log_line("[%ds] INPUTS 重连成功", elapsed); }
            last_reopen = GetTickCount();
        }

        /* RFC6455 协议层 Ping(WebSocket层保活) */
        if ((now - last_ping) >= WS_PING_INTERVAL_MS) {
            ws_send_ping(&wsc);
            if (disp.up) ws_send_ping(&disp.ws);
            if (inp.up) ws_send_ping(&inp.ws);
            last_ping = now;
        }

        /* clink 应用层心跳 CLINK_MSGC_HEARTBEAT(7): MAIN每5s、子通道每30s */
        if ((now - last_hb_main) >= CLINK_HB_MAIN_MS) {
            uint8_t hb[8];
            build_empty_msg(hb, 7);
            ws_send_bytes(&wsc, hb, 6);
            last_hb_main = now;
        }
        if ((now - last_hb_chan) >= CLINK_HB_CHAN_MS) {
            uint8_t hb[8];
            build_empty_msg(hb, 7);
            if (disp.up) ws_send_bytes(&disp.ws, hb, 6);
            if (inp.up) ws_send_bytes(&inp.ws, hb, 6);
            last_hb_chan = now;
        }

        /* 自适应模式: 周期自查任务1003；拿满3600或status=2立即收尾(跨凌晨黑窗关键)。
         * 查询复用已登录会话的独立HTTP短连接，亚秒级返回，不影响WS心跳节拍。 */
        if (g_adaptive && !g_task_complete &&
            (now - last_task_check) >= (DWORD)g_task_check_secs * 1000u) {
            last_task_check = now;
            long prog = -1, st = -1;
            if (fetch_task_1003(s, &prog, &st)) {
                log_line("[进度][%ds] 任务1003 currentProgress=%ld/%d status=%ld",
                         elapsed, prog, TASK_1003_TARGET, st);
                if (st == 2 || prog >= TASK_1003_TARGET) {
                    InterlockedExchange(&g_task_complete, 1);
                    log_line("[进度] 任务1003已达标(status=%ld, progress=%ld)，挂机完成，准备退出", st, prog);
                    break;
                }
            } else {
                log_line("[进度][%ds] 查询任务1003失败，保持连接并在下个周期重试", elapsed);
            }
        }

        DWORD rt = WS_POLL_TIMEOUT_MS;

        /* ---- MAIN channel ---- */
        WinHttpSetOption(wsc.hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));
        {
            size_t total = 0; int is_text = 0, over = 0;
            int r = ws_read_frame(&wsc, ws_buf, 65536, &total, &is_text, &over);
            if (r == -1) {
                log_line("[%ds] MAIN接收错误/连接关闭 (err=%lu)", elapsed, GetLastError());
                break;
            }
            if (r == 0 && total > 0) {
                if (!is_text) {
                    /* 统一处理 REDQ 认证应答与 clink PING(4)->PONG(3) */
                    if (total >= 16 && memcmp(ws_buf, "REDQ", 4) == 0)
                        log_line("[%ds] 收到MAIN REDQ认证请求(%zuB)", elapsed, total);
                    clink_on_recv(&wsc, tag_main, ws_buf, total, is_text);
                }
                if (!is_text && total >= 6) {
                    size_t off = 0;
                    while (off + 6 <= total) {
                        uint16_t mt = (uint16_t)(ws_buf[off] | (ws_buf[off+1] << 8));
                        int32_t dl = (int32_t)(ws_buf[off+2] | (ws_buf[off+3]<<8) |
                                               (ws_buf[off+4]<<16) | (ws_buf[off+5]<<24));
                        if (dl < 0 || off + 6 + (size_t)dl > total) break;
                        const uint8_t *body = ws_buf + off + 6;

                        if (mt == 103 && !init_seen && dl >= 4) {
                            session_id = (uint32_t)(body[0] | (body[1]<<8) |
                                                    (body[2]<<16) | (body[3]<<24));
                            init_seen = 1;
                            init_tick = GetTickCount();
                            log_line("[%ds] MAIN_INIT(103) session_id=%u", elapsed, (unsigned)session_id);
                            if (user_payload_len > 0)
                                ws_send_bytes(&wsc, user_payload_buf, user_payload_len);
                            uint8_t li[1200];
                            size_t ll = build_login_info_msg(s, d, li, sizeof(li));
                            if (ll > 0) {
                                ws_send_bytes(&wsc, li, ll);
                                log_line("[%ds] CLIENT_LOGIN_INFO(112)已发送(%zuB)", elapsed, ll);
                            }
                            uint8_t ab[8];
                            size_t al = build_attach_channels_msg(ab);
                            ws_send_bytes(&wsc, ab, al);
                            log_line("[%ds] ATTACH_CHANNELS(104)已发送", elapsed);
                        } else if (mt == 104 && !have_chan_list && dl >= 4) {
                            uint32_t num = (uint32_t)(body[0] | (body[1]<<8) |
                                                      (body[2]<<16) | (body[3]<<24));
                            size_t co = 4;
                            for (uint32_t ci = 0; ci < num && co + 2 <= (size_t)dl; ci++, co += 2) {
                                uint8_t ct = body[co], cid = body[co+1];
                                if (ct == 2) disp_id = cid;
                                if (ct == 3) inp_id = cid;
                            }
                            have_chan_list = 1;
                            log_line("[%ds] CHANNELS_LIST(104): num=%u displayId=%d inputsId=%d",
                                     elapsed, (unsigned)num, disp_id, inp_id);
                        }
                        /* mt==4 etc.: heartbeats / acks -> ignore */
                        off += 6 + (size_t)dl;
                    }
                }
            }
        }

        /* ---- DISPLAY channel (drain the video stream; marks active viewing) ---- */
        if (disp.up) {
            WinHttpSetOption(disp.ws.hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));
            size_t total = 0; int is_text = 0, over = 0;
            int r = ws_read_frame(&disp.ws, aux_buf, 8192, &total, &is_text, &over);
            if (r == -1) { log_line("[%ds] DISPLAY通道断开", elapsed); disp.up = 0; }
            else if (r == 0 && total > 0) {
                char tag[64]; snprintf(tag, sizeof(tag), "%s/DISPLAY", d->desktop_code);
                clink_on_recv(&disp.ws, tag, aux_buf, total, is_text);
            }
        }

        /* ---- INPUTS channel ---- */
        if (inp.up) {
            WinHttpSetOption(inp.ws.hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));
            size_t total = 0; int is_text = 0, over = 0;
            int r = ws_read_frame(&inp.ws, aux_buf, 8192, &total, &is_text, &over);
            if (r == -1) { log_line("[%ds] INPUTS通道断开", elapsed); inp.up = 0; }
            else if (r == 0 && total > 0) {
                char tag[64]; snprintf(tag, sizeof(tag), "%s/INPUTS", d->desktop_code);
                clink_on_recv(&inp.ws, tag, aux_buf, total, is_text);
            }
        }
    }

    if (disp.up) ws_close(&disp.ws);
    if (inp.up) ws_close(&inp.ws);
    ws_close(&wsc);
    free(ws_buf);
    free(aux_buf);

    if (g_task_complete) {
        return 2;   /* 自适应模式下任务1003已达标 */
    }
    if (elapsed >= session_seconds) {
        return 1;
    }
    if (elapsed >= (int)g_session_rotate_secs) {
        return 3;   /* 主动会话轮换，外层应立即重新 connect 继续 */
    }
    return 0;
}
static int read_plain_config(char *user, size_t user_sz, char *pass, size_t pass_sz) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);

    FILE *f = fopen(config_path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 65536) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *content = (char *)malloc(fsize + 1);
    if (!content) { fclose(f); return 0; }
    size_t clen = fread(content, 1, fsize, f);
    content[clen] = 0;
    fclose(f);

    char u[256], p[256];
    jstr(content, "user", u, sizeof(u));
    jstr(content, "pass", p, sizeof(p));
    if (!u[0]) jstr(content, "username", u, sizeof(u));
    if (!p[0]) jstr(content, "password", p, sizeof(p));

    free(content);

    if (u[0] && p[0]) {
        strncpy(user, u, user_sz - 1);
        user[user_sz - 1] = 0;
        strncpy(pass, p, pass_sz - 1);
        pass[pass_sz - 1] = 0;
        log_line("从config.json读取到凭据");
        return 1;
    }
    return 0;
}
static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_running, 0);
        return TRUE;
    }
    return FALSE;
}

static void log_long(const char *prefix, const char *s) {
    size_t len = strlen(s);
    size_t off = 0;
    int chunk = 0;
    while (off < len) {
        char buf[1024];
        size_t n = len - off;
        if (n > 900) n = 900;
        memcpy(buf, s + off, n);
        buf[n] = 0;
        log_line("%s[%d] %s", prefix, chunk++, buf);
        off += n;
    }
}

/* 自适应挂机用: 轻量查询任务1003("使用1小时")进度。
 * 成功返回1并填 *progress/*status；请求或解析失败返回0。不打印整包，避免日志膨胀。
 * 响应为任务数组，顺序通常为 1002/1003/1004，这里以 "taskDefId":1003 为锚点向后
 * 在一个有限窗口内取其自身的 currentProgress 与 status，避免串到下一个任务。 */
static int fetch_task_1003(const Session *s, long *progress, long *status) {
    static const char *url = "https://desk.ctyun.cn/selforder/api/marketing/userPoints/getTaskList";
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    int rlen = api_get_text(s, url, resp, MAX_RESP);
    int ok = 0;
    if (rlen > 0) {
        resp[rlen] = 0;
        const char *m = strstr(resp, "\"taskDefId\":1003");
        if (!m) m = strstr(resp, "\"taskDefId\": 1003");
        if (m) {
            const char *end = resp + rlen;
            const char *win_end = m + 1200;
            if (win_end > end) win_end = end;
            const char *cp = strstr(m, "\"currentProgress\":");
            if (!cp) cp = strstr(m, "\"currentProgress\": ");
            const char *st = cp ? strstr(cp, "\"status\":") : NULL;
            if (cp && cp < win_end) { *progress = atol(cp + 18); ok = 1; }
            if (st && st < win_end) *status = atol(st + 9);
        }
    }
    free(resp);
    return ok;
}

static void query_task_list(const Session *s) {
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return;
    const char *url = "https://desk.ctyun.cn/selforder/api/marketing/userPoints/getTaskList";
    int rlen = api_get_text(s, url, resp, MAX_RESP);
    if (rlen <= 0) {
        log_line("[tasklist] 请求失败");
        free(resp);
        return;
    }
    resp[rlen] = 0;
    char msg[256];
    jstr(resp, "msg", msg, sizeof(msg));
    log_line("[tasklist] code=%d msg=%s", jint(resp, "code"), msg);
    log_long("[tasklist] ", resp);
    free(resp);
}

/* ============================================================
 * 临时诊断模式 /dump : 抓取真实 web 客户端进入桌面相关的原始响应，
 * 用于定位"夜间冷态挂满时长但任务1003不计时"的根因(connectUrl/
 * queryConnectData/区域网关/goingRetry 等)。输出到 dump.txt，不做WS连接。
 * ============================================================ */
static void dump_file_write(const char *label, const char *data, int len) {
    FILE *f = fopen("D:\\tmp\\ctyun_keepalive_c\\dump.txt", "ab");
    if (!f) { log_line("dump.txt 打开失败"); return; }
    fprintf(f, "\n\n==================== %s (len=%d) ====================\n", label, len);
    if (data && len > 0) fwrite(data, 1, (size_t)len, f);
    fclose(f);
}

static void dump_connect_data(Session *s) {
    const size_t cap = 300u * 1024u;
    char *resp = (char *)malloc(cap);
    if (!resp) { log_line("[dump] malloc 失败"); return; }
    remove("D:\\tmp\\ctyun_keepalive_c\\dump.txt");

    int r = api_get_text(s, "https://desk.ctyun.cn:8810/api/desktop/client/list", resp, cap);
    if (r > 0) { resp[r] = 0; log_line("[dump] list r=%d code=%d", r, jint(resp, "code")); dump_file_write("GET list", resp, r); }
    else log_line("[dump] list 失败 r=%d", r);

    const char *pd = "{\"getCnt\":20,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}";
    r = api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
                 pd, strlen(pd), "application/json", resp, cap);
    if (r > 0) { resp[r] = 0; log_line("[dump] pageDesktop r=%d code=%d", r, jint(resp, "code")); dump_file_write("POST pageDesktop", resp, r); }
    else log_line("[dump] pageDesktop 失败 r=%d", r);

    Desktop dts[10];
    memset(dts, 0, sizeof(dts));
    int cnt = get_desktop_list(s, dts, 10);
    const char *id = NULL;
    if (cnt > 0) {
        int tg = 0;
        for (int i = 0; i < cnt; i++) if (dts[i].is_active) { tg = i; break; }
        id = dts[tg].desktop_id;
    }
    if (!id) { log_line("[dump] 无可用桌面"); free(resp); return; }
    log_line("[dump] 目标桌面 id=%s", id);

    char post[4096];
    snprintf(post, sizeof(post),
             "objId=%s&objType=0&osType=15&deviceId=60&vdCommand=&ipAddress=&macAddress="
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001&specifiedCertCategory=1",
             id, s->device_code);

    r = api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/queryConnectData",
                 post, strlen(post), "application/x-www-form-urlencoded", resp, cap);
    if (r > 0) { resp[r] = 0; log_line("[dump] queryConnectData r=%d code=%d", r, jint(resp, "code")); dump_file_write("POST queryConnectData", resp, r); }
    else log_line("[dump] queryConnectData 失败 r=%d", r);

    r = api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/connect",
                 post, strlen(post), "application/x-www-form-urlencoded", resp, cap);
    if (r > 0) { resp[r] = 0; log_line("[dump] connect r=%d code=%d", r, jint(resp, "code")); dump_file_write("POST connect", resp, r); }
    else log_line("[dump] connect 失败 r=%d", r);

    char su[640];
    snprintf(su, sizeof(su), "https://desk.ctyun.cn:8810/api/desktop/client/status?desktopId=%s&specifiedCertCategory=1", id);
    r = api_get_text(s, su, resp, cap);
    if (r > 0) { resp[r] = 0; log_line("[dump] status r=%d code=%d", r, jint(resp, "code")); dump_file_write("GET status", resp, r); }
    else log_line("[dump] status 失败 r=%d", r);

    free(resp);
    log_line("[dump] 完成 -> dump.txt");
}
/*
 * hang_for_points - 挂机主循环
 *
 * 固定时长模式(g_adaptive=0): 在 total_seconds 内保持 clink WebSocket 连接累计在线时长。
 * 自适应模式(g_adaptive=1):  持续保活并由 ws_keepalive 周期自查任务1003，达标(g_task_complete)
 *                            立即成功返回；否则一直重连保活直到硬上限 g_adaptive_max，
 *                            以跨过凌晨服务端计量黑窗。
 * 连接意外断开时自动重新获取桌面列表并连接继续挂机。重连复用已登录会话(secretKey)，
 * 无需重新登录/验证码。
 */
static int hang_for_points(Session *s, const char *user, const char *pwd) {
    DWORD start_tick = GetTickCount();
    int attempt = 0;
    int consec_fail = 0;   /* 连续失败计数(取桌面列表/connect失败) */
    const int effective_cap = g_adaptive ? (int)g_adaptive_max : (int)g_keep_seconds;

    if (g_adaptive) {
        log_line("自适应挂机: 每%ld秒轮换桌面会话维持计量，每%ld秒自查1003，拿满%d即止；硬上限%d秒(%.2f小时)",
                 (long)g_session_rotate_secs, (long)g_task_check_secs, TASK_1003_TARGET,
                 effective_cap, effective_cap / 3600.0);
    }

    while (g_running) {
        if (g_task_complete) {
            log_line("任务1003已达标，结束挂机");
            return 1;
        }

        int elapsed = (int)((GetTickCount() - start_tick) / 1000);
        int remaining = effective_cap - elapsed;
        if (remaining <= 0) {
            if (g_adaptive) {
                long prog = -1, st = -1;
                fetch_task_1003(s, &prog, &st);
                log_line("到达自适应硬上限(%d秒)，结束本轮；最终1003 progress=%ld status=%ld",
                         effective_cap, prog, st);
                return (st == 2 || prog >= TASK_1003_TARGET) ? 1 : 0;
            }
            log_line("累计挂机时长已达标(%d秒)", (int)g_keep_seconds);
            return 1;
        }
        attempt++;
        log_line("===== 挂机第 %d 轮，累计 %d 秒，剩余 %d 秒 =====", attempt, elapsed, remaining);

        Desktop desktops[10];
        memset(desktops, 0, sizeof(desktops));
        int count = get_desktop_list(s, desktops, 10);
        if (count == 0) {
            consec_fail++;
            /* 可能被其他客户端顶号导致登录态失效: 每连续失败3次自动重新登录(OCR自动) */
            if (consec_fail % 3 == 0 && user && user[0] && pwd && pwd[0]) {
                log_line("连续%d轮失败，尝试重新登录(可能被其他客户端顶号)", consec_fail);
                if (do_login(s, user, pwd)) log_line("重新登录成功，继续挂机");
                else log_line("重新登录失败，继续重试");
            }
            int wait_sec = (consec_fail >= 12) ? 60 : 10;
            log_line("获取桌面列表失败，%d秒后重试(连续失败%d)", wait_sec, consec_fail);
            Sleep(wait_sec * 1000);
            continue;
        }

        int target = -1;
        for (int i = 0; i < count; i++) {
            if (desktops[i].is_active) { target = i; break; }
        }
        if (target == -1) target = 0;

        Desktop *d = &desktops[target];
        log_line("选择桌面: %s (%s)", d->desktop_code, d->desktop_id);

        if (!connect_desktop(s, d)) {
            consec_fail++;
            if (consec_fail % 3 == 0 && user && user[0] && pwd && pwd[0]) {
                log_line("连续%d轮连接失败，尝试重新登录(可能被其他客户端顶号)", consec_fail);
                if (do_login(s, user, pwd)) log_line("重新登录成功，继续挂机");
                else log_line("重新登录失败，继续重试");
            }
            int wait_sec = (consec_fail >= 12) ? 60 : 10;
            log_line("连接桌面失败，%d秒后重试(连续失败%d)", wait_sec, consec_fail);
            for (int i = 0; i < count; i++) desktop_cleanup(&desktops[i]);
            Sleep(wait_sec * 1000);
            continue;
        }
        consec_fail = 0;

        int rc = ws_keepalive(s, d, remaining);

        desktop_cleanup(d);
        for (int i = 0; i < count; i++) {
            if (i != target) desktop_cleanup(&desktops[i]);
        }

        if (g_task_complete || rc == 2) {
            log_line("本轮确认任务1003已完成，挂机达成");
            return 1;
        }
        if (rc == 3) {
            /* 主动会话轮换: 立即重新 connect 建立新鲜桌面会话继续计量 */
            log_line("会话轮换，2秒后建立新桌面会话");
            Sleep(2000);
            continue;
        }
        if (rc == 1) {
            if (g_adaptive) {
                long prog = -1, st = -1;
                fetch_task_1003(s, &prog, &st);
                log_line("自适应挂机到达硬上限结束；最终1003 progress=%ld/%d status=%ld",
                         prog, TASK_1003_TARGET, st);
                if (st == 2 || prog >= TASK_1003_TARGET) {
                    InterlockedExchange(&g_task_complete, 1);
                    return 1;
                }
            }
            log_line("本轮挂机跑满目标时长，挂机完成");
            return 1;
        }
        log_line("连接提前结束(可能被其他客户端顶号)，5秒后重连继续挂机");
        Sleep(5000);
    }
    log_line("挂机被中断(g_running=0)");
    return 0;
}

/* ======================== 公共层钩子实现 ======================== */

static int points_console_input(char *out, size_t out_sz) {
    printf("请输入验证码："); fflush(stdout);
    if (!fgets(out, (int)out_sz, stdin)) return 0;
    out[strcspn(out, "\r\n")] = 0;
    return out[0] ? 1 : 0;
}

int ct_manual_captcha_mode(void) {
    const char *v = getenv("CTYUN_MANUAL_CAPTCHA");
    return (v && v[0] == '1') ? 1 : 0;
}

int ct_manual_captcha(const uint8_t *img_data, int img_len, char *out, size_t out_sz) {
    printf("验证码图片已获取，请查看后输入验证码\n");
    if (img_data && img_len > 0) {
        char tmp_path[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp_path);
        char img_path[MAX_PATH];
        snprintf(img_path, sizeof(img_path), "%sctyun_captcha.png", tmp_path);
        FILE *f = fopen(img_path, "wb");
        if (f) {
            fwrite(img_data, 1, (size_t)img_len, f);
            fclose(f);
            ShellExecuteA(NULL, "open", img_path, NULL, NULL, SW_SHOW);
            ct_log("验证码已保存到: %s 并已打开", img_path);
        }
    }
    return points_console_input(out, out_sz);
}

const wchar_t *ct_ws_ua(void) {
    return L"CtYunPoints/" APP_VERSION;
}

void ct_log(const char *fmt, ...) {
    char b[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    log_line("%s", b);
}

/* ======================== eaichat AES 支持 ======================== */

static BCRYPT_ALG_HANDLE g_aes_alg = NULL;

/* eaichat 会话密钥解密用 AES-128-ECB；须在公共 crypto_init() 成功后调用 */
static int chat_aes_init(void) {
    NTSTATUS st = BCryptOpenAlgorithmProvider(&g_aes_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) { g_aes_alg = NULL; return 0; }
    BCryptSetProperty(g_aes_alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    return 1;
}

/**
 * ChatSession - eaichat AI对话会话(定义前置，供全局变量使用)
 *
 * 与 desk.ctyun.cn:8810 的认证体系完全独立，cookie + 签名(sk)。
 */
typedef struct {
    char cookies[2048];       /* "YL-Token=...; YL-Ssid=..." 形式 */
    char sk[33];              /* 签名密钥(32 hex + \0) */
    char session_key[512];    /* ticketAuthorize 返回的 sessionKey(base64) */
    char client_key[32];      /* 本地AES密钥/RSA明文(16字节字符串) */
    char xuid[80];            /* x-eai-xuid 值(登录后生成/复用) */
    int  tenant_id;           /* 租户ID(eaichat用，默认15) */
    int  logged_in;           /* 是否已登录eaichat */
    char last_sent_date[12];  /* "YYYY-MM-DD"，当天已发过消息的标记 */
} ChatSession;
static ChatSession g_chat = {0};

/**
 * load_chat_credentials_from_config - 从config.json解密出账号和密码的SHA256，供eaichat复用
 *
 * 避免用户为对话功能重复输入账号密码：保活成功后凭据已加密存config.json，
 * 这里重新解密一遍，算出账号明文 + SHA256(密码) 写入 out_user/out_pass_sha。
 * 注意: 只输出密码哈希，明文密码立即清零，不长期驻留内存。
 *
 * @param out_user      输出账号(明文)缓冲区
 * @param out_pass_sha  输出密码SHA256(64hex+\0)缓冲区
 * @param usz           账号缓冲区大小
 * @return              1=成功, 0=失败(无config或解密失败)
 */
static int load_chat_credentials_from_config(char *out_user, char *out_pass_sha, size_t usz) {
    out_user[0] = 0; out_pass_sha[0] = 0;
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);

    FILE *f = fopen(config_path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *content = (char *)malloc(fsize + 1);
    if (!content) { fclose(f); return 0; }
    size_t clen = fread(content, 1, fsize, f);
    content[clen] = 0;
    fclose(f);

    char fp[65];
    get_fingerprint(fp);

    int got = 0;
    char plain_user[256];   /* 解出的明文账号 */
    char plain_pass[256];   /* 解出的明文密码(临时，算完SHA立即清零) */
    plain_user[0] = plain_pass[0] = 0;

    /* 先试v2.0 DPAPI */
    const char *dpapi_start = strstr(content, "\"dpapi\"");
    if (dpapi_start) {
        dpapi_start += strlen("\"dpapi\"");
        while (*dpapi_start == ' ' || *dpapi_start == ':') dpapi_start++;
        if (*dpapi_start == '"') {
            dpapi_start++;
            const char *dpapi_end = strchr(dpapi_start, '"');
            if (dpapi_end) {
                size_t dpapi_len = (size_t)(dpapi_end - dpapi_start);
                uint8_t *dpapi_ct = (uint8_t *)malloc(dpapi_len);
                if (dpapi_ct) {
                    size_t dpapi_ct_len = b64dec(dpapi_start, dpapi_len, dpapi_ct);
                    if (dpapi_ct_len > 0) {
                        uint8_t *inner_data = NULL; DWORD inner_len = 0;
                        if (unprotect_data_dpapi(dpapi_ct, (DWORD)dpapi_ct_len, fp, &inner_data, &inner_len)) {
                            char *inner_json = (char *)malloc(inner_len + 1);
                            if (inner_json) {
                                memcpy(inner_json, inner_data, inner_len);
                                inner_json[inner_len] = 0;
                                LocalFree(inner_data);
                                char salt[65];
                                jstr(inner_json, "salt", salt, sizeof(salt));
                                if (salt[0]) {
                                    uint8_t key[32];
                                    derive_key(fp, salt, key);
                                    /* 解析 accounts */
                                    const char *acc = strstr(inner_json, "\"accounts\"");
                                    if (acc) {
                                        acc = strchr(acc, '[');
                                        if (acc) acc = strchr(acc, '{');
                                        if (acc) {
                                            char ua[2048], pw[2048];
                                            jstr(acc, "user_account", ua, sizeof(ua));
                                            jstr(acc, "password", pw, sizeof(pw));
                                            if (decrypt_data(ua, key, plain_user, sizeof(plain_user)) &&
                                                decrypt_data(pw, key, plain_pass, sizeof(plain_pass))) {
                                                got = 1;
                                            }
                                        }
                                    }
                                    SecureZeroMemory(key, sizeof(key));
                                }
                                SecureZeroMemory(inner_json, inner_len);
                                free(inner_json);
                            }
                        }
                    }
                    free(dpapi_ct);
                }
            }
        }
    }
    /* v1.x legacy ChaCha20 回退 */
    if (!got) {
        char salt[65];
        jstr(content, "salt", salt, sizeof(salt));
        if (salt[0]) {
            uint8_t key[32];
            derive_key_legacy(fp, salt, key);
            const char *acc = strstr(content, "\"accounts\"");
            if (acc) {
                acc = strchr(acc, '[');
                if (acc) acc = strchr(acc, '{');
                if (acc) {
                    char ua[2048], pw[2048];
                    jstr(acc, "user_account", ua, sizeof(ua));
                    jstr(acc, "password", pw, sizeof(pw));
                    if (decrypt_data(ua, key, plain_user, sizeof(plain_user)) &&
                        decrypt_data(pw, key, plain_pass, sizeof(plain_pass))) {
                        got = 1;
                    }
                }
            }
            SecureZeroMemory(key, sizeof(key));
        }
    }
    free(content);

    if (got) {
        strncpy(out_user, plain_user, usz - 1);
        out_user[usz - 1] = 0;
        sha256_hex(plain_pass, out_pass_sha);   /* 算SHA256，明文随后清零 */
        SecureZeroMemory(plain_user, sizeof(plain_user));
        SecureZeroMemory(plain_pass, sizeof(plain_pass));
        return 1;
    }
    return 0;
}
/* ======================== eaichat AI对话 (加密/签名) ======================== */
/*
 * eaichat.ctyun.cn 的认证与签名体系，与 desk.ctyun.cn:8810 完全独立。
 * 已通过抓包逆向 + 本地数学验证全部确认:
 *
 *   1. 密码:           SHA256(明文) 无加盐
 *   2. clientKey:      16字节本地随机串(自生成固定复用)，作为AES密钥和RSA明文
 *   3. sessionKey:     ticketAuthorize 响应 data.sessionKey (base64)
 *   4. sk:             AES-128-ECB-Decrypt(base64decode(sessionKey), clientKey)
 *                      去PKCS7 padding，得到32字符hex(签名用)
 *   5. 签名 sign:      SHA256( paramsStr [& bodyMd5] + "&" + sk + "&"
 *                                  + timestamp + "&" + random )
 *                      paramsStr = URL query参数按键名字典序排序拼 "k=v&k=v"
 *                      bodyMd5   = MD5(请求体)，GET请求为空
 *   6. RSA加密clientKey: RSA-1024 PKCS1v1.5 + bytesToHex
 *                      (用于ticketAuthorize请求的clientKey参数)
 */

#define CHAT_CLIENT_KEY_LEN   16      /* clientKey固定16字节(AES-128密钥) */

/**
 * aes128_ecb_decrypt - AES-128-ECB解密(单块或多块)
 *
 * 使用CNG解密数据。ECB模式无IV，每16字节独立解密。
 * 用于eaichat会话密钥: sk = AES-ECB-Decrypt(base64(sessionKey), clientKey)
 *
 * @param ct       密文(长度必须是16的倍数)
 * @param ctlen    密文长度
 * @param key      16字节AES密钥(clientKey)
 * @param pt       输出明文缓冲区(至少ctlen字节)
 * @param ptlen    输出: 明文长度(未去padding)
 * @return         1=成功, 0=失败
 */
static int aes128_ecb_decrypt(const uint8_t *ct, size_t ctlen,
                               const uint8_t key[16], uint8_t *pt, size_t *ptlen) {
    if (!g_aes_alg || ctlen == 0 || ctlen % 16 != 0) return 0;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptGenerateSymmetricKey(g_aes_alg, &hKey, NULL, 0,
                                                  (PUCHAR)key, 16, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return 0;
    }

    /* ECB模式无IV，传NULL。不用BCRYPT_BLOCK_PADDING(让调用方自行处理PKCS7)，
     * 因为CNG的ECB+PADDING组合在部分版本上有问题。 */
    DWORD outlen = (DWORD)ctlen;
    status = BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ctlen, NULL,
                           NULL, 0, pt, outlen, &outlen,
                           0);  /* dwFlags=0, 不padding */
    BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(status)) {
        return 0;
    }
    *ptlen = outlen;
    return 1;
}

/**
 * rsa_pkcs1_encrypt_hex - RSA-PKCS1v1.5加密并输出hex字符串
 *
 * 用于eaichat ticketAuthorize: clientKey参数 = RSA(clientKey短串, 公钥)转hex。
 * 公钥为SubjectPublicKeyInfo(DER)格式，直接用BCryptImportKeyPair导入。
 *
 * @param pub_der   公钥DER字节(X.509 SubjectPublicKeyInfo)
 * @param der_len   公钥长度
 * @param plaintext 明文(通常为clientKey 16字节)
 * @param plen      明文长度
 * @param hex_out   输出hex字符串缓冲区
 * @param hex_sz    输出缓冲区大小(至少 2*der_len 字节)
 * @return          hex字符串长度, 失败返回0
 */
static size_t rsa_pkcs1_encrypt_hex(const uint8_t *pub_der, size_t der_len,
                                     const uint8_t *plaintext, size_t plen,
                                     char *hex_out, size_t hex_sz) {
    /* 把 X.509 SubjectPublicKeyInfo DER 解析为 CERT_PUBLIC_KEY_INFO,
     * 再用 CryptImportPublicKeyInfoEx2 导入为 CNG 密钥句柄(CryptoAPI/CNG互通)。 */
    CERT_PUBLIC_KEY_INFO *pki = NULL;
    DWORD pki_len = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                             pub_der, (DWORD)der_len,
                             CRYPT_DECODE_ALLOC_FLAG, NULL,
                             &pki, &pki_len)) {
        return 0;
    }
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOLEAN ok = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pki, 0, NULL, &hKey);
    LocalFree(pki);
    if (!ok || !hKey) return 0;

    /* RSA PKCS1v1.5 加密(CNG默认OAEP需指定padding) */
    BCRYPT_PKCS1_PADDING_INFO pad = {0};
    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;  /* PKCS1v1.5不需要hashAlg，但结构体要填 */
    /* 实际PKCS1v1.5(v1.5)不使用OAEP的hash，用 BCRYPT_PAD_PKCS1 */
    uint8_t *buf = (uint8_t *)malloc(plen + 512);
    if (!buf) { BCryptDestroyKey(hKey); return 0; }
    ULONG blen = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plen,
                                    &pad, NULL, 0,
                                    buf, (ULONG)(plen + 512), &blen,
                                    BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(status)) {
        free(buf);
        return 0;
    }
    size_t hexlen = 0;
    for (ULONG i = 0; i < blen && hexlen + 2 < hex_sz; i++) {
        hex_out[hexlen++] = HEX_LUT[buf[i] >> 4];
        hex_out[hexlen++] = HEX_LUT[buf[i] & 0x0F];
    }
    hex_out[hexlen] = 0;
    free(buf);
    return hexlen;
}

/**
 * md5_hex_of_bytes - 计算二进制数据的MD5并输出32字符hex
 *
 * 区别于md5_hex(行486,只处理字符串),本函数处理任意二进制+指定长度,
 * 用于eaichat签名的 bodyMd5 = MD5(请求体)。
 */
static void md5_hex_of_bytes(const uint8_t *d, size_t n, char *out) {
    HCRYPTHASH h;
    if (!CryptCreateHash(g_crypt, CALG_MD5, 0, 0, &h)) { out[0] = 0; return; }
    if (!CryptHashData(h, (BYTE *)d, (DWORD)n, 0)) { CryptDestroyHash(h); out[0] = 0; return; }
    uint8_t digest[16];
    DWORD dl = 16;
    if (!CryptGetHashParam(h, HP_HASHVAL, digest, &dl, 0)) { CryptDestroyHash(h); out[0] = 0; return; }
    CryptDestroyHash(h);
    for (int i = 0; i < 16; i++) {
        out[i * 2] = HEX_LUT[digest[i] >> 4];
        out[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }
    out[32] = 0;
}

/**
 * sha256_hex_of_bytes - 计算二进制数据的SHA256并输出64字符hex
 *
 * 用于eaichat签名: sign = SHA256(origin串)。
 */
static void sha256_hex_of_bytes(const uint8_t *d, size_t n, char *out) {
    uint8_t digest[32];
    sha256(d, n, digest);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = HEX_LUT[digest[i] >> 4];
        out[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }
    out[64] = 0;
}

/**
 * eai_sign - 生成eaichat请求签名
 *
 * 算法(已验证):
 *   prefix  = paramsStr ? paramsStr : ""
 *   bodyMd5 = body非空 ? MD5(body) : ""
 *   if (prefix && bodyMd5) origin = prefix + "&" + bodyMd5
 *   else                   origin = prefix ? prefix : bodyMd5
 *   final_origin = origin + "&" + sk + "&" + timestamp + "&" + random
 *   sign = SHA256(final_origin)
 *
 * 注意: 实际JS逻辑是 l = paramsStr; if(bodyMd5) l = l ? l+"&"+bodyMd5 : bodyMd5;
 *       然后 c = (l?l+"&":"") + sk + "&" + ts + "&" + random
 *       即: 若l非空, origin=l+"&"+sk+...; 若l空, origin=sk+...
 *
 * @param params_str  URL query参数串(已排序,如"k1=v1&k2=v2")，可为""
 * @param body        请求体(POST)，可为NULL
 * @param body_len    请求体长度
 * @param sk          签名密钥(32 hex字符)
 * @param sign_out    输出sign(64 hex + \0, 至少65字节)
 * @param random_out  输出random(8字符 + \0, 至少9字节)
 * @param ts_out      输出timestamp字符串(至少16字节)
 */
static void eai_sign(const char *params_str, const uint8_t *body, size_t body_len,
                     const char *sk, char *sign_out, char *random_out, char *ts_out) {
    /* bodyMd5 */
    char body_md5[33] = "";
    if (body && body_len > 0) {
        md5_hex_of_bytes(body, body_len, body_md5);
    }

    /* 构造 l = prefix (paramsStr + 可选 bodyMd5) */
    /* JS: l = n(paramsStr); if(bodyMd5) l = l ? l+"&"+bodyMd5 : bodyMd5; */
    char l_buf[2048];
    size_t lp = 0;
    if (params_str && params_str[0]) {
        size_t sl = strlen(params_str);
        if (sl > sizeof(l_buf) - 1) sl = sizeof(l_buf) - 1;
        memcpy(l_buf, params_str, sl);
        lp = sl;
        l_buf[lp] = 0;
    }
    if (body_md5[0]) {
        if (lp > 0) {
            l_buf[lp++] = '&';
        }
        if (lp + 32 < sizeof(l_buf)) {
            memcpy(l_buf + lp, body_md5, 32);
            lp += 32;
            l_buf[lp] = 0;
        }
    }

    /* timestamp (毫秒) + random(8字符) */
    long long ts = (long long)time(NULL) * 1000LL;
    snprintf(ts_out, 16, "%lld", ts);
    /* 8字符随机串: 字母+数字 */
    {
        static const char *RND_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        uint8_t rnd[8];
        if (CryptGenRandom(g_crypt, 8, rnd)) {
            for (int i = 0; i < 8; i++) {
                random_out[i] = RND_CHARS[rnd[i] % 62];
            }
        } else {
            for (int i = 0; i < 8; i++) random_out[i] = RND_CHARS[i % 62];
        }
        random_out[8] = 0;
    }

    /* final origin: (l ? l+"&" : "") + sk + "&" + ts + "&" + random */
    char origin[4096];
    int olen = 0;
    if (lp > 0) {
        olen = snprintf(origin, sizeof(origin), "%.*s&%s&%s&%s",
                        (int)lp, l_buf, sk, ts_out, random_out);
    } else {
        olen = snprintf(origin, sizeof(origin), "%s&%s&%s",
                        sk, ts_out, random_out);
    }
    (void)olen;
    sha256_hex_of_bytes((const uint8_t *)origin, strlen(origin), sign_out);
}

/* ---- eaichat 登录链路与发消息 ---- */

/* RSA公钥(X.509 SubjectPublicKeyInfo, DER base64)，从ssopk解码得到，固定 */
static const char *EAI_SSOPK_B64 =
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHaZ5BNp518C/OEOup76d/HXbg6nUGJWiLzMoy4Qg87izLG1dRJ6PIPawt3vGvLuVMG0x8cwPfUfUrfUO1w6e9luGbJLohWwlqBdB0znnmBi5FHWqnNmvigLDVNfOKjQ0NsHhf+6D/aF2RVx+axWPE6auX2iPsYgN8OCOhhfXZwwIDAQAB";
static const char *EAI_SSOPK_ID = "Prod-1-20230613";
static const char *EAI_IAM_LOGIN_URL =
    "https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/login";
static const char *EAI_TICKET_AUTH_URL =
    "https://eaichat.ctyun.cn/sso/login/v2/iam/ticketAuthorize";
static const char *EAI_CHAT_URL =
    "https://eaichat.ctyun.cn/ai/portal/wenc/v3/openai/chat/completions";
static const char *EAI_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

/**
 * gen_uuid - 生成UUID字符串(8-4-4-4-12格式)
 *
 * eaichat 的 verify_id、x-client-trace-id 都需要UUID。
 * 用CryptGenRandom生成随机字节后格式化。
 *
 * @param out   输出缓冲区(至少37字节)
 */
static void gen_uuid(char *out) {
    uint8_t b[16];
    if (!CryptGenRandom(g_crypt, 16, b)) {
        for (int i = 0; i < 16; i++) b[i] = (uint8_t)(rand() & 0xFF);
    }
    /* 设置version(4)和variant */
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

/**
 * gen_client_key - 生成16字节clientKey(字母数字)
 *
 * 替代前端R()。eaichat的clientKey是本地AES密钥/RSA明文，服务端不校验具体值，
 * 只要ticketAuthorize的RSA密文能用同一clientKey解出sk即可。
 * 生成一次后持久化复用。
 *
 * @param out  输出缓冲区(至少17字节)
 */
static void gen_client_key(char *out) {
    static const char *CK =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    uint8_t rnd[16];
    if (!CryptGenRandom(g_crypt, 16, rnd)) {
        for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)(rand() & 0xFF);
    }
    for (int i = 0; i < 16; i++) out[i] = CK[rnd[i] % 62];
    out[16] = 0;
}

/**
 * derive_sk_from_session_key - 从sessionKey派生sk
 *
 * sk = AES-128-ECB-Decrypt(base64decode(sessionKey), clientKey)
 *      去PKCS7 padding，得到32字符hex字符串。
 *
 * @param session_key  ticketAuthorize返回的base64 sessionKey
 * @param client_key   16字节AES密钥
 * @param sk_out       输出sk(至少33字节)
 * @return             1=成功, 0=失败
 */
static int derive_sk_from_session_key(const char *session_key, const char *client_key, char *sk_out) {
    /* base64解码sessionKey(忽略空格/换行) */
    size_t b64len = strlen(session_key);
    uint8_t *ct = (uint8_t *)malloc(b64len + 1);
    if (!ct) return 0;
    /* 过滤非base64字符(如sessionKey里的空格) */
    size_t ct_len = 0;
    for (size_t i = 0; i < b64len; i++) {
        char c = session_key[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            ct[ct_len++] = (uint8_t)c;
        }
    }
    uint8_t *plain = (uint8_t *)malloc(ct_len + 1);
    if (!plain) { free(ct); return 0; }
    size_t pt_len = b64dec((const char *)ct, ct_len, plain);
    free(ct);
    if (pt_len == 0 || pt_len % 16 != 0) { free(plain); return 0; }

    size_t out_len = 0;
    int ok = aes128_ecb_decrypt(plain, pt_len, (const uint8_t *)client_key, plain, &out_len);
    if (!ok) {
        free(plain);
        return 0;
    }
    if (out_len >= 33) out_len = 32;
    memcpy(sk_out, plain, out_len);
    sk_out[out_len] = 0;
    SecureZeroMemory(plain, pt_len);
    free(plain);
    /* 验证sk是32位hex */
    if (strlen(sk_out) != 32) return 0;
    for (const char *p = sk_out; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
            return 0;
    }
    return 1;
}

/**
 * chat_login - 执行eaichat账密登录全链路
 *
 * 1. iam/login(账密POST) → 拿iamTicket
 * 2. ticketAuthorize(iamTicket+RSA加密clientKey) → 拿sessionKey + Set-Cookie(YL-Token/YL-Ssid)
 * 3. derive_sk → 派生sk
 *
 * @param cs     ChatSession(输出 cookies/sk/session_key)
 * @param user   账号(手机号)
 * @param pwd    明文密码
 * @return       1=成功, 0=失败
 */
/**
 * chat_login - 执行eaichat账密登录全链路
 *
 * 1. iam/login(账密POST) → 拿iamTicket
 * 2. ticketAuthorize(iamTicket+RSA加密clientKey) → 拿sessionKey + Set-Cookie(YL-Token/YL-Ssid)
 * 3. derive_sk → 派生sk
 *
 * @param cs        ChatSession(输出 cookies/sk/session_key)
 * @param user      账号(手机号)
 * @param pwd_sha   密码的SHA256哈希(64位hex字符串，即 eaichat iam/login 的password字段)
 *                  注意: 此处直接用哈希，调用方负责算SHA256(明文)，避免明文长期驻留
 * @return          1=成功, 0=失败
 */
static int chat_login(ChatSession *cs, const char *user, const char *pwd_sha) {
    /* 确保client_key存在 */
    if (!cs->client_key[0]) {
        gen_client_key(cs->client_key);
    }

    /* ---- Step1: iam/login ---- */
    /* password字段直接用传入的SHA256哈希 */
    char dc[40];
    snprintf(dc, sizeof(dc), "iam:%s", cs->client_key);

    char login_body[1024];
    snprintf(login_body, sizeof(login_body),
             "{\"userAccount\":\"%s\",\"password\":\"%s\",\"deviceCode\":\"%s\",\"deviceName\":\"iam:web\"}",
             user, pwd_sha, dc);

    const char *login_hdrs[8] = {
        "accept: application/json, text/plain, */*",
        "content-type: application/json",
        "origin: https://desk.ctyun.cn",
        "referer: https://desk.ctyun.cn/cloudB/dy/iam/",
        "if-modified-since: 0"
    };
    /* 构造User-Agent头 */
    char ua_hdr[256];
    snprintf(ua_hdr, sizeof(ua_hdr), "user-agent: %s", EAI_USER_AGENT);
    login_hdrs[5] = ua_hdr;

    char login_resp[MAX_RESP];
    int login_status = 0;
    int rlen = http_req_with_cookies("POST", EAI_IAM_LOGIN_URL,
                                      login_body, strlen(login_body),
                                      NULL, login_hdrs, 6,
                                      cs->cookies, cs->cookies, sizeof(cs->cookies),
                                      login_resp, sizeof(login_resp), &login_status);
    if (rlen < 0) {
        log_line("[eaichat] iam/login请求失败");
        return 0;
    }

    /* 提取iamTicket(可能直接在响应JSON里，或通过Set-Cookie/重定向) */
    /* 观察抓包: iam/login成功后前端轮询qrCode/status拿ticket，但账密登录
     * 的iam/login响应应直接返回ticket或登录态。这里尝试从响应提取。 */
    char iam_ticket[1024] = "";
    /* ticket可能在 data.ticket / data.iamTicket / 直接重定向Location */
    jstr(login_resp, "ticket", iam_ticket, sizeof(iam_ticket));
    if (!iam_ticket[0]) jstr(login_resp, "iamTicket", iam_ticket, sizeof(iam_ticket));
    /* 某些版本ticket在data对象里 */
    if (!iam_ticket[0]) {
        const char *dp = strstr(login_resp, "\"data\"");
        if (dp) {
            jstr(dp, "ticket", iam_ticket, sizeof(iam_ticket));
            if (!iam_ticket[0]) jstr(dp, "iamTicket", iam_ticket, sizeof(iam_ticket));
        }
    }

    if (!iam_ticket[0]) {
        /* iam/login 响应里没有 ticket。
         * 真实流程: iam/login 成功(设token_iam cookie)后，需再请求
         * cas/login?service=<eaichat URL>，服务端检测token_iam有效→
         * 302重定向，Location里带 ?ticket=ST-xxx。
         * 此处发起 cas/login 并从 Location 提取 ticket。 */
        log_line("[eaichat] iam/login成功，请求cas/login换ticket...");

        /* 构造 cas/login URL(带service参数) */
        char cas_url[512];
        /* 方案2：service 值改用不含 "//" 的形式，绕过 WinHTTP URL 规范化。
         * 原值 https://eaichat... 中的双斜杠会让 WinHTTP 把 query 截断。
         * 这里用 https:/eaichat...（单斜杠），服务端若做 URL 规范化应能识别。 */
        snprintf(cas_url, sizeof(cas_url),
                 "https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/cas/login"
                 "?service=https:/eaichat.ctyun.cn:443/chat/%%23/aichat");

        const char *cas_hdrs[8] = {
            "accept: application/json, text/plain, */*",
            "referer: https://desk.ctyun.cn/cloudB/dy/iam/",
            "if-modified-since: 0"
        };
        char cas_ua[256]; snprintf(cas_ua, sizeof(cas_ua), "user-agent: %s", EAI_USER_AGENT);
        cas_hdrs[3] = cas_ua;

        char cas_resp[4096];
        int cas_status = 0;
        char location[1024] = "";
        /* 先尝试 WinHTTP 方案 2 */
        log_line("[eaichat] cas/login 尝试 WinHTTP 方案 2(单斜杠 service)...");
        int crlen = http_get_with_winhttp(cas_url, cas_hdrs, 4,
                                           cs->cookies,
                                           cas_resp, sizeof(cas_resp),
                                           &cas_status, location, sizeof(location));
        if (cas_status != 302 || !location[0]) {
            log_line("[eaichat] WinHTTP 方案 2 失败(status=%d)，回退到 curl.exe", cas_status);
            /* 回退时仍用原双斜杠 URL，curl.exe 不做 WinHTTP 规范化 */
            snprintf(cas_url, sizeof(cas_url),
                     "https://desk.ctyun.cn/cloudB/dy/iam/api/auth/iam/cas/login"
                     "?service=https%%3A%%2F%%2Feaichat.ctyun.cn%%3A443%%2Fchat%%2F%%23%%2Faichat");
            crlen = http_get_via_curl(cas_url, cas_hdrs, 4,
                                       cs->cookies, NULL, 0,
                                       cas_resp, sizeof(cas_resp), &cas_status, location, sizeof(location));
        }
        log_line("[eaichat] cas/login status=%d", cas_status);
        (void)crlen;
        if (cas_status != 302 || !location[0]) {
            log_line("[eaichat] cas/login未返回重定向(status=%d)", cas_status);
            return 0;
        }
        /* 从 location 提取 ticket=ST-xxx */
        const char *tp = strstr(location, "ticket=");
        if (!tp) {
            log_line("[eaichat] cas/login重定向无ticket: %s", location);
            return 0;
        }
        tp += 7;
        size_t ti = 0;
        while (*tp && *tp != '&' && *tp != '#' && ti < sizeof(iam_ticket) - 1) {
            iam_ticket[ti++] = *tp++;
        }
        iam_ticket[ti] = 0;
    }

    if (!iam_ticket[0]) {
        char msg[256]; jstr(login_resp, "msg", msg, sizeof(msg));
        log_line("[eaichat] 登录失败，未获取到ticket (code=%d msg=%s)", login_status, msg);
        return 0;
    }
    log_line("[eaichat] 获取ticket成功(%zu字符)", strlen(iam_ticket));

    /* ---- Step3: ticketAuthorize ---- */
    /* RSA加密clientKey → hex */
    /* base64解码公钥 */
    size_t pk_b64len = strlen(EAI_SSOPK_B64);
    uint8_t *pub_der = (uint8_t *)malloc(pk_b64len + 1);
    if (!pub_der) return 0;
    size_t der_len = b64dec(EAI_SSOPK_B64, pk_b64len, pub_der);

    char rsa_hex[1024];
    size_t rsa_len = rsa_pkcs1_encrypt_hex(pub_der, der_len,
                                            (const uint8_t *)cs->client_key, 16,
                                            rsa_hex, sizeof(rsa_hex));
    free(pub_der);
    if (rsa_len == 0) {
        log_line("[eaichat] RSA加密clientKey失败");
        return 0;
    }

    /* 构造表单 body (application/x-www-form-urlencoded) */
    char ta_body[4096];
    int bl = snprintf(ta_body, sizeof(ta_body),
        "loginType=iamTicket&clientId=eaiapp&iamTicket=%s"
        "&redirectUri=https%%3A%%2F%%2Feaichat.ctyun.cn%%3A443%%2Fchat%%2F%%23%%2Faichat"
        "&clientKey=%s&clientKeyId=%s",
        iam_ticket, rsa_hex, EAI_SSOPK_ID);

    const char *ta_hdrs[8] = {
        "accept: application/json, text/plain, */*",
        "content-type: application/x-www-form-urlencoded;charset=UTF-8",
        "origin: https://eaichat.ctyun.cn",
        "referer: https://eaichat.ctyun.cn/chat/"
    };
    char ta_ua[256]; snprintf(ta_ua, sizeof(ta_ua), "user-agent: %s", EAI_USER_AGENT);
    ta_hdrs[4] = ta_ua;

    char ta_resp[MAX_RESP];
    int ta_status = 0;
    rlen = http_req_with_cookies("POST", EAI_TICKET_AUTH_URL,
                                  ta_body, (size_t)bl, NULL, ta_hdrs, 5,
                                  cs->cookies, cs->cookies, sizeof(cs->cookies),
                                  ta_resp, sizeof(ta_resp), &ta_status);
    if (rlen < 0) {
        log_line("[eaichat] ticketAuthorize请求失败");
        return 0;
    }

    /* 提取 sessionKey */
    char session_key[512] = "";
    jstr(ta_resp, "sessionKey", session_key, sizeof(session_key));
    if (!session_key[0]) {
        log_line("[eaichat] ticketAuthorize响应无sessionKey: %.200s", ta_resp);
        return 0;
    }
    strncpy(cs->session_key, session_key, sizeof(cs->session_key) - 1);
    cs->session_key[sizeof(cs->session_key) - 1] = 0;

    /* ---- Step3: 派生sk ---- */
    if (!derive_sk_from_session_key(cs->session_key, cs->client_key, cs->sk)) {
        log_line("[eaichat] 从sessionKey派生sk失败");
        return 0;
    }

    cs->logged_in = 1;
    cs->tenant_id = 15;
    log_line("[eaichat] 登录成功，sk=%s", cs->sk);
    return 1;
}

/**
 * chat_collect_reply_callback - SSE回调，收集回复文本
 *
 * eaichat SSE 的每个 data: 是一个 JSON，含 delta.content 或完成标志。
 * 累积 content 到 userdata 指向的缓冲区。
 */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int finished;
    int got_content;
} ChatReplyCtx;

static int chat_collect_reply_callback(const char *data, size_t dlen, void *userdata) {
    ChatReplyCtx *ctx = (ChatReplyCtx *)userdata;
    if (!data || dlen == 0) return 0;
    /* "[DONE]" 表示流结束 */
    if (dlen >= 6 && strncmp(data, "[DONE]", 6) == 0) {
        ctx->finished = 1;
        return 1;
    }
    /* 解析JSON里的 content 字段(delta增量) */
    /* data 格式: {"choices":[{"delta":{"content":"xxx"}}],...} 或 {"content":"xxx"} */
    char field[1024];
    /* 优先 delta.content */
    if (jstr_range(data, data + dlen, "content", field, sizeof(field)) && field[0]) {
        /* 过滤掉非文本的(如 reasoning_content 误匹配) */
        size_t fl = strlen(field);
        if (ctx->len + fl < ctx->cap) {
            memcpy(ctx->buf + ctx->len, field, fl);
            ctx->len += fl;
            ctx->buf[ctx->len] = 0;
            ctx->got_content = 1;
        }
    }
    return 0;
}

/**
 * chat_send_message - 向eaichat发送一条消息并等待回复
 *
 * @param cs       ChatSession(需已登录)
 * @param message  消息文本
 * @param reply    输出回复文本缓冲区
 * @param reply_sz 回复缓冲区大小
 * @param conv_id  会话ID(续聊用，新对话传空串)
 * @return         1=成功收到回复, 0=失败
 */
static int chat_send_message(ChatSession *cs, const char *message,
                              char *reply, size_t reply_sz, const char *conv_id) {
    if (!cs->logged_in || !cs->sk[0]) return 0;

    /* 生成 verify_id (UUID) */
    char verify_id[40];
    gen_uuid(verify_id);

    /* 构造请求体JSON */
    char body[4096];
    int bl;
    if (conv_id && conv_id[0]) {
        bl = snprintf(body, sizeof(body),
            "{\"key_model\":\"TEXT_DEEPSEEK_V4\","
            "\"messages\":[{\"role\":\"user\",\"content\":\"%s\",\"verify_id\":\"%s\","
            "\"ref\":{\"type\":\"file\",\"file\":[]}}],"
            "\"stream\":true,\"client_retry\":true,\"web_search\":true,"
            "\"tenantId\":%d,\"enable_thinking\":false,\"conversation_id\":\"%s\"}",
            message, verify_id, cs->tenant_id, conv_id);
    } else {
        bl = snprintf(body, sizeof(body),
            "{\"key_model\":\"TEXT_DEEPSEEK_V4\","
            "\"messages\":[{\"role\":\"user\",\"content\":\"%s\",\"verify_id\":\"%s\","
            "\"ref\":{\"type\":\"file\",\"file\":[]}}],"
            "\"stream\":true,\"client_retry\":true,\"web_search\":true,"
            "\"tenantId\":%d,\"enable_thinking\":false}",
            message, verify_id, cs->tenant_id);
    }

    /* 计算签名(POST无params) */
    char sign[65], random[16], ts[16];
    eai_sign("", (const uint8_t *)body, (size_t)bl, cs->sk, sign, random, ts);

    /* 生成 x-client-trace-id (UUID) */
    char trace_id[40];
    gen_uuid(trace_id);

    /* 构造请求头(全部已知字段) */
    char hdr_sign[80], hdr_random[32], hdr_ts[40], hdr_trace[80];
    char hdr_xuid[120];
    snprintf(hdr_sign, sizeof(hdr_sign), "web-signature: %s", sign);
    snprintf(hdr_random, sizeof(hdr_random), "web-random: %s", random);
    snprintf(hdr_ts, sizeof(hdr_ts), "web-timestamp: %s", ts);
    snprintf(hdr_trace, sizeof(hdr_trace), "x-client-trace-id: %s", trace_id);
    snprintf(hdr_xuid, sizeof(hdr_xuid), "x-eai-xuid: %s", cs->xuid[0] ? cs->xuid : "pubweb_00000000-0000-0000-0000-000000000000");

    const char *hdrs[24];  /* 实际填17个头，预留余量避免栈溢出 */
    int nh = 0;
    hdrs[nh++] = "accept: */*";
    hdrs[nh++] = "content-type: application/json";
    hdrs[nh++] = "origin: https://eaichat.ctyun.cn";
    hdrs[nh++] = "referer: https://eaichat.ctyun.cn/chat/";
    char hdr_ua[256]; snprintf(hdr_ua, sizeof(hdr_ua), "user-agent: %s", EAI_USER_AGENT);
    hdrs[nh++] = hdr_ua;
    hdrs[nh++] = hdr_sign;
    hdrs[nh++] = hdr_random;
    hdrs[nh++] = hdr_ts;
    hdrs[nh++] = hdr_trace;
    hdrs[nh++] = hdr_xuid;
    hdrs[nh++] = "x-eai-env: pubWeb";
    hdrs[nh++] = "x-eai-mode: eai";
    hdrs[nh++] = "x-eai-source: web-eai";
    char hdr_tenant[32]; snprintf(hdr_tenant, sizeof(hdr_tenant), "x-eai-tenant-id: %d", cs->tenant_id);
    hdrs[nh++] = hdr_tenant;
    hdrs[nh++] = "x-eai-version: 202060201";
    hdrs[nh++] = "yl-main-version: 202060201";
    hdrs[nh++] = "yl-product-id: 5";

    /* 读SSE流 */
    reply[0] = 0;
    ChatReplyCtx ctx = { reply, reply_sz - 1, 0, 0, 0 };
    int total = http_read_sse(EAI_CHAT_URL, body, (size_t)bl, hdrs, nh, cs->cookies,
                               chat_collect_reply_callback, &ctx);
    if (total < 0) {
        log_line("[eaichat] 发送消息失败(SSE读取错误)");
        return 0;
    }
    if (!ctx.got_content) {
        log_line("[eaichat] 未收到AI回复(读取%d字节)", total);
        return 0;
    }
    log_line("[eaichat] 收到回复(%zu字符): %.100s", ctx.len, reply);
    return 1;
}
/* 问题列表文件名(与exe同目录) */
#define QUESTIONS_FILE "questions.txt"
/* 生成问题的提示词 */
#define QUESTIONS_PROMPT "\xe9\x9a\x8f\xe6\x9c\xba\xe8\xbe\x93\xe5\x87\xba" "300\xe4\xb8\xaa\xe5\xb8\xb8\xe8\xaf\x86\xe9\x97\xae\xe9\xa2\x98\xef\xbc\x8c\xe6\xa0\xbc\xe5\xbc\x8f\xe4\xb8\xba\xe6\xaf\x8f\xe8\xa1\x8c\xe4\xb8\x80\xe4\xb8\xaa\xe9\x97\xae\xe9\xa2\x98\xef\xbc\x8c\xe4\xb8\x8d\xe5\x8a\xa0\xe5\xba\x8f\xe5\x8f\xb7\xef\xbc\x8c\xe5\x8f\xaa\xe8\xbe\x93\xe5\x87\xba\xe9\x97\xae\xe9\xa2\x98\xe6\x9c\xac\xe8\xba\xab\xef\xbc\x88\xe5\x90\xab\xe6\xa0\x87\xe7\x82\xb9\xe7\xac\xa6\xe5\x8f\xb7\xef\xbc\x89\xe3\x80\x82"

/**
 * get_questions_path - 获取 questions.txt 的完整路径
 */
static void get_questions_path(char *out, size_t outsz) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    snprintf(out, outsz, "%s\\%s", exe_path, QUESTIONS_FILE);
}

/**
 * generate_questions - 向AI请求生成300个常识问题，保存到 questions.txt
 *
 * @return 1=成功, 0=失败
 */
static int generate_questions(void) {
    char qpath[MAX_PATH];
    get_questions_path(qpath, sizeof(qpath));

    log_line("[eaichat] 问题列表不存在，向AI请求生成300个常识问题...");

    char reply[65536];
    int send_ok = chat_send_message(&g_chat, QUESTIONS_PROMPT, reply, sizeof(reply), "");
    if (!send_ok) {
        log_line("[eaichat] 生成问题列表失败(AI未回复)");
        return 0;
    }

    /* 将AI回复按行拆分写入 questions.txt */
    FILE *f = fopen(qpath, "w");
    if (!f) {
        log_line("[eaichat] 无法写入 %s", qpath);
        return 0;
    }

    int count = 0;
    const char *p = reply;
    while (*p) {
        /* 跳过行首换行 */
        while (*p == '\r' || *p == '\n') p++;
        if (!*p) break;

        /* 提取一行 */
        const char *start = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        size_t line_len = (size_t)(p - start);

        /* 去除行尾空白 */
        while (line_len > 0 && (start[line_len-1] == ' ' || start[line_len-1] == '\t'))
            line_len--;

        /* 跳过空行 */
        if (line_len == 0) continue;

        /* 跳过序号前缀(如 "1." "23. " "1、" 等) */
        const char *wp = start;
        size_t wlen = line_len;
        if (wlen >= 2 && wp[0] >= '0' && wp[0] <= '9') {
            const char *dp = wp;
            while (dp < wp + wlen && *dp >= '0' && *dp <= '9') dp++;
            if (dp < wp + wlen && *dp == '.') {
                dp++;
                while (dp < wp + wlen && (*dp == ' ' || *dp == '\t')) dp++;
                wp = dp;
                wlen = (size_t)(start + line_len - wp);
            } else if (dp + 2 < wp + wlen && dp[0] == '\xe3' && dp[1] == '\x80' && dp[2] == '\x81') {
                /* UTF-8 顿号 "、" = \xe3\x80\x81 */
                dp += 3;
                while (dp < wp + wlen && (*dp == ' ' || *dp == '\t')) dp++;
                wp = dp;
                wlen = (size_t)(start + line_len - wp);
            }
        }

        if (wlen == 0) continue;
        fwrite(wp, 1, wlen, f);
        fputc('\n', f);
        count++;
    }
    fclose(f);
    log_line("[eaichat] 问题列表已生成(%d个问题)", count);
    return count > 0;
}

/**
 * pick_question - 从 questions.txt 随机取一个问题，并从文件中删除它
 *
 * @param out     输出问题文本
 * @param outsz   输出缓冲区大小
 * @return        1=成功取到问题, 0=无问题或读取失败
 */
static int pick_question(char *out, size_t outsz) {
    char qpath[MAX_PATH];
    get_questions_path(qpath, sizeof(qpath));

    FILE *f = fopen(qpath, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *content = (char *)malloc(fsize + 1);
    if (!content) { fclose(f); return 0; }
    size_t clen = fread(content, 1, fsize, f);
    content[clen] = 0;
    fclose(f);

    /* 统计行数 */
    int total_lines = 0;
    const char *p = content;
    while (*p) {
        if (*p == '\n') total_lines++;
        p++;
    }
    /* 最后一行可能无换行符 */
    if (clen > 0 && content[clen-1] != '\n') total_lines++;
    if (total_lines == 0) { free(content); return 0; }

    /* 随机选一行 */
    uint8_t rnd[4];
    CryptGenRandom(g_crypt, 4, rnd);
    uint32_t ridx = ((uint32_t)rnd[0] << 16) | ((uint32_t)rnd[1] << 8) | rnd[2];
    int target = (int)(ridx % total_lines);

    /* 找到目标行 */
    int line_idx = 0;
    const char *line_start = content;
    const char *line_end = NULL;
    p = content;
    while (*p) {
        if (*p == '\n') {
            if (line_idx == target) {
                line_end = p;
                break;
            }
            line_idx++;
            line_start = p + 1;
        }
        p++;
    }
    if (!line_end) {
        /* 最后一行无换行符 */
        if (line_idx == target) {
            line_end = content + clen;
        } else {
            free(content);
            return 0;
        }
    }

    /* 提取问题文本(去行尾\r和空白) */
    size_t qlen = (size_t)(line_end - line_start);
    while (qlen > 0 && (line_start[qlen-1] == '\r' || line_start[qlen-1] == ' ' || line_start[qlen-1] == '\t'))
        qlen--;
    if (qlen == 0 || qlen >= outsz) { free(content); return 0; }
    memcpy(out, line_start, qlen);
    out[qlen] = 0;

    /* 重写文件: 删除已选行 */
    f = fopen(qpath, "w");
    if (f) {
        /* 写 target 之前的行 */
        if (target > 0)
            fwrite(content, 1, (size_t)(line_start - content), f);
        /* 写 target 之后的行 */
        if (*line_end == '\n')
            fwrite(line_end + 1, 1, clen - (size_t)(line_end - content) - 1, f);
        else
            fwrite(line_end, 1, clen - (size_t)(line_end - content), f);
        fclose(f);
    }

    free(content);
    return 1;
}
/**
 * chat_param - 对话线程参数
 *
 * 安全设计: 只存密码的 SHA256 哈希(SHA256(明文))，不存明文。
 * eaichat 登录只需该哈希(POST的password字段即SHA256(明文))，
 * 因此线程内可凭哈希完成登录，明文密码不必长期驻留内存。
 * 哈希是单向的，泄漏后无法逆推明文，风险远低于明文常驻。
 */
typedef struct {
    char user[128];
    char password_sha[65];  /* SHA256(明文密码)的64位hex + \0 */
} ChatParam;
/**
 * save_chat_state - 持久化 chat 会话状态到 config.json 的 chat_dpapi 字段
 *
 * config.json 格式:
 *   {"version":2,"dpapi":"<凭据>","chat_dpapi":"<base64(DPAPI(chat_json))>"}
 * chat_dpapi 与 dpapi 独立加密，互不影响。
 *
 * 隐私模式 /p 下不保存。
 */
static void save_chat_state(void) {
    if (!g_chat.client_key[0]) return;  /* 无 client_key 说明从未登录过，不保存 */

    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);

    char fp[65];
    get_fingerprint(fp);

    /* 构造 chat 内部 JSON */
    size_t need = 256 + strlen(g_chat.cookies) + strlen(g_chat.session_key) +
                  strlen(g_chat.client_key) + strlen(g_chat.xuid);
    char *inner = (char *)malloc(need);
    if (!inner) return;
    int ilen = snprintf(inner, need,
        "{\"client_key\":\"%s\",\"cookies\":\"%s\",\"sk\":\"%s\","
        "\"session_key\":\"%s\",\"xuid\":\"%s\",\"tenant_id\":%d,"
        "\"last_sent_date\":\"%s\"}",
        g_chat.client_key, g_chat.cookies, g_chat.sk,
        g_chat.session_key, g_chat.xuid, g_chat.tenant_id,
        g_chat.last_sent_date);

    /* DPAPI 加密 */
    uint8_t *ct = NULL; DWORD ct_len = 0;
    if (!protect_data_dpapi((const uint8_t *)inner, (DWORD)ilen, fp, &ct, &ct_len)) {
        SecureZeroMemory(inner, ilen);
        free(inner);
        return;
    }
    SecureZeroMemory(inner, ilen);
    free(inner);

    size_t b64_need = ((size_t)ct_len + 2) / 3 * 4 + 1;
    char *b64 = (char *)malloc(b64_need);
    if (!b64) { LocalFree(ct); return; }
    b64enc(ct, ct_len, b64);
    LocalFree(ct);

    /* 读取现有 config.json，合并 chat_dpapi 字段后写回 */
    FILE *f = fopen(config_path, "rb");
    char *old = NULL;
    size_t old_len = 0;
    if (f) {
        fseek(f, 0, SEEK_END);
        old_len = (size_t)ftell(f);
        if (old_len > 0 && old_len < 1024 * 1024) {
            fseek(f, 0, SEEK_SET);
            old = (char *)malloc(old_len + 1);
            if (old) {
                size_t rd = fread(old, 1, old_len, f);
                old[rd] = 0;
            }
        }
        fclose(f);
    }

    /* 构造新的 config.json */
    char *new_cfg = NULL;
    if (old && old[0]) {
        /* 查找已有的 "chat_dpapi" 字段 */
        const char *cdp = strstr(old, "\"chat_dpapi\"");
        if (cdp) {
            /* 替换现有值: 找到值的起止引号 */
            const char *vp = cdp + strlen("\"chat_dpapi\"");
            while (*vp == ' ' || *vp == ':') vp++;
            if (*vp == '"') {
                vp++;
                const char *ve = strchr(vp, '"');
                if (ve) {
                    size_t prefix_len = (size_t)(vp - old);
                    size_t suffix_start = (size_t)(ve - old);
                    size_t new_len = prefix_len + strlen(b64) + (old_len - suffix_start) + 1;
                    new_cfg = (char *)malloc(new_len);
                    if (new_cfg) {
                        memcpy(new_cfg, old, prefix_len);
                        strcpy(new_cfg + prefix_len, b64);
                        strcat(new_cfg, old + suffix_start);
                    }
                }
            }
        } else {
            /* 追加到 JSON 末尾(在最后一个 } 前插入) */
            char *last_brace = strrchr(old, '}');
            if (last_brace) {
                size_t pos = (size_t)(last_brace - old);
                /* 检查 } 前是否需要逗号 */
                size_t i = pos;
                int need_comma = 0;
                while (i > 0 && (old[i-1] == ' ' || old[i-1] == '\t' ||
                                 old[i-1] == '\r' || old[i-1] == '\n')) i--;
                if (i > 0 && old[i-1] != '{') need_comma = 1;

                size_t new_len = pos + (need_comma ? 1 : 0) +
                                 strlen(",\"chat_dpapi\":\"") + strlen(b64) +
                                 strlen("\"}") + 1;
                new_cfg = (char *)malloc(new_len);
                if (new_cfg) {
                    memcpy(new_cfg, old, pos);
                    new_cfg[pos] = 0;
                    if (need_comma) strcat(new_cfg, ",");
                    strcat(new_cfg, "\"chat_dpapi\":\"");
                    strcat(new_cfg, b64);
                    strcat(new_cfg, "\"}");
                }
            }
        }
    } else {
        /* 无现有 config.json，创建新的 */
        size_t new_len = strlen("{\"chat_dpapi\":\"") + strlen(b64) + strlen("\"}") + 1;
        new_cfg = (char *)malloc(new_len);
        if (new_cfg) {
            strcpy(new_cfg, "{\"chat_dpapi\":\"");
            strcat(new_cfg, b64);
            strcat(new_cfg, "\"}");
        }
    }
    if (old) { SecureZeroMemory(old, old_len); free(old); }

    if (new_cfg) {
        f = fopen(config_path, "w");
        if (f) {
            fputs(new_cfg, f);
            fclose(f);
        }
        free(new_cfg);
    }
    free(b64);
}
/**
 * load_chat_state - 从 config.json 的 chat_dpapi 字段恢复 chat 会话状态
 *
 * @return 1=成功恢复, 0=无 chat_dpapi 或解密失败
 */
static int load_chat_state(void) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);

    FILE *f = fopen(config_path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 65536) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *content = (char *)malloc(fsize + 1);
    if (!content) { fclose(f); return 0; }
    size_t clen = fread(content, 1, fsize, f);
    content[clen] = 0;
    fclose(f);

    char fp[65];
    get_fingerprint(fp);

    int got = 0;
    /* 查找 "chat_dpapi" 字段(而非 "dpapi") */
    const char *dp = strstr(content, "\"chat_dpapi\"");
    if (dp) {
        dp += strlen("\"chat_dpapi\"");
        while (*dp == ' ' || *dp == ':') dp++;
        if (*dp == '"') {
            dp++;
            const char *dpe = strchr(dp, '"');
            if (dpe) {
                size_t dp_len = (size_t)(dpe - dp);
                uint8_t *ct = (uint8_t *)malloc(dp_len);
                if (ct) {
                    size_t ct_len = b64dec(dp, dp_len, ct);
                    if (ct_len > 0) {
                        uint8_t *inner = NULL; DWORD inner_len = 0;
                        if (unprotect_data_dpapi(ct, (DWORD)ct_len, fp, &inner, &inner_len)) {
                            char *json = (char *)malloc(inner_len + 1);
                            if (json) {
                                memcpy(json, inner, inner_len);
                                json[inner_len] = 0;
                                /* 解析各字段 */
                                jstr(json, "client_key", g_chat.client_key, sizeof(g_chat.client_key));
                                jstr(json, "cookies", g_chat.cookies, sizeof(g_chat.cookies));
                                jstr(json, "sk", g_chat.sk, sizeof(g_chat.sk));
                                jstr(json, "session_key", g_chat.session_key, sizeof(g_chat.session_key));
                                jstr(json, "xuid", g_chat.xuid, sizeof(g_chat.xuid));
                                jstr(json, "last_sent_date", g_chat.last_sent_date, sizeof(g_chat.last_sent_date));
                                char tid[16]; jstr(json, "tenant_id", tid, sizeof(tid));
                                if (tid[0]) g_chat.tenant_id = atoi(tid);
                                else g_chat.tenant_id = 15;
                                if (g_chat.sk[0]) g_chat.logged_in = 1;
                                SecureZeroMemory(json, inner_len);
                                free(json);
                                got = 1;
                            }
                            LocalFree(inner);
                        }
                    }
                    free(ct);
                }
            }
        }
    }
    free(content);
    return got;
}
/**
 * chat_do_daily_task - 执行一次对话任务(登录+发消息)
 *
 * @return 1=成功, 0=失败
 */
static int chat_do_daily_task(ChatParam *cp) {
    if (!g_chat.logged_in) {
        if (!chat_login(&g_chat, cp->user, cp->password_sha)) {
            log_line("[eaichat] 登录失败，跳过本次对话");
            return 0;
        }
        save_chat_state();  /* 登录成功后持久化会话 */
    }

    /* 检查问题列表是否存在且有剩余问题 */
    char question[1024];
    if (!pick_question(question, sizeof(question))) {
        /* 无问题或文件不存在，生成新列表 */
        if (!generate_questions()) {
            log_line("[eaichat] 生成问题列表失败，跳过本次对话");
            return 0;
        }
        /* 生成后重新取问题 */
        if (!pick_question(question, sizeof(question))) {
            log_line("[eaichat] 问题列表仍为空，跳过本次对话");
            return 0;
        }
    }

    log_line("[eaichat] 提问: %s", question);

    char reply[4096];
    int send_ok = chat_send_message(&g_chat, question, reply, sizeof(reply), "");
    if (!send_ok) {
        /* 可能cookie过期，重新登录再试一次 */
        log_line("[eaichat] 发送失败，尝试重新登录");
        g_chat.logged_in = 0;
        if (chat_login(&g_chat, cp->user, cp->password_sha)) {
            save_chat_state();  /* 重登后也持久化 */
            if (chat_send_message(&g_chat, question, reply, sizeof(reply), "")) {
                log_line("[eaichat] 回答: %s", reply);
                log_line("[eaichat] 重登后对话成功");
                return 1;
            }
        }
        return 0;
    }
    log_line("[eaichat] 回答: %s", reply);
    return 1;
}

/* ======================== 单实例保护 ======================== */
/*
 * v1.5.0: 积分流程改由常驻 ctyun_keepalive 每日05:00拉起，不再自注册计划任务。
 * 同名互斥量保证全会话(同一登录桌面)只有一个 points 实例进入登录/挂机流程，
 * 避免手动重复运行或 keepalive 重启补跑时同账号互顶(被顶会触发无谓的重登风暴)。
 * /tasklist、/dump 等一次性查询不受互斥限制。
 */
#define POINTS_SINGLE_INSTANCE_MUTEX  "Local\\ctyun_points_single_v1"

int main(int argc, char *argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    srand((unsigned)time(NULL));
    log_open();

    log_line("========================================");
    log_line("天翼云电脑积分挂机程序 v%s", APP_VERSION);
    log_line("========================================");

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    char user[128] = "", pass[128] = "";
    char enc_device_code[128] = "";
    int tasklist_only = 0;
    int dump_only = 0;
    int fixed_secs = 0;   /* 是否显式指定固定时长(指定则关闭自适应) */
    int nochat = 0;       /* /nochat: 本次不执行每日AI对话 */   /* 是否显式指定固定时长(指定则关闭自适应) */

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "/help") == 0 || _stricmp(argv[i], "/h") == 0 ||
            _stricmp(argv[i], "-h") == 0 || _stricmp(argv[i], "--help") == 0) {
            printf("天翼云电脑积分挂机程序 v%s\n\n", APP_VERSION);
            printf("用法: ctyun_points.exe [选项]\n\n");
            printf("选项:\n");
            printf("  /user <账号>  /u <账号>    指定登录账号(手机号)\n");
            printf("  /pass <密码>  /p <密码>    指定登录密码\n");
            printf("  (无参数)                   登录→每日AI对话(1004)→自适应挂机(1003)，拿满即止，硬上限6小时。\n"
                   "                             通常由常驻的 ctyun_keepalive 每日05:00自动调用，也可手动运行\n");
            printf("  /seconds <秒> /s <秒>     指定固定挂机时长(显式指定后关闭自适应, <%d秒)\n", 7200);
            printf("  /tasklist     /t           仅登录并查询积分任务列表(测试验证，不兑换)后退出\n");
            printf("  /nochat                     本次运行不执行每日AI对话任务\n");
            printf("  /help         /h           显示帮助信息\n");
            printf("  /version      /v           显示版本号\n\n");
            printf("凭据获取优先级:\n");
            printf("  1. 命令行参数 /user /pass\n");
            printf("  2. 环境变量 CTYUN_USER / CTYUN_PASS\n");
            printf("  3. 加密 config.json (ctyun_keepalive格式, DPAPI+ChaCha20-Poly1305)\n");
            printf("  4. 明文 config.json ({\"user\":\"xxx\",\"pass\":\"xxx\"})\n");
            printf("  5. 交互式输入\n\n");
            printf("环境变量:\n");
            printf("  CTYUN_MANUAL_CAPTCHA=1     强制使用手工输入验证码\n");
            printf("  CTYUN_POINTS_SECONDS=<秒>  指定固定挂机时长(等效 /seconds，会关闭自适应)\n");
            printf("  CTYUN_ADAPTIVE_MAX_SECS=<秒> 自适应硬上限(默认%d，60..21600)\n", ADAPTIVE_MAX_SECONDS);
            printf("  CTYUN_TASK_CHECK_SECS=<秒>    自适应自查1003间隔(默认%d，15..3600)\n", TASK_CHECK_INTERVAL_SEC);
            printf("  CTYUN_SESSION_ROTATE_SECS=<秒> 桌面会话整体重连间隔(默认%d，30..1800；服务端只对新鲜会话计量)\n", SESSION_ROTATE_SECONDS);
            return 0;
        } else if (_stricmp(argv[i], "/version") == 0 || _stricmp(argv[i], "/v") == 0 ||
                   _stricmp(argv[i], "-v") == 0 || _stricmp(argv[i], "--version") == 0) {
            printf("ctyun_points v%s\n", APP_VERSION);
            return 0;
        } else if ((_stricmp(argv[i], "/tasklist") == 0 || _stricmp(argv[i], "/t") == 0 ||
                    _stricmp(argv[i], "-t") == 0 ||
                    _stricmp(argv[i], "--tasklist") == 0)) {
            tasklist_only = 1;
        } else if (_stricmp(argv[i], "/dump") == 0 || _stricmp(argv[i], "--dump") == 0) {
            dump_only = 1;
        } else if (_stricmp(argv[i], "/nochat") == 0) {
            nochat = 1;
        } else if ((_stricmp(argv[i], "/seconds") == 0 || _stricmp(argv[i], "/s") == 0 ||
                    _stricmp(argv[i], "-s") == 0 || _stricmp(argv[i], "--seconds") == 0) && i + 1 < argc) {
            int v = atoi(argv[i + 1]);
            if (v > 0 && v < 7200) { InterlockedExchange(&g_keep_seconds, v); fixed_secs = 1; }
            i++;
        } else if ((_stricmp(argv[i], "/user") == 0 || _stricmp(argv[i], "-user") == 0 ||
             _stricmp(argv[i], "--user") == 0) && i + 1 < argc) {
            strncpy(user, argv[i + 1], sizeof(user) - 1);
            user[sizeof(user) - 1] = 0;
            i++;
        } else if ((_stricmp(argv[i], "/pass") == 0 || _stricmp(argv[i], "-pass") == 0 ||
                    _stricmp(argv[i], "--pass") == 0) && i + 1 < argc) {
            strncpy(pass, argv[i + 1], sizeof(pass) - 1);
            pass[sizeof(pass) - 1] = 0;
            i++;
        }
    }

    {
        const char *env_secs = getenv("CTYUN_POINTS_SECONDS");
        if (env_secs && env_secs[0]) {
            int v = atoi(env_secs);
            if (v > 0 && v < 7200) { InterlockedExchange(&g_keep_seconds, v); fixed_secs = 1; log_line("挂机时长(环境变量): %d秒", v); }
        }
    }
    {
        const char *e = getenv("CTYUN_ADAPTIVE_MAX_SECS");
        if (e && *e) { int v = atoi(e); if (v >= 60 && v <= 21600) InterlockedExchange(&g_adaptive_max, v); }
    }
    {
        const char *e = getenv("CTYUN_TASK_CHECK_SECS");
        if (e && *e) { int v = atoi(e); if (v >= 15 && v <= 3600) InterlockedExchange(&g_task_check_secs, v); }
    }
    {
        const char *e = getenv("CTYUN_SESSION_ROTATE_SECS");
        if (e && *e) { int v = atoi(e); if (v >= 30 && v <= 1800) InterlockedExchange(&g_session_rotate_secs, v); }
    }

    /* 默认(未显式 /seconds)走自适应: 一直保活并周期自查1003，拿满即止，跨过凌晨计量黑窗。
     * /tasklist、/dump 仅一次性查询，不进入挂机，模式标志对它们无影响。 */
    if (!tasklist_only && !dump_only)
        InterlockedExchange(&g_adaptive, fixed_secs ? 0 : 1);

    /* 单实例保护: 仅挂机主流程受限(查询/诊断/帮助/版本不受影响)。
     * 已有实例时静默成功退出，避免 keepalive 补跑或手动运行造成同账号顶号。 */
    HANDLE h_single = NULL;
    if (!tasklist_only && !dump_only) {
        h_single = CreateMutexA(NULL, TRUE, POINTS_SINGLE_INSTANCE_MUTEX);
        if (!h_single || GetLastError() == ERROR_ALREADY_EXISTS) {
            log_line("已有一个积分挂机实例在运行，本次静默退出(避免重复登录顶号)");
            if (g_logfp) fclose(g_logfp);
            return 0;
        }
    }

    if (g_adaptive) {
        log_line("自适应挂机模式: 维持活跃clink会话，每%ld秒自查任务1003，拿满%d即止；硬上限%ld秒(%.2f小时)",
                 (long)g_task_check_secs, TASK_1003_TARGET, (long)g_adaptive_max,
                 (double)g_adaptive_max / 3600.0);
    } else {
        log_line("固定时长挂机模式: 目标 %d秒 (%.2f小时)", (int)g_keep_seconds, g_keep_seconds / 3600.0);
    }

    if (!user[0]) {
        const char *env_user = getenv("CTYUN_USER");
        if (env_user && env_user[0]) {
            strncpy(user, env_user, sizeof(user) - 1);
            user[sizeof(user) - 1] = 0;
            log_line("从环境变量CTYUN_USER读取用户名");
        }
    }
    if (!pass[0]) {
        const char *env_pass = getenv("CTYUN_PASS");
        if (env_pass && env_pass[0]) {
            strncpy(pass, env_pass, sizeof(pass) - 1);
            pass[sizeof(pass) - 1] = 0;
            log_line("从环境变量CTYUN_PASS读取密码");
        }
    }

    if (!crypto_init()) {
        log_line("加密模块初始化失败");
        return 1;
    }
    if (!chat_aes_init()) log_line("AES提供者初始化失败，eaichat对话功能将不可用");

    if (!http_init()) {
        log_line("HTTP模块初始化失败");
        return 1;
    }

    char fp[65];
    get_fingerprint(fp);
    log_line("机器指纹: %s", fp);

    if (!user[0] || !pass[0]) {
        if (load_encrypted_credentials(user, sizeof(user), pass, sizeof(pass),
                                        enc_device_code, sizeof(enc_device_code))) {
            log_line("从加密配置文件读取到凭据");
        }
    }

    if (!user[0] || !pass[0]) {
        if (read_plain_config(user, sizeof(user), pass, sizeof(pass))) {
        }
    }

    if (!user[0]) {
        printf("账户: "); fflush(stdout);
        if (!fgets(user, sizeof(user), stdin)) { user[0] = 0; }
        user[strcspn(user, "\r\n")] = 0;
    }
    if (!pass[0]) {
        printf("密码: "); fflush(stdout);
        DWORD old_mode = 0;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        GetConsoleMode(hIn, &old_mode);
        SetConsoleMode(hIn, old_mode & ~ENABLE_ECHO_INPUT);
        int ch;
        int pi = 0;
        while ((ch = fgetc(stdin)) != EOF && ch != '\n' && ch != '\r') {
            if (pi < (int)sizeof(pass) - 2) {
                pass[pi++] = (char)ch;
                putchar('*');
            }
        }
        pass[pi] = 0;
        SetConsoleMode(hIn, old_mode);
        printf("\n");
    }

    if (!user[0] || !pass[0]) {
        log_line("账户或密码为空，退出");
        return 1;
    }

    Session s = {0};
    if (enc_device_code[0]) {
        strncpy(s.device_code, enc_device_code, sizeof(s.device_code) - 1);
        s.device_code[sizeof(s.device_code) - 1] = '\0';
        log_line("使用加密配置中的设备码: %s", s.device_code);
    } else {
        generate_device_code(fp, s.device_code, sizeof(s.device_code));
        log_line("设备码: %s", s.device_code);
    }

    log_line("开始登录...");
    if (!do_login(&s, user, pass)) {
        log_line("登录失败");
        SecureZeroMemory(pass, sizeof(pass));
        if (g_logfp) fclose(g_logfp);
        return 1;
    }
    /* 注意: 此处不清零 pass，挂机期间被其他客户端顶号时需用它自动重新登录 */

    int result = 0;
    if (dump_only) {
        log_line("诊断模式: 抓取进入桌面相关原始响应到 dump.txt(不建立WS)");
        dump_connect_data(&s);
        result = 1;
    } else if (tasklist_only) {
        log_line("测试模式: 查询积分任务列表(不做兑换)");
        query_task_list(&s);
        result = 1;
    } else {
        /* ---- 每日 eaichat AI 对话(任何失败只记日志，不影响挂机) ---- */
        if (!nochat) {
            ChatParam chat_cp = {0};
            load_chat_state();
            SYSTEMTIME cst;
            GetLocalTime(&cst);
            char chat_today[16];
            snprintf(chat_today, sizeof(chat_today), "%04d-%02d-%02d",
                     cst.wYear, cst.wMonth, cst.wDay);
            if (strcmp(g_chat.last_sent_date, chat_today) != 0) {
                strncpy(chat_cp.user, user, sizeof(chat_cp.user) - 1);
                sha256_hex(pass, chat_cp.password_sha);
                if (!chat_cp.user[0] || !chat_cp.password_sha[0])
                    load_chat_credentials_from_config(chat_cp.user, chat_cp.password_sha,
                                                      sizeof(chat_cp.user));
                if (chat_cp.user[0] && chat_do_daily_task(&chat_cp)) {
                    strncpy(g_chat.last_sent_date, chat_today,
                            sizeof(g_chat.last_sent_date) - 1);
                    g_chat.last_sent_date[sizeof(g_chat.last_sent_date) - 1] = 0;
                    save_chat_state();
                }
                SecureZeroMemory(chat_cp.password_sha, sizeof(chat_cp.password_sha));
            }
        }
        result = hang_for_points(&s, user, pass);
    }

    SecureZeroMemory(pass, sizeof(pass));

    if (g_rsa_alg) BCryptCloseAlgorithmProvider(g_rsa_alg, 0);
    if (g_crypt) CryptReleaseContext(g_crypt, 0);
    if (g_inet) WinHttpCloseHandle(g_inet);
    if (g_logfp) fclose(g_logfp);

    if (result) {
        log_line("任务完成，程序正常退出");
        return 0;
    } else {
        log_line("任务异常结束");
        return 1;
    }
}
