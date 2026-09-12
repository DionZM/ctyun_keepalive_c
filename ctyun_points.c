/*
 * ctyun_points.c - 天翼云电脑积分挂机程序 (C语言版)
 *
 * 功能概述:
 *   自动登录天翼云电脑平台，获取桌面列表，连接一个桌面后WebSocket挂机1.5小时(5400秒)，
 *   挂机期间定时发送Ping和鼠标移动消息维持活跃，挂机结束后正常退出。
 *
 * 编译 (MSVC x64):
 *   cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ctyun_points.c ^
 *      /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG ^
 *      winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib user32.lib
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iphlpapi.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define APP_VERSION   "1.2.0-points"

#define MAX_RESP      65536
#define WS_RECV_BUF_SIZE   8192
#define CAPTCHA_IMG_BUF    65536
#define OCR_RESP_BUF       4096
#define WS_PING_INTERVAL_MS 15000
#define WS_MOUSE_INTERVAL_MS 30000
#define WS_SEND_DELAY_MS   100
#define KEEPALIVE_SECONDS  5400
#define DNS_RESOLVE_TIMEOUT_MS 10000
#define WINHTTP_CONNECT_TIMEOUT_MS  15000
#define WINHTTP_SEND_TIMEOUT_MS     30000
#define WINHTTP_RECEIVE_TIMEOUT_MS  30000
#define WS_RECV_TIMEOUT_MS  60000
#define WS_POLL_TIMEOUT_MS  300    /* 单通道轮询接收超时(毫秒)，保证多通道及时排空/响应 */
#define CLINK_HB_MAIN_MS    5000   /* MAIN通道应用层心跳(CLINK_MSGC_HEARTBEAT)间隔 */
#define CLINK_HB_CHAN_MS    30000  /* DISPLAY/INPUTS通道应用层心跳间隔 */
#define OCR_SERVICE_URL    "https://orc.1999111.xyz/ocr"
#define MAX_LOGIN_ATTEMPTS 3
#define MAX_MANUAL_CAPTCHA_ATTEMPTS 3

#ifndef WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE
#define WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE         3
#endif
#ifndef WINHTTP_WEB_SOCKET_PONG_BUFFER_TYPE
#define WINHTTP_WEB_SOCKET_PONG_BUFFER_TYPE         4
#endif

static HCRYPTPROV g_crypt = 0;
static HINTERNET g_inet = NULL;
static BCRYPT_ALG_HANDLE g_rsa_alg = NULL;
static volatile LONG g_running = 1;
static FILE *g_logfp = NULL;
static volatile LONG g_keep_seconds = KEEPALIVE_SECONDS;

/* ---- 自适应挂机(默认) + 会话周期轮换 ----
 * 实测根因(2026-09-12): 服务端只对"新鲜的桌面connect会话"计量使用时长；单条 clink
 *   MAIN 会话长期存活(实测连续12870秒)虽三通道心跳/子通道重连正常，却全程不计1003；
 *   一旦重新 connect 建立新会话，立即按约1:1恢复计分(新会话60秒即计67)。
 *   DISPLAY/INPUTS 子通道45秒被服务端踢除并重连无效，因桌面会话租约(connect token)未更新。
 * 对策: 每 g_session_rotate_secs(默认300秒) 主动整体重连(重新 connect，无需重新登录)，
 *   使每段都处于会计量的新鲜会话；同时每 g_task_check_secs 自查1003，拿满即止。 */
#define ADAPTIVE_MAX_SECONDS    21600  /* 硬上限6小时: 计划任务05:00启动 -> 11:00 兜底 */
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

static int crypto_init(void) {
    if (!CryptAcquireContext(&g_crypt, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptoAPI初始化失败: %lu\n", GetLastError());
        return 0;
    }
    NTSTATUS status = BCryptOpenAlgorithmProvider(&g_rsa_alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "CNG RSA算法提供者初始化失败: 0x%08X\n", (unsigned)status);
        CryptReleaseContext(g_crypt, 0);
        g_crypt = 0;
        return 0;
    }
    return 1;
}

static void sha256(const uint8_t *d, size_t n, uint8_t *out) {
    HCRYPTHASH h = 0;
    if (!CryptCreateHash(g_crypt, CALG_SHA_256, 0, 0, &h)) { memset(out, 0, 32); return; }
    if (!CryptHashData(h, (BYTE *)d, (DWORD)n, 0)) { CryptDestroyHash(h); memset(out, 0, 32); return; }
    DWORD dl = 32;
    if (!CryptGetHashParam(h, HP_HASHVAL, out, &dl, 0)) { memset(out, 0, 32); }
    CryptDestroyHash(h);
}

static const char HEX_LUT[] = "0123456789abcdef";

static size_t url_encode(const char *in, char *out, size_t out_sz) {
    static const uint8_t URL_SAFE[256] = {
        ['A']=1,['B']=1,['C']=1,['D']=1,['E']=1,['F']=1,['G']=1,['H']=1,
        ['I']=1,['J']=1,['K']=1,['L']=1,['M']=1,['N']=1,['O']=1,['P']=1,
        ['Q']=1,['R']=1,['S']=1,['T']=1,['U']=1,['V']=1,['W']=1,['X']=1,
        ['Y']=1,['Z']=1,
        ['a']=1,['b']=1,['c']=1,['d']=1,['e']=1,['f']=1,['g']=1,['h']=1,
        ['i']=1,['j']=1,['k']=1,['l']=1,['m']=1,['n']=1,['o']=1,['p']=1,
        ['q']=1,['r']=1,['s']=1,['t']=1,['u']=1,['v']=1,['w']=1,['x']=1,
        ['y']=1,['z']=1,
        ['0']=1,['1']=1,['2']=1,['3']=1,['4']=1,['5']=1,['6']=1,['7']=1,
        ['8']=1,['9']=1,
        ['-']=1,['_']=1,['.']=1,['~']=1
    };
    size_t j = 0;
    if (out_sz < 4) { if (out_sz > 0) out[0] = 0; return 0; }
    for (size_t i = 0; in[i] && j < out_sz - 4; i++) {
        unsigned char c = (unsigned char)in[i];
        if (URL_SAFE[c]) {
            out[j++] = in[i];
        } else {
            out[j++] = '%';
            out[j++] = HEX_LUT[c >> 4];
            out[j++] = HEX_LUT[c & 0x0F];
        }
    }
    out[j] = 0;
    return j;
}

static void sha256_hex(const char *s, char *out) {
    uint8_t d[32];
    sha256((const uint8_t *)s, strlen(s), d);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = HEX_LUT[d[i] >> 4];
        out[i * 2 + 1] = HEX_LUT[d[i] & 0x0F];
    }
    out[64] = 0;
}

static void md5_hex(const char *s, char *out) {
    HCRYPTHASH h;
    if (!CryptCreateHash(g_crypt, CALG_MD5, 0, 0, &h)) { out[0] = 0; return; }
    if (!CryptHashData(h, (BYTE *)s, (DWORD)strlen(s), 0)) { CryptDestroyHash(h); out[0] = 0; return; }
    uint8_t d[16];
    DWORD dl = 16;
    if (!CryptGetHashParam(h, HP_HASHVAL, d, &dl, 0)) { CryptDestroyHash(h); out[0] = 0; return; }
    CryptDestroyHash(h);
    for (int i = 0; i < 16; i++) {
        out[i * 2] = HEX_LUT[d[i] >> 4];
        out[i * 2 + 1] = HEX_LUT[d[i] & 0x0F];
    }
    out[32] = 0;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64enc(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        int r = n - i > 3 ? 3 : (int)(n - i);
        unsigned v = in[i] << 16;
        if (r > 1) v |= in[i + 1] << 8;
        if (r > 2) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = r > 1 ? B64[(v >> 6) & 63] : '=';
        out[o++] = r > 2 ? B64[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64dec(const char *in, size_t n, uint8_t *out) {
    size_t o = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=') break;
        int v = b64val(in[i]);
        if (v < 0) return 0;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (buf >> bits) & 0xFF; }
    }
    return o;
}

static char *jstr(const char *j, const char *k, char *buf, size_t bsz) {
    if (strlen(k) > 120) { buf[0] = 0; return buf; }
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) { buf[0] = 0; return buf; }
    p += strlen(srch);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') { buf[0] = 0; return buf; }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < bsz - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
                case 'n': buf[i++] = '\n'; break;
                case 't': buf[i++] = '\t'; break;
                case 'r': buf[i++] = '\r'; break;
                case '"': buf[i++] = '"';  break;
                case '\\': buf[i++] = '\\'; break;
                case '/': buf[i++] = '/';  break;
                default:  buf[i++] = *p;   break;
            }
            p++;
        } else {
            buf[i++] = *p++;
        }
    }
    buf[i] = 0;
    return buf;
}

static int jint(const char *j, const char *k) {
    if (strlen(k) > 120) return 0;
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) return 0;
    p += strlen(srch);
    while (*p == ' ' || *p == ':') p++;
    return atoi(p);
}

static const char *find_matching_brace(const char *start) {
    if (!start || *start != '{') return NULL;
    int depth = 0;
    const char *p = start;
    while (*p) {
        if (*p == '"') {
            p++;
            while (*p && *p != '"') {
                if (*p == '\\') p++;
                p++;
            }
            if (!*p) return NULL;
        } else if (*p == '{') {
            depth++;
        } else if (*p == '}') {
            depth--;
            if (depth == 0) return p;
        }
        p++;
    }
    return NULL;
}

#define JSON_MAX_DEPTH 16
#define JSON_MAX_STRING_LEN 8192
#define JSON_MAX_KEY_LEN 128
#define JSON_MAX_NUMBER_LEN 64

static int json_find_key_impl(const char *json, const char *key, const char **vstart, int *vlen, char *vtype, int depth);
static char *jstr_range_impl(const char *start, const char *end, const char *k, char *buf, size_t bsz);

static int json_find_key(const char *json, const char *key, const char **vstart, int *vlen, char *vtype) {
    return json_find_key_impl(json, key, vstart, vlen, vtype, 0);
}

static int json_find_key_impl(const char *json, const char *key, const char **vstart, int *vlen, char *vtype, int depth) {
    if (!json || !key || !vstart || !vlen || !vtype || depth > JSON_MAX_DEPTH) return 0;
    size_t key_len = strlen(key);
    if (key_len == 0 || key_len >= JSON_MAX_KEY_LEN) return 0;
    const char *p = json;
    size_t chars_since_quote_check = 0;

    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '"') {
            p++;
            size_t match = 0;
            const char *key_start = p;
            while (*p && *p != '"' && match < key_len && match < JSON_MAX_KEY_LEN) {
                if (*p == '\\') { p++; if (!*p) break; }
                if (*p == key[match]) match++;
                else break;
                p++;
            }
            if (match == key_len && *p == '"') {
                p++;
                while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
                if (*p == '"') {
                    *vtype = 's';
                    *vstart = ++p;
                    *vlen = 0;
                    chars_since_quote_check = 0;
                    while (*p && *p != '"' && *vlen < JSON_MAX_STRING_LEN) {
                        if (*p == '\\') { p++; chars_since_quote_check++; }
                        p++;
                        (*vlen)++;
                        chars_since_quote_check++;
                        if (chars_since_quote_check > JSON_MAX_STRING_LEN * 2) break;
                    }
                    return 1;
                } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
                    *vtype = 'n';
                    *vstart = p;
                    *vlen = 0;
                    while ((*p == '-' || (*p >= '0' && *p <= '9')) && *vlen < JSON_MAX_NUMBER_LEN) {
                        p++;
                        (*vlen)++;
                    }
                    return 1;
                } else if (p[0] == 't' && p[1] == 'r' && p[2] == 'u' && p[3] == 'e') {
                    *vtype = 'b';
                    *vstart = p;
                    *vlen = 4;
                    return 1;
                } else if (p[0] == 'f' && p[1] == 'a' && p[2] == 'l' && p[3] == 's' && p[4] == 'e') {
                    *vtype = 'b';
                    *vstart = p;
                    *vlen = 5;
                    return 1;
                }
            } else {
                while (*p && *p != '"') {
                    if (*p == '\\') p++;
                    p++;
                }
            }
        } else if (*p == '{') {
            const char *end = find_matching_brace(p);
            if (end) {
                if (json_find_key_impl(p + 1, key, vstart, vlen, vtype, depth + 1)) {
                    return 1;
                }
                p = end + 1;
            } else break;
        } else if (*p == '[') {
            p++;
            int bracket_depth = 1;
            while (*p && bracket_depth > 0) {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') { if (*p == '\\') p++; p++; }
                } else if (*p == '[') bracket_depth++;
                else if (*p == ']') bracket_depth--;
                p++;
            }
        } else p++;
    }
    return 0;
}

typedef struct {
    char device_code[128];
    char secret_key[128];
    char user_account[128];
    int user_id;
    int tenant_id;
    int logged_in;
} Session;

typedef struct {
    char desktop_id[64];
    char desktop_code[64];
    char *host;
    char *port;
    char *clink_host;
    char *ca_cert;
    char *client_cert;
    char *client_key;
    char *token;
    char *tenant_account;
    int is_active;
    char *connect_msg;
    char *ws_uri;
} Desktop;

static char *str_dup(const char *s) {
    if (!s || !s[0]) return NULL;
    size_t n = strlen(s) + 1;
    char *r = (char *)malloc(n);
    if (!r) return NULL;
    memcpy(r, s, n);
    return r;
}

static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    for (int i = 0; i < 8; i++)
        s[4 + i] = key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
    s[12] = counter;
    for (int i = 0; i < 3; i++)
        s[13 + i] = nonce[i * 4] | (nonce[i * 4 + 1] << 8) | (nonce[i * 4 + 2] << 16) | (nonce[i * 4 + 3] << 24);
    uint32_t w[16];
    memcpy(w, s, 64);
    for (int i = 0; i < 10; i++) {
        qr(&w[0],&w[4],&w[8],&w[12]); qr(&w[1],&w[5],&w[9],&w[13]);
        qr(&w[2],&w[6],&w[10],&w[14]); qr(&w[3],&w[7],&w[11],&w[15]);
        qr(&w[0],&w[5],&w[10],&w[15]); qr(&w[1],&w[6],&w[11],&w[12]);
        qr(&w[2],&w[7],&w[8],&w[13]); qr(&w[3],&w[4],&w[9],&w[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = w[i] + s[i];
        out[i * 4] = v & 0xFF;
        out[i * 4 + 1] = (v >> 8) & 0xFF;
        out[i * 4 + 2] = (v >> 16) & 0xFF;
        out[i * 4 + 3] = (v >> 24) & 0xFF;
    }
}

static void chacha20_xor(const uint8_t *src, size_t n, const uint8_t key[32],
                         const uint8_t nonce[12], uint32_t counter, uint8_t *out) {
    size_t off = 0;
    while (off < n) {
        uint8_t blk[64];
        chacha20_block(key, counter, nonce, blk);
        size_t r = n - off > 64 ? 64 : n - off;
        for (size_t i = 0; i < r; i++) out[off + i] = src[off + i] ^ blk[i];
        off += r;
        counter++;
    }
}

static void poly1305(const uint8_t *msg, size_t mlen, const uint8_t key[32], uint8_t tag[16]) {
    uint32_t r0 = key[0]|((uint32_t)key[1]<<8)|((uint32_t)key[2]<<16)|((uint32_t)key[3]<<24);
    uint32_t r1 = ((uint32_t)key[3]>>2)|((uint32_t)key[4]<<6)|((uint32_t)key[5]<<14)|((uint32_t)key[6]<<22);
    uint32_t r2 = ((uint32_t)key[6]>>4)|((uint32_t)key[7]<<4)|((uint32_t)key[8]<<12)|((uint32_t)key[9]<<20);
    uint32_t r3 = ((uint32_t)key[9]>>6)|((uint32_t)key[10]<<2)|((uint32_t)key[11]<<10)|((uint32_t)key[12]<<18);
    uint32_t r4 = ((uint32_t)key[12]>>8)|((uint32_t)key[13]<<0)|((uint32_t)key[14]<<8)|((uint32_t)key[15]<<16);
    r0 &= 0x3ffffff; r1 &= 0x3ffff03; r2 &= 0x3ffc0ff; r3 &= 0x3f03fff; r4 &= 0x00fffff;
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=0,h1=0,h2=0,h3=0,h4=0;
    size_t off = 0;
    while (off < mlen) {
        uint8_t blk[16] = {0};
        size_t r = mlen - off > 16 ? 16 : mlen - off;
        memcpy(blk, msg + off, r);
        uint32_t hibit = r == 16 ? (1u << 24) : 0;
        if (r < 16) blk[r] = 1;
        uint32_t t0=blk[0]|((uint32_t)blk[1]<<8)|((uint32_t)blk[2]<<16)|((uint32_t)blk[3]<<24);
        uint32_t t1=((uint32_t)blk[3]>>2)|((uint32_t)blk[4]<<6)|((uint32_t)blk[5]<<14)|((uint32_t)blk[6]<<22);
        uint32_t t2=((uint32_t)blk[6]>>4)|((uint32_t)blk[7]<<4)|((uint32_t)blk[8]<<12)|((uint32_t)blk[9]<<20);
        uint32_t t3=((uint32_t)blk[9]>>6)|((uint32_t)blk[10]<<2)|((uint32_t)blk[11]<<10)|((uint32_t)blk[12]<<18);
        uint32_t t4=((uint32_t)blk[12]>>8)|((uint32_t)blk[13]<<0)|((uint32_t)blk[14]<<8)|((uint32_t)blk[15]<<16);
        h0+=t0&0x3ffffff; h1+=t1&0x3ffffff; h2+=t2&0x3ffffff;
        h3+=t3&0x3ffffff; h4+=(t4&0x3ffffff)+hibit;
        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        h0=(uint32_t)d0&0x3ffffff; d1+=d0>>26;
        h1=(uint32_t)d1&0x3ffffff; d2+=d1>>26;
        h2=(uint32_t)d2&0x3ffffff; d3+=d2>>26;
        h3=(uint32_t)d3&0x3ffffff; d4+=d3>>26;
        h4=(uint32_t)d4&0x3ffffff; h0+=(uint32_t)(d4>>26)*5;
        h1+=h0>>26; h0&=0x3ffffff;
        off += r;
    }
    h2+=h1>>26; h1&=0x3ffffff;
    h3+=h2>>26; h2&=0x3ffffff;
    h4+=h3>>26; h3&=0x3ffffff;
    h0+=(h4>>26)*5; h4&=0x3ffffff;
    h1+=h0>>26; h0&=0x3ffffff;
    uint32_t g0=h0+5,g1=h1,g2=h2,g3=h3,g4=h4;
    g1+=g0>>26; g0&=0x3ffffff;
    g2+=g1>>26; g1&=0x3ffffff;
    g3+=g2>>26; g2&=0x3ffffff;
    g4+=g3>>26; g3&=0x3ffffff;
    g4-=1u<<26;
    if(!(g4>>31)){h0=g0;h1=g1;h2=g2;h3=g3;h4=g4;}
    uint32_t f0=(h0|(h1<<26))&0xffffffff;
    uint32_t f1=((h1>>6)|(h2<<20))&0xffffffff;
    uint32_t f2=((h2>>12)|(h3<<14))&0xffffffff;
    uint32_t f3=((h3>>18)|(h4<<8))&0xffffffff;
    uint32_t k0=key[16]|(key[17]<<8)|(key[18]<<16)|(key[19]<<24);
    uint32_t k1=key[20]|(key[21]<<8)|(key[22]<<16)|(key[23]<<24);
    uint32_t k2=key[24]|(key[25]<<8)|(key[26]<<16)|(key[27]<<24);
    uint32_t k3=key[28]|(key[29]<<8)|(key[30]<<16)|(key[31]<<24);
    uint64_t ff0=f0,ff1=f1,ff2=f2,ff3=f3;
    ff0+=k0; ff1+=k1+(ff0>>32); ff0&=0xffffffff;
    ff2+=k2+(ff1>>32); ff1&=0xffffffff;
    ff3+=k3+(ff2>>32); ff2&=0xffffffff; ff3&=0xffffffff;
    f0=(uint32_t)ff0; f1=(uint32_t)ff1; f2=(uint32_t)ff2; f3=(uint32_t)ff3;
    tag[0]=(uint8_t)f0;tag[1]=(uint8_t)(f0>>8);tag[2]=(uint8_t)(f0>>16);tag[3]=(uint8_t)(f0>>24);
    tag[4]=(uint8_t)f1;tag[5]=(uint8_t)(f1>>8);tag[6]=(uint8_t)(f1>>16);tag[7]=(uint8_t)(f1>>24);
    tag[8]=(uint8_t)f2;tag[9]=(uint8_t)(f2>>8);tag[10]=(uint8_t)(f2>>16);tag[11]=(uint8_t)(f2>>24);
    tag[12]=(uint8_t)f3;tag[13]=(uint8_t)(f3>>8);tag[14]=(uint8_t)(f3>>16);tag[15]=(uint8_t)(f3>>24);
}

static void build_poly1305_data(const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t off = 0;
    size_t need = aad_len + 16 + ct_len + 16 + 16;
    if (need > out_cap) { *out_len = 0; return; }
    if (aad_len > 0 && aad) {
        memcpy(out + off, aad, aad_len);
        off += aad_len;
        if (aad_len % 16 != 0) {
            size_t pad = 16 - (aad_len % 16);
            memset(out + off, 0, pad);
            off += pad;
        }
    }
    if (ct_len > 0 && ct) {
        memcpy(out + off, ct, ct_len);
        off += ct_len;
    }
    if (ct_len % 16 != 0) {
        size_t pad = 16 - (ct_len % 16);
        memset(out + off, 0, pad);
        off += pad;
    }
    uint64_t aad_len64 = aad_len;
    uint64_t ct_len64 = ct_len;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)((aad_len64 >> (i * 8)) & 0xFF);
        out[off + 8 + i] = (uint8_t)((ct_len64 >> (i * 8)) & 0xFF);
    }
    off += 16;
    *out_len = off;
}

#define AEAD_STACK_BUF_SIZE 256

static int aead_open(const uint8_t *ct, size_t ctlen, const uint8_t key[32],
                     const uint8_t nonce[12], uint8_t *pt) {
    if (ctlen < 16) return 0;
    size_t dlen = ctlen - 16;
    const uint8_t *tag = ct + dlen;
    uint8_t blk0[64];
    chacha20_block(key, 0, nonce, blk0);
    size_t mac_buf_sz = dlen + 64 + 16;
    uint8_t stack_buf[AEAD_STACK_BUF_SIZE];
    uint8_t *mac_data = (mac_buf_sz <= AEAD_STACK_BUF_SIZE) ? stack_buf : (uint8_t *)malloc(mac_buf_sz);
    if (!mac_data) return 0;
    size_t mac_len = 0;
    build_poly1305_data(NULL, 0, ct, dlen, mac_data, mac_buf_sz, &mac_len);
    uint8_t expected[16];
    poly1305(mac_data, mac_len, blk0, expected);
    if (mac_data != stack_buf) free(mac_data);
    {
        volatile uint8_t diff = 0;
        for (int ci = 0; ci < 16; ci++) diff |= tag[ci] ^ expected[ci];
        if (diff != 0) return 0;
    }
    chacha20_xor(ct, dlen, key, nonce, 1, pt);
    pt[dlen] = 0;
    return 1;
}

static int decrypt_data(const char *b64, const uint8_t key[32], char *out, size_t out_sz) {
    size_t b64len = strlen(b64);
    size_t data_cap = b64len / 4 * 3 + 4;
    uint8_t *data = (uint8_t *)malloc(data_cap);
    size_t dlen = b64dec(b64, b64len, data);
    if (dlen == 0) { free(data); return 0; }
    if (dlen < 12 + 16) { free(data); return 0; }
    uint8_t *pt = (uint8_t *)malloc(dlen);
    int ok = aead_open(data + 12, dlen - 12, key, data, pt);
    if (ok) {
        size_t pt_len = dlen - 12 - 16;
        if (pt_len >= out_sz) pt_len = out_sz - 1;
        memcpy(out, pt, pt_len);
        out[pt_len] = '\0';
    }
    free(pt);
    free(data);
    return ok;
}

static int get_all_macs(char macs[][32], int max_macs);
static void mac_to_fingerprint(const char *mac, char *fp_hex);
static void get_fingerprint(char *fp_hex);

static void derive_key_legacy(const char *fp, const char *salt, uint8_t key[32]) {
    char material[256];
    snprintf(material, sizeof(material), "%s|%s", fp, salt);
    sha256((const uint8_t *)material, strlen(material), key);
}

static void derive_key(const char *fp, const char *salt, uint8_t key[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        derive_key_legacy(fp, salt, key);
        return;
    }
    ULONGLONG iterations = 100000;
    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)fp, (ULONG)strlen(fp),
        (PUCHAR)salt, (ULONG)strlen(salt),
        iterations,
        key, 32,
        0
    );
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        derive_key_legacy(fp, salt, key);
    }
}

static int unprotect_data_dpapi(const uint8_t *ciphertext, DWORD cipher_len,
                                 const char *entropy,
                                 uint8_t **out, DWORD *out_len) {
    DATA_BLOB data_in = { cipher_len, (BYTE *)ciphertext };
    DATA_BLOB data_out = { 0, NULL };
    DATA_BLOB entropy_blob = { 0, NULL };
    if (entropy && entropy[0]) {
        entropy_blob.cbData = (DWORD)strlen(entropy);
        entropy_blob.pbData = (BYTE *)entropy;
    }
    DWORD flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;
    BOOL result = CryptUnprotectData(
        &data_in, NULL,
        entropy ? &entropy_blob : NULL,
        NULL, NULL, flags, &data_out
    );
    if (result) {
        *out = data_out.pbData;
        *out_len = data_out.cbData;
        return 1;
    }
    return 0;
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

static void desktop_free(Desktop *d) {
    free(d->connect_msg); d->connect_msg = NULL;
    free(d->ws_uri); d->ws_uri = NULL;
    free(d->host); d->host = NULL;
    free(d->port); d->port = NULL;
    free(d->clink_host); d->clink_host = NULL;
    free(d->ca_cert); d->ca_cert = NULL;
    free(d->client_cert); d->client_cert = NULL;
    free(d->client_key); d->client_key = NULL;
    free(d->token); d->token = NULL;
    free(d->tenant_account); d->tenant_account = NULL;
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

static int http_init(void) {
    g_inet = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_inet) return 0;
    WinHttpSetTimeouts(g_inet, DNS_RESOLVE_TIMEOUT_MS, WINHTTP_CONNECT_TIMEOUT_MS, WINHTTP_SEND_TIMEOUT_MS, WINHTTP_RECEIVE_TIMEOUT_MS);
    return 1;
}

static int http_req(const char *method, const char *url, const char *body, size_t blen,
                    const char *ct, const char **hdrs, int nhdrs,
                    char *resp, size_t rsz) {
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    WCHAR whostname[256], wurl_path[2048];
    uc.lpszHostName = whostname; uc.dwHostNameLength = sizeof(whostname)/sizeof(WCHAR);
    uc.lpszUrlPath = wurl_path; uc.dwUrlPathLength = sizeof(wurl_path)/sizeof(WCHAR);
    WCHAR wurl[4096];
    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 4096);
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        log_line("URL解析失败: %s", url);
        return -1;
    }
    WCHAR wmethod[16] = {0};
    MultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 16);

    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) {
        char hname[256];
        WideCharToMultiByte(CP_ACP, 0, whostname, -1, hname, sizeof(hname), NULL, NULL);
        log_line("连接服务器失败: %s:%d 错误=%lu", hname, uc.nPort, GetLastError());
        return -1;
    }

    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) {
        log_line("创建HTTP请求失败: 错误=%lu", GetLastError());
        WinHttpCloseHandle(hconn);
        return -1;
    }

    if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    for (int i = 0; i < nhdrs; i++) {
        WCHAR whdr[512];
        MultiByteToWideChar(CP_ACP, 0, hdrs[i], -1, whdr, 512);
        WinHttpAddRequestHeaders(hreq, whdr, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (ct) {
        char h[256]; snprintf(h, sizeof(h), "Content-Type: %s", ct);
        WCHAR wh[256]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 256);
        WinHttpAddRequestHeaders(hreq, wh, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (void *)body, (DWORD)blen, (DWORD)blen, 0)) {
        log_line("发送HTTP请求失败: 错误=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    if (!WinHttpReceiveResponse(hreq, NULL)) {
        log_line("接收HTTP响应失败: 错误=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    DWORD total = 0, n;
    while (WinHttpReadData(hreq, resp + total, (DWORD)(rsz - total - 1), &n) && n > 0) {
        total += n;
        if (total >= rsz - 1) break;
    }
    resp[total] = 0;

    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    return (int)total;
}

static int http_get_binary(const char *url, const char **hdrs, int nhdrs,
                           uint8_t *resp, size_t rsz) {
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    WCHAR whostname[256], wurl_path[2048];
    uc.lpszHostName = whostname; uc.dwHostNameLength = sizeof(whostname)/sizeof(WCHAR);
    uc.lpszUrlPath = wurl_path; uc.dwUrlPathLength = sizeof(wurl_path)/sizeof(WCHAR);
    WCHAR wurl[4096];
    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 4096);
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return -1;

    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) return -1;
    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, L"GET", wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) { WinHttpCloseHandle(hconn); return -1; }
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }
    for (int i = 0; i < nhdrs; i++) {
        WCHAR whdr[512]; MultiByteToWideChar(CP_ACP, 0, hdrs[i], -1, whdr, 512);
        WinHttpAddRequestHeaders(hreq, whdr, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }
    DWORD total = 0, n;
    while (WinHttpReadData(hreq, resp + total, (DWORD)(rsz - total), &n) && n > 0) {
        total += n;
        if (total >= rsz) break;
    }
    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    return (int)total;
}

static __declspec(thread) char g_bh1[64], g_bh2[64], g_bh3[128], g_bh5[64], g_bh6[256];
static void make_base_headers(const Session *s, const char **hdrs, int *nhdrs) {
    snprintf(g_bh1, sizeof(g_bh1), "ctg-devicetype: 60");
    snprintf(g_bh2, sizeof(g_bh2), "ctg-version: 103020001");
    snprintf(g_bh3, sizeof(g_bh3), "ctg-devicecode: %s", s->device_code);
    snprintf(g_bh5, sizeof(g_bh5), "referer: https://pc.ctyun.cn/");
    snprintf(g_bh6, sizeof(g_bh6), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
    hdrs[0] = g_bh6; hdrs[1] = g_bh1; hdrs[2] = g_bh2; hdrs[3] = g_bh3; hdrs[4] = g_bh5;
    *nhdrs = 5;
}

static __declspec(thread) char g_sh1[64], g_sh2[64], g_sh3[128], g_sh4[64], g_sh5[64], g_sh6[64], g_sh7[256];
static __declspec(thread) char g_shts[64], g_shri[64], g_shsig[128];
static __declspec(thread) char g_shcombined[512], g_shsig_hex[33];
static void make_sig_headers(const Session *s, const char **hdrs, int *nhdrs) {
    snprintf(g_sh1, sizeof(g_sh1), "ctg-devicetype: 60");
    snprintf(g_sh2, sizeof(g_sh2), "ctg-version: 103020001");
    snprintf(g_sh3, sizeof(g_sh3), "ctg-devicecode: %s", s->device_code);
    snprintf(g_sh5, sizeof(g_sh5), "referer: https://pc.ctyun.cn/");
    snprintf(g_sh7, sizeof(g_sh7), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
    long long ts = (long long)time(NULL) * 1000LL;
    snprintf(g_sh4, sizeof(g_sh4), "ctg-userid: %d", s->user_id);
    snprintf(g_sh6, sizeof(g_sh6), "ctg-tenantid: %d", s->tenant_id);
    snprintf(g_shts, sizeof(g_shts), "ctg-timestamp: %lld", ts);
    snprintf(g_shri, sizeof(g_shri), "ctg-requestid: %lld", ts);
    snprintf(g_shcombined, sizeof(g_shcombined), "60%lld%d%lld%d103020001%s",
             ts, s->tenant_id, ts, s->user_id, s->secret_key);
    md5_hex(g_shcombined, g_shsig_hex);
    snprintf(g_shsig, sizeof(g_shsig), "ctg-signaturestr: %s", g_shsig_hex);
    hdrs[0] = g_sh7; hdrs[1] = g_sh1; hdrs[2] = g_sh2; hdrs[3] = g_sh3; hdrs[4] = g_sh5;
    hdrs[5] = g_sh4; hdrs[6] = g_sh6; hdrs[7] = g_shts; hdrs[8] = g_shri; hdrs[9] = g_shsig;
    *nhdrs = 10;
}

static int api_post_noauth(const Session *s, const char *url, const char *body, size_t blen,
                           const char *ct, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_base_headers(s, hdrs, &nhdrs);
    return http_req("POST", url, body, blen, ct, hdrs, nhdrs, resp, rsz);
}

static int api_post(const Session *s, const char *url, const char *body, size_t blen,
                    const char *ct, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("POST", url, body, blen, ct, hdrs, nhdrs, resp, rsz);
}

static int api_get_binary(const Session *s, const char *url, uint8_t *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_get_binary(url, hdrs, nhdrs, resp, rsz);
}

/* 带签名头的 GET 请求(返回文本 JSON)。仅用于测试验证积分任务进度。 */
static int api_get_text(const Session *s, const char *url, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("GET", url, NULL, 0, NULL, hdrs, nhdrs, resp, rsz);
}

static int read_manual_captcha(char *out, size_t out_sz) {
    printf("请输入验证码："); fflush(stdout);
    if (!fgets(out, (int)out_sz, stdin)) return 0;
    out[strcspn(out, "\r\n")] = 0;
    return out[0] ? 1 : 0;
}

static int try_captcha_ocr(const Session *s, const char *user,
                           char *captcha_out, size_t co_sz,
                           uint8_t **img_out, int *img_len_out) {
    char captcha_url[512];
    long long t = (long long)time(NULL) * 1000LL;

    if (user) {
        snprintf(captcha_url, sizeof(captcha_url),
                 "https://desk.ctyun.cn:8810/api/auth/client/captcha?height=36&width=85&userInfo=%s&mode=auto&_t=%lld",
                 user, t);
    } else {
        snprintf(captcha_url, sizeof(captcha_url),
                 "https://desk.ctyun.cn:8810/api/auth/client/validateCode/captcha?width=120&height=40&_t=%lld", t);
    }

    uint8_t *img = (uint8_t *)malloc(CAPTCHA_IMG_BUF);
    int img_len;
    if (user) {
        const char *hdrs[16];
        int nhdrs = 0;
        make_base_headers(s, hdrs, &nhdrs);
        img_len = http_get_binary(captcha_url, hdrs, nhdrs, img, CAPTCHA_IMG_BUF);
    } else {
        img_len = api_get_binary(s, captcha_url, img, CAPTCHA_IMG_BUF);
    }
    if (img_len <= 0) {
        log_line("验证码图片下载失败");
        free(img);
        return 0;
    }

    *img_out = img;
    *img_len_out = img_len;

    size_t b64_cap = ((img_len + 2) / 3 * 4 + 1);
    char *img_b64 = (char *)malloc(b64_cap);
    b64enc(img, img_len, img_b64);

    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----ctyun%08x", (unsigned)GetTickCount());
    size_t b64len = strlen(img_b64);
    size_t body_len = 256 + b64len;
    char *body = (char *)malloc(body_len);
    int blen = snprintf(body, body_len,
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"image\"\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, img_b64, boundary);
    free(img_b64);

    char ct_hdr[256];
    snprintf(ct_hdr, sizeof(ct_hdr), "multipart/form-data; boundary=%s", boundary);
    const char *ocr_hdrs[16];
    int nhdrs = 0;
    make_base_headers(s, ocr_hdrs, &nhdrs);
    char orc_resp[OCR_RESP_BUF];
    int rlen = http_req("POST", OCR_SERVICE_URL, body, blen, ct_hdr, ocr_hdrs, nhdrs, orc_resp, sizeof(orc_resp));
    free(body);
    if (rlen <= 0) {
        log_line("OCR接口连接失败");
        return 1;
    }
    orc_resp[rlen] = 0;

    jstr(orc_resp, "data", captcha_out, co_sz);
    if (!captcha_out[0]) {
        log_line("OCR识别结果为空");
        return 1;
    }
    log_line("OCR识别成功: %s", captcha_out);
    return 2;
}

static int do_login_send(Session *s, const char *user, const char *final_sha, const char *sha2_pwd,
                         const char *cid, const char *captcha, char *resp, size_t resp_sz) {
    char enc_cid[512], enc_dc[512];
    url_encode(cid, enc_cid, sizeof(enc_cid));
    url_encode(s->device_code, enc_dc, sizeof(enc_dc));

    char post[4096];
    snprintf(post, sizeof(post),
             "userAccount=%s&password=%s&sha256Password=%s&challengeId=%s&captchaCode=%s"
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
             user, final_sha, sha2_pwd, enc_cid, captcha, enc_dc);

    if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/login",
                        post, strlen(post), "application/x-www-form-urlencoded",
                        resp, (int)resp_sz) < 0) {
        return -2;
    }

    int code = jint(resp, "code");
    if (code != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        if (strcmp(msg, "\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf") == 0) {
            return -1;
        }
        return 0;
    }

    const char *data_start = strstr(resp, "\"data\"");
    if (!data_start) return 0;
    data_start = strchr(data_start, '{');
    if (!data_start) return 0;

    const char *vstart;
    int vlen;
    char vtype;

    if (json_find_key(data_start, "secretKey", &vstart, &vlen, &vtype) && vtype == 's') {
        int copy_len = vlen < (int)sizeof(s->secret_key) - 1 ? vlen : (int)sizeof(s->secret_key) - 1;
        memcpy(s->secret_key, vstart, copy_len);
        s->secret_key[copy_len] = 0;
    }
    if (json_find_key(data_start, "userAccount", &vstart, &vlen, &vtype) && vtype == 's') {
        int copy_len = vlen < (int)sizeof(s->user_account) - 1 ? vlen : (int)sizeof(s->user_account) - 1;
        memcpy(s->user_account, vstart, copy_len);
        s->user_account[copy_len] = 0;
    }
    if (json_find_key(data_start, "userId", &vstart, &vlen, &vtype) && vtype == 'n') {
        char num_buf[32];
        int copy_len = vlen < 31 ? vlen : 31;
        memcpy(num_buf, vstart, copy_len);
        num_buf[copy_len] = 0;
        s->user_id = atoi(num_buf);
    }
    if (json_find_key(data_start, "tenantId", &vstart, &vlen, &vtype) && vtype == 'n') {
        char num_buf[32];
        int copy_len = vlen < 31 ? vlen : 31;
        memcpy(num_buf, vstart, copy_len);
        num_buf[copy_len] = 0;
        s->tenant_id = atoi(num_buf);
    }

    s->logged_in = s->secret_key[0] ? 1 : 0;
    SecureZeroMemory(post, sizeof(post));
    if (getenv("CTYUN_DUMP_AUTH")) {
        char tmp[MAX_PATH], full[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        snprintf(full, sizeof(full), "%sctyun_auth_debug.json", tmp);
        FILE *df = fopen(full, "wb");
        if (df) {
            fprintf(df, "{\"device_code\":\"%s\",\"login_resp\":%s}\n", s->device_code, resp);
            fclose(df);
            log_line("[dumpauth] 已转储登录响应到 %s", full);
        }
    }
    return 1;
}

static int manual_captcha_mode(void) {
    const char *v = getenv("CTYUN_MANUAL_CAPTCHA");
    return (v && v[0] == '1') ? 1 : 0;
}

static int do_login(Session *s, const char *user, const char *pwd) {
    uint8_t *img_data = NULL;
    int img_len = 0;
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;

    int manual_mode = manual_captcha_mode();
    int max_attempts = manual_mode ? MAX_MANUAL_CAPTCHA_ATTEMPTS : MAX_LOGIN_ATTEMPTS;

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData",
                            "{}", 2, "application/json", resp, MAX_RESP) < 0) {
            log_line("获取挑战码失败 (尝试%d)", attempt);
            continue;
        }
        int code = jint(resp, "code");
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            log_line("获取挑战码错误: %s", msg);
            continue;
        }
        char cid[128], ccode[128];
        jstr(resp, "challengeId", cid, sizeof(cid));
        jstr(resp, "challengeCode", ccode, sizeof(ccode));
        if (!cid[0]) { log_line("挑战码为空"); continue; }

        char final_sha[65], sha2_pwd[65];
        {
            char combined[512];
            snprintf(combined, sizeof(combined), "%s%s", pwd, ccode);
            sha256_hex(combined, final_sha);
            char pwd_sha[65];
            sha256_hex(pwd, pwd_sha);
            char sha2_combined[512];
            snprintf(sha2_combined, sizeof(sha2_combined), "%s%s", pwd_sha, ccode);
            sha256_hex(sha2_combined, sha2_pwd);
        }

        char captcha[64] = "";

        if (manual_mode) {
            try_captcha_ocr(s, user, captcha, sizeof(captcha), &img_data, &img_len);
            printf("验证码图片已获取，请查看后输入验证码\n");
            if (img_data && img_len > 0) {
                char tmp_path[MAX_PATH];
                GetTempPathA(MAX_PATH, tmp_path);
                char img_path[MAX_PATH];
                snprintf(img_path, sizeof(img_path), "%sctyun_captcha.png", tmp_path);
                FILE *f = fopen(img_path, "wb");
                if (f) {
                    fwrite(img_data, 1, img_len, f);
                    fclose(f);
                    ShellExecuteA(NULL, "open", img_path, NULL, NULL, SW_SHOW);
                    log_line("验证码已保存到: %s 并已打开", img_path);
                }
            }
            if (!read_manual_captcha(captcha, sizeof(captcha))) {
                log_line("验证码输入为空 (尝试%d)", attempt);
                if (img_data) { free(img_data); img_data = NULL; }
                continue;
            }
        } else {
            int ocr_result = try_captcha_ocr(s, user, captcha, sizeof(captcha), &img_data, &img_len);
            if (ocr_result < 2) {
                log_line("OCR识别失败，切换手工输入");
                if (img_data) { free(img_data); img_data = NULL; }
                if (!read_manual_captcha(captcha, sizeof(captcha))) {
                    log_line("验证码输入为空 (尝试%d)", attempt);
                    continue;
                }
            }
        }

        log_line("正在发送登录请求 (尝试%d)...", attempt);
        int result = do_login_send(s, user, final_sha, sha2_pwd, cid, captcha, resp, MAX_RESP);
        SecureZeroMemory(final_sha, sizeof(final_sha));
        SecureZeroMemory(sha2_pwd, sizeof(sha2_pwd));
        if (img_data) { free(img_data); img_data = NULL; }
        if (result == 1) {
            log_line("登录成功: userId=%d, tenantId=%d", s->user_id, s->tenant_id);
            free(resp);
            return 1;
        }
        if (result == -1) {
            log_line("用户名或密码错误");
            free(resp);
            return 0;
        }
    }

    log_line("登录失败，验证码错误次数过多");
    free(resp);
    return 0;
}

static int get_desktop_list(Session *s, Desktop *desktops, int max) {
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    char body[] = "{\"getCnt\":20,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}";
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
                 body, strlen(body), "application/json", resp, MAX_RESP) < 0) {
        log_line("获取桌面列表请求失败");
        free(resp);
        return 0;
    }
    if (jint(resp, "code") != 0) {
        log_line("获取桌面列表错误: code=%d", jint(resp, "code"));
        free(resp);
        return 0;
    }
    log_line("获取桌面列表成功，正在解析桌面信息");

    const char *dl = strstr(resp, "\"desktopList\"");
    if (!dl) { free(resp); return 0; }
    dl = strchr(dl, '[');
    if (!dl) { free(resp); return 0; }

    int count = 0;
    const char *p = dl;
    while (count < max) {
        const char *obj = strchr(p, '{');
        if (!obj) break;
        const char *end = find_matching_brace(obj);
        if (!end) break;

        jstr_range_impl(obj, end + 1, "desktopId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        if (!desktops[count].desktop_id[0])
            jstr_range_impl(obj, end + 1, "objId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        jstr_range_impl(obj, end + 1, "desktopCode", desktops[count].desktop_code, sizeof(desktops[count].desktop_code));
        char status[64];
        jstr_range_impl(obj, end + 1, "useStatusText", status, sizeof(status));
        desktops[count].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
        desktops[count].host = NULL;
        desktops[count].port = NULL;
        desktops[count].clink_host = NULL;
        desktops[count].ca_cert = NULL;
        desktops[count].client_cert = NULL;
        desktops[count].client_key = NULL;
        desktops[count].token = NULL;
        desktops[count].tenant_account = NULL;
        desktops[count].connect_msg = NULL;
        desktops[count].ws_uri = NULL;

        log_line("桌面[%d]: id=%s code=%s 状态=%s 运行中=%d",
                 count, desktops[count].desktop_id, desktops[count].desktop_code,
                 status, desktops[count].is_active);
        count++;
        p = end + 1;
    }

    free(resp);
    return count;
}

static char *jstr_range_impl(const char *start, const char *end, const char *k, char *buf, size_t bsz) {
    if (strlen(k) > 120) { buf[0] = 0; return buf; }
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *key_start = start;
    const char *p = NULL;
    size_t nlen = strlen(srch);
    for (const char *cp = start; cp + nlen <= end; cp++) {
        if (*cp == srch[0] && memcmp(cp, srch, nlen) == 0) {
            p = cp + nlen;
            break;
        }
    }
    if (!p) { buf[0] = 0; return buf; }
    while (p < end && (*p == ' ' || *p == ':')) p++;
    if (p >= end || *p != '"') { buf[0] = 0; return buf; }
    p++;
    size_t i = 0;
    while (p < end && *p && *p != '"' && i < bsz - 1) {
        if (*p == '\\' && (p + 1) < end) {
            p++;
            switch (*p) {
                case 'n': buf[i++] = '\n'; break;
                case 't': buf[i++] = '\t'; break;
                case 'r': buf[i++] = '\r'; break;
                case '"': buf[i++] = '"';  break;
                case '\\': buf[i++] = '\\'; break;
                case '/': buf[i++] = '/';  break;
                default:  buf[i++] = *p;   break;
            }
            p++;
        } else {
            buf[i++] = *p++;
        }
    }
    buf[i] = 0;
    return buf;
}

static int connect_desktop(Session *s, Desktop *d) {
    char post[4096];
    snprintf(post, sizeof(post),
             "objId=%s&objType=0&osType=15&deviceId=60&vdCommand=&ipAddress=&macAddress="
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
             d->desktop_id, s->device_code);

    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/connect",
                 post, strlen(post), "application/x-www-form-urlencoded",
                 resp, MAX_RESP) < 0) {
        log_line("连接桌面请求失败: %s", d->desktop_id);
        free(resp);
        return 0;
    }

    if (jint(resp, "code") != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        log_line("连接桌面错误 [%s]: %s", d->desktop_id, msg);
        free(resp);
        return 0;
    }

    static const char *info_keys[] = { "desktopInfo", "shadowDesktopInfo", "desktopAnywhereInfo" };
    char tmp[16384];

    for (int ki = 0; ki < 3; ki++) {
        char key_pattern[64];
        snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", info_keys[ki]);
        const char *di = strstr(resp, key_pattern);
        if (!di) continue;
        di = strchr(di, '{');
        if (!di) continue;
        const char *di_end = find_matching_brace(di);
        if (!di_end) continue;

        jstr_range_impl(di, di_end + 1, "host", tmp, sizeof(tmp));
        d->host = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "port", tmp, sizeof(tmp));
        d->port = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "clinkLvsOutHost", tmp, sizeof(tmp));
        d->clink_host = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "caCert", tmp, sizeof(tmp));
        d->ca_cert = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "clientCert", tmp, sizeof(tmp));
        d->client_cert = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "clientKey", tmp, sizeof(tmp));
        d->client_key = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "token", tmp, sizeof(tmp));
        d->token = str_dup(tmp);
        jstr_range_impl(di, di_end + 1, "tenantMemberAccount", tmp, sizeof(tmp));
        d->tenant_account = str_dup(tmp);

        log_line("[%s] 连接桌面成功: host=%s port=%s clink=%s [来源:%s]",
                 d->desktop_code,
                 d->host ? d->host : "", d->port ? d->port : "",
                 d->clink_host ? d->clink_host : "", info_keys[ki]);

        if (d->host && d->host[0]) break;

        free(d->host); d->host = NULL;
        free(d->port); d->port = NULL;
        free(d->clink_host); d->clink_host = NULL;
        free(d->ca_cert); d->ca_cert = NULL;
        free(d->client_cert); d->client_cert = NULL;
        free(d->client_key); d->client_key = NULL;
        free(d->token); d->token = NULL;
        free(d->tenant_account); d->tenant_account = NULL;
    }

    free(resp);
    if (!d->host || !d->host[0]) {
        desktop_free(d);
        return 0;
    }
    if (!d->ca_cert || !d->client_cert || !d->client_key) {
        desktop_free(d);
        return 0;
    }
    return 1;
}

static size_t rsa_oaep_encrypt(const uint8_t *n_bytes, size_t n_len, uint32_t e_val, uint8_t *result) {
    const uint8_t *mod_bytes = n_bytes;
    size_t mod_len = n_len;
    while (mod_len > 1 && mod_bytes[0] == 0) { mod_bytes++; mod_len--; }

    BCRYPT_RSAKEY_BLOB rsakb = {0};
    rsakb.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    rsakb.BitLength = (ULONG)(mod_len * 8);
    rsakb.cbPublicExp = 3;
    rsakb.cbModulus = (ULONG)mod_len;
    rsakb.cbPrime1 = 0;
    rsakb.cbPrime2 = 0;

    uint8_t e_be[3] = {(uint8_t)(e_val>>16), (uint8_t)(e_val>>8), (uint8_t)(e_val)};

    DWORD blob_len = sizeof(BCRYPT_RSAKEY_BLOB) + 3 + (ULONG)mod_len;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    memcpy(blob, &rsakb, sizeof(BCRYPT_RSAKEY_BLOB));
    memcpy(blob + sizeof(BCRYPT_RSAKEY_BLOB), e_be, 3);
    uint8_t *modulus = blob + sizeof(BCRYPT_RSAKEY_BLOB) + 3;
    memcpy(modulus, mod_bytes, mod_len);

    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptImportKeyPair(g_rsa_alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                           &hKey, blob, blob_len, 0);
    free(blob);
    if (!BCRYPT_SUCCESS(status)) {
        log_line("RSA公钥导入失败: 0x%08X", (unsigned)status);
        return 0;
    }

    BCRYPT_OAEP_PADDING_INFO oaep_info = {0};
    oaep_info.pszAlgId = BCRYPT_SHA1_ALGORITHM;

    uint8_t empty_msg[] = {0};
    ULONG ct_len = 0;
    status = BCryptEncrypt(hKey, empty_msg, 0, &oaep_info, NULL, 0,
                           result, (ULONG)mod_len, &ct_len, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        log_line("RSA加密失败: 0x%08X", (unsigned)status);
        return 0;
    }
    return ct_len;
}

static int handle_redq(const uint8_t *msg, size_t mlen, uint8_t *resp, size_t *rlen) {
    if (mlen < 16 || memcmp(msg, "REDQ", 4) != 0) return 0;
    const uint8_t *key_data = msg + 16;
    if (mlen - 16 < 166) return 0;

    const uint8_t *n_source = key_data + 32;
    const uint8_t *e_source = key_data + 163;
    uint32_t e_val = (e_source[0]<<16)|(e_source[1]<<8)|e_source[2];
    if (e_val == 0) return 0;

    uint8_t encrypted[512];
    size_t enc_len = rsa_oaep_encrypt(n_source, 129, e_val, encrypted);
    if (enc_len == 0) return 0;

    uint32_t auth = 1;
    resp[0]=auth&0xFF; resp[1]=(auth>>8)&0xFF; resp[2]=(auth>>16)&0xFF; resp[3]=(auth>>24)&0xFF;
    memcpy(resp+4, encrypted, enc_len);
    *rlen = 4 + enc_len;
    return 1;
}

static uint8_t initial_payload[] = {
    0x52,0x45,0x44,0x51,0x02,0x00,0x00,
    0x00,0x02,0x00,0x00,0x00,0x1A,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x12,
    0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x04,
    0x08,0x00,0x00
};

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    HINTERNET hWebSocket;
} WSConn;

static int ws_connect(const char *uri, WSConn *wsc, const char *desktop_code) {
    memset(wsc, 0, sizeof(WSConn));
    char host[256] = "", path[2048] = "/";
    int port = 443;
    int use_ssl = 0;

    const char *hp = strstr(uri, "://");
    if (hp) {
        if (_strnicmp(uri, "wss://", 6) == 0) use_ssl = 1;
        hp += 3;
    } else {
        hp = uri;
    }
    const char *sl = strchr(hp, '/');
    if (sl) {
        int hlen = (int)(sl - hp);
        if (hlen >= (int)sizeof(host)) hlen = (int)sizeof(host) - 1;
        memcpy(host, hp, hlen); host[hlen] = 0;
        strncpy(path, sl, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, hp, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    char *colon = strchr(host, ':');
    if (colon) { *colon = 0; port = atoi(colon + 1); }
    if (use_ssl && port == 80) port = 443;

    log_line("[%s] 正在连接WebSocket: host=%s port=%d ssl=%d", desktop_code, host, port, use_ssl);

    wsc->hSession = WinHttpOpen(L"CtYunPoints/" APP_VERSION, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!wsc->hSession) {
        log_line("[%s] HTTP会话创建失败: %lu", desktop_code, GetLastError());
        return 0;
    }

    WCHAR whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    wsc->hConnect = WinHttpConnect(wsc->hSession, whost, (INTERNET_PORT)port, 0);
    if (!wsc->hConnect) {
        log_line("[%s] HTTP连接失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    WCHAR wpath[2048] = {0};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 2048);
    DWORD flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
    wsc->hRequest = WinHttpOpenRequest(wsc->hConnect, L"GET", wpath, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!wsc->hRequest) {
        log_line("[%s] HTTP请求创建失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    if (use_ssl) {
        DWORD opt_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(wsc->hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opt_flags, sizeof(opt_flags));
    }

    WinHttpAddRequestHeaders(wsc->hRequest, L"Origin: https://pc.ctyun.cn", (ULONG)-1,
                              WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(wsc->hRequest, L"Sec-WebSocket-Protocol: binary", (ULONG)-1,
                              WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSetOption(wsc->hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        log_line("[%s] WebSocket升级选项设置失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    if (!WinHttpSendRequest(wsc->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        log_line("[%s] HTTP请求发送失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(wsc->hRequest, NULL)) {
        log_line("[%s] HTTP响应接收失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    DWORD status_code = 0;
    DWORD sc_len = sizeof(status_code);
    WinHttpQueryHeaders(wsc->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &status_code, &sc_len, NULL);
    if (status_code != 101) {
        log_line("[%s] WebSocket升级失败，状态码=%lu", desktop_code, status_code);
        goto cleanup;
    }

    wsc->hWebSocket = WinHttpWebSocketCompleteUpgrade(wsc->hRequest, (DWORD_PTR)NULL);
    if (!wsc->hWebSocket) {
        log_line("[%s] WebSocket升级完成失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    WinHttpCloseHandle(wsc->hRequest);
    wsc->hRequest = NULL;

    /* 连接建立即设置短轮询超时：挂机主循环以~300ms粒度轮转MAIN/DISPLAY/INPUTS，
     * 保证DISPLAY视频流及时排空、clink PING及时应答、断线快速重连。 */
    DWORD recv_timeout = WS_POLL_TIMEOUT_MS;
    WinHttpSetOption(wsc->hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_timeout, sizeof(recv_timeout));

    log_line("[%s] WebSocket握手成功", desktop_code);
    return 1;

cleanup:
    if (wsc->hRequest) { WinHttpCloseHandle(wsc->hRequest); wsc->hRequest = NULL; }
    if (wsc->hConnect) { WinHttpCloseHandle(wsc->hConnect); wsc->hConnect = NULL; }
    if (wsc->hSession) { WinHttpCloseHandle(wsc->hSession); wsc->hSession = NULL; }
    return 0;
}

static int ws_send_text(WSConn *wsc, const char *text) {
    size_t len = strlen(text);
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                          (void *)text, (DWORD)len);
    return (err == ERROR_SUCCESS) ? 0 : -1;
}

static int ws_send_bytes(WSConn *wsc, const uint8_t *data, size_t dlen) {
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                          (void *)data, (DWORD)dlen);
    return (err == ERROR_SUCCESS) ? 0 : -1;
}

static int ws_recv(WSConn *wsc, uint8_t *out, size_t outsz, int *is_text) {
    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    DWORD err = WinHttpWebSocketReceive(wsc->hWebSocket, out, (DWORD)outsz, &bytesRead, &bufType);
    if (err != ERROR_SUCCESS) return -1;
    if (bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return -1;
    *is_text = (bufType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
                bufType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE);
    return (int)bytesRead;
}

/*
 * Read one complete WebSocket message, reassembling continuation fragments.
 * Up to outsz bytes are copied into out; any overflow is drained/discarded.
 * Returns:  0 = full message read (total set; pover=1 if truncated)
 *          -1 = connection closed / error
 *          -2 = receive timeout (partial data may be present if total>0)
 */
static int ws_read_frame(WSConn *wsc, uint8_t *out, size_t outsz,
                         size_t *ptotal, int *pis_text, int *pover) {
    size_t total = 0;
    int is_text = 0, over = 0;
    uint8_t junk[512];
    for (;;) {
        DWORD br = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bt = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
        uint8_t *dst;
        DWORD cap;
        if (total < outsz) { dst = out + total; cap = (DWORD)(outsz - total); }
        else { dst = junk; cap = (DWORD)sizeof(junk); over = 1; }
        DWORD err = WinHttpWebSocketReceive(wsc->hWebSocket, dst, cap, &br, &bt);
        if (err == ERROR_WINHTTP_TIMEOUT) {
            if (ptotal) *ptotal = total;
            if (pis_text) *pis_text = is_text;
            if (pover) *pover = over;
            return total > 0 ? 0 : -2;
        }
        if (err != ERROR_SUCCESS) return -1;
        if (bt == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return -1;
        if (bt == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
            bt == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) is_text = 1;
        total += br;
        if (bt == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
            bt == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            if (ptotal) *ptotal = total;
            if (pis_text) *pis_text = is_text;
            if (pover) *pover = over;
            return 0;
        }
    }
}

static void ws_close(WSConn *wsc) {
    if (wsc->hWebSocket) {
        WinHttpWebSocketClose(wsc->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(wsc->hWebSocket);
    }
    if (wsc->hRequest) WinHttpCloseHandle(wsc->hRequest);
    if (wsc->hConnect) WinHttpCloseHandle(wsc->hConnect);
    if (wsc->hSession) WinHttpCloseHandle(wsc->hSession);
}

static int ws_send_ping(WSConn *wsc) {
    static const uint8_t ping_payload[4] = { 'A','L','I','V' };
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket,
                                     WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE,
                                     (void *)ping_payload, sizeof(ping_payload));
    return (err == ERROR_SUCCESS) ? 0 : -1;
}

static size_t build_mouse_move_msg(uint8_t *out, size_t osz) {
    if (osz < 15) return 0;
    int mx = 100 + (rand() % 200);
    int my = 100 + (rand() % 200);
    uint16_t msg_type = 201;
    uint32_t total_len = 6 + 9;
    out[0]  = (uint8_t)(msg_type & 0xFF);
    out[1]  = (uint8_t)((msg_type >> 8) & 0xFF);
    out[2]  = (uint8_t)(total_len & 0xFF);
    out[3]  = (uint8_t)((total_len >> 8) & 0xFF);
    out[4]  = (uint8_t)((total_len >> 16) & 0xFF);
    out[5]  = (uint8_t)((total_len >> 24) & 0xFF);
    out[6]  = (uint8_t)(mx & 0xFF);
    out[7]  = (uint8_t)((mx >> 8) & 0xFF);
    out[8]  = (uint8_t)((mx >> 16) & 0xFF);
    out[9]  = (uint8_t)((mx >> 24) & 0xFF);
    out[10] = (uint8_t)(my & 0xFF);
    out[11] = (uint8_t)((my >> 8) & 0xFF);
    out[12] = (uint8_t)((my >> 16) & 0xFF);
    out[13] = (uint8_t)((my >> 24) & 0xFF);
    out[14] = 0;
    return 15;
}

static size_t build_send_info_msg(uint16_t type_val, const uint8_t *data, size_t dlen, int is_build_msg, uint8_t *out) {
    size_t msg_length = is_build_msg ? 8 : 0;
    size_t sz = msg_length + dlen;
    out[0] = (uint8_t)(type_val & 0xFF);
    out[1] = (uint8_t)((type_val >> 8) & 0xFF);
    out[2] = (uint8_t)(sz & 0xFF);
    out[3] = (uint8_t)((sz >> 8) & 0xFF);
    out[4] = (uint8_t)((sz >> 16) & 0xFF);
    out[5] = (uint8_t)((sz >> 24) & 0xFF);
    if (is_build_msg) {
        out[6] = (uint8_t)(dlen & 0xFF);
        out[7] = (uint8_t)((dlen >> 8) & 0xFF);
        out[8] = (uint8_t)((dlen >> 16) & 0xFF);
        out[9] = (uint8_t)((dlen >> 24) & 0xFF);
        out[10] = 8 & 0xFF;
        out[11] = (8 >> 8) & 0xFF;
        out[12] = (8 >> 16) & 0xFF;
        out[13] = (8 >> 24) & 0xFF;
    }
    if (dlen > 0) memcpy(out + 6 + msg_length, data, dlen);
    return 6 + msg_length + dlen;
}

static size_t build_user_payload(const Session *s, uint8_t *out, size_t out_sz) {
    char user_json[512];
    snprintf(user_json, sizeof(user_json),
             "{\"type\":1,\"userName\":\"%s\",\"userInfo\":\"\",\"userId\":%d}",
             s->user_account, s->user_id);
    size_t jlen = strlen(user_json);
    size_t need = 6 + 8 + jlen;
    if (need > out_sz) return 0;
    return build_send_info_msg(118, (const uint8_t *)user_json, jlen, 1, out);
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

static void mac_to_fingerprint(const char *mac, char *fp_hex) {
    uint8_t d[32];
    sha256((const uint8_t *)mac, strlen(mac), d);
    for (int i = 0; i < 32; i++) {
        fp_hex[i * 2]     = HEX_LUT[d[i] >> 4];
        fp_hex[i * 2 + 1] = HEX_LUT[d[i] & 0x0f];
    }
    fp_hex[64] = 0;
}

static void get_fingerprint(char *fp_hex) {
    char mac[32] = "";
    DWORD sz = 0;
    if (GetAdaptersInfo(NULL, &sz) != ERROR_BUFFER_OVERFLOW) {
        mac_to_fingerprint("", fp_hex);
        log_line("MAC地址: (空) -> 指纹: %s", fp_hex);
        return;
    }
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) { mac_to_fingerprint("", fp_hex); log_line("MAC地址: (内存不足) -> 指纹: %s", fp_hex); return; }
    PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
    if (GetAdaptersInfo(pinfo, &sz) != ERROR_SUCCESS) {
        free(buf); mac_to_fingerprint("", fp_hex); log_line("MAC地址: (获取失败) -> 指纹: %s", fp_hex); return;
    }
    PIP_ADAPTER_INFO adapter = pinfo;
    while (adapter) {
        if (adapter->AddressLength == 6) {
            int nonzero = 0;
            for (int i = 0; i < 6; i++) {
                if (adapter->Address[i] != 0) { nonzero = 1; break; }
            }
            if (nonzero) {
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         adapter->Address[0], adapter->Address[1], adapter->Address[2],
                         adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                break;
            }
        }
        adapter = adapter->Next;
    }
    if (!mac[0] && pinfo->AddressLength == 6) {
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 pinfo->Address[0], pinfo->Address[1], pinfo->Address[2],
                 pinfo->Address[3], pinfo->Address[4], pinfo->Address[5]);
    }
    free(buf);
    mac_to_fingerprint(mac, fp_hex);
    log_line("MAC地址: %s -> 指纹: %s", mac, fp_hex);
}

static int get_all_macs(char macs[][32], int max_macs) {
    int count = 0;
    DWORD sz = 0;
    if (GetAdaptersInfo(NULL, &sz) != ERROR_BUFFER_OVERFLOW) return 0;
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) return 0;
    PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
    if (GetAdaptersInfo(pinfo, &sz) != ERROR_SUCCESS) { free(buf); return 0; }
    PIP_ADAPTER_INFO adapter = pinfo;
    while (adapter && count < max_macs) {
        if (adapter->AddressLength == 6) {
            int nonzero = 0;
            for (int i = 0; i < 6; i++) {
                if (adapter->Address[i] != 0) { nonzero = 1; break; }
            }
            if (nonzero) {
                char m[32];
                snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                         adapter->Address[0], adapter->Address[1], adapter->Address[2],
                         adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                int dup = 0;
                for (int j = 0; j < count; j++) {
                    if (strcmp(macs[j], m) == 0) { dup = 1; break; }
                }
                if (!dup) {
                    strncpy(macs[count], m, 31);
                    macs[count][31] = '\0';
                    count++;
                }
            }
        }
        adapter = adapter->Next;
    }
    free(buf);
    return count;
}

static void generate_device_code(const char *fp_hex, char *out, size_t out_sz) {
    uint8_t h[32];
    sha256((const uint8_t *)fp_hex, strlen(fp_hex), h);
    snprintf(out, out_sz, "web_%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
             h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
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

/* 分段打印超长字符串(积分任务列表 JSON 可能很长) */
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

/* 仅用于测试验证: 查询积分任务列表(不做任何兑换)。 */
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
            for (int i = 0; i < count; i++) desktop_free(&desktops[i]);
            Sleep(wait_sec * 1000);
            continue;
        }
        consec_fail = 0;

        int rc = ws_keepalive(s, d, remaining);

        desktop_free(d);
        for (int i = 0; i < count; i++) {
            if (i != target) desktop_free(&desktops[i]);
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

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "/help") == 0 || _stricmp(argv[i], "/h") == 0 ||
            _stricmp(argv[i], "-h") == 0 || _stricmp(argv[i], "--help") == 0) {
            printf("天翼云电脑积分挂机程序 v%s\n\n", APP_VERSION);
            printf("用法: ctyun_points.exe [选项]\n\n");
            printf("选项:\n");
            printf("  /user <账号>  /u <账号>    指定登录账号(手机号)\n");
            printf("  /pass <密码>  /p <密码>    指定登录密码\n");
            printf("  (无参数)                   自适应挂机: 保活并周期自查1003，拿满即止，硬上限4小时\n");
            printf("  /seconds <秒> /s <秒>     指定固定挂机时长(显式指定后关闭自适应, <%d秒)\n", 7200);
            printf("  /tasklist     /t           仅登录并查询积分任务列表(测试验证，不兑换)后退出\n");
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
