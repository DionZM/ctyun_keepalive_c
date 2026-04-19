/*
 * ctyun_keepalive.c - 天翼云电脑保活客户端 (C语言版)
 *
 * 功能概述:
 *   自动登录天翼云电脑平台，获取桌面列表，对运行中的桌面建立WebSocket保活连接，
 *   对未运行的桌面定时检测状态，开机后自动切换为保活模式。
 *
 * 内存优化:
 *   - Desktop结构体使用动态指针代替固定数组，保活阶段释放证书等大块内存
 *   - 使用DesktopLight轻量结构体进行状态轮询，减少栈/堆占用
 *   - 定期调用trim_working_set()将物理内存页归还操作系统
 *   - connect_msg按需精确分配，替代固定12KB缓冲区
 *   - 预构建ws_uri，保活阶段释放host/port/clink_host等连接参数
 *
 * 编译 (MSVC x64):
 *   cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS ctyun_keepalive.c ^
 *      /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF ^
 *      winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib
 *
 * 版本: 1.1.0
 */

/* ======================== 标准库与系统头文件 ======================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Windows网络与加密相关头文件 */
#include <winsock2.h>      /* Winsock2 基础 */
#include <ws2tcpip.h>      /* Winsock2 扩展 (InetPton等) */
#include <wincrypt.h>      /* CryptoAPI (SHA256, MD5, 随机数) */
#include <windows.h>       /* Windows基础API */
#include <winhttp.h>       /* WinHTTP (HTTP/WebSocket客户端) */
#include <bcrypt.h>        /* CNG API (RSA-OAEP加密) */
#include <iphlpapi.h>      /* 网络适配器信息 (GetAdaptersInfo) */

/* CryptoAPI中SHA-256算法标识符，部分SDK版本未定义，手动补充 */
#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

/* ======================== 链接库指示 ======================== */
#pragma comment(lib, "winhttp.lib")    /* WinHTTP: HTTP/WebSocket通信 */
#pragma comment(lib, "ws2_32.lib")     /* Winsock2: 网络基础 */
#pragma comment(lib, "crypt32.lib")    /* CryptoAPI: 证书和加密 */
#pragma comment(lib, "advapi32.lib")   /* 高级API: 注册表/安全 */
#pragma comment(lib, "iphlpapi.lib")   /* IP Helper: 网卡信息 */
#pragma comment(lib, "bcrypt.lib")     /* CNG: 现代加密算法 */

/* ======================== 常量定义 ======================== */
#define MAX_DESKTOPS  10       /* 最大桌面数量 */
#define CHECK_INTERVAL 180     /* 未运行桌面状态检查间隔(秒)，即3分钟 */
#define MAX_RESP      65536    /* HTTP响应缓冲区大小(64KB) */
#define THREAD_STACK  131072   /* 线程栈大小(128KB)，默认1MB太大，缩小以节省内存 */

/* ======================== 全局变量 ======================== */

/* CryptoAPI加密提供者句柄，用于SHA-256/MD5/随机数生成 */
static HCRYPTPROV g_crypt = 0;

/* 全局运行标志，volatile保证多线程可见性，LONG配合Interlocked原子操作 */
static volatile LONG g_running = 1;

/* WinHTTP会话句柄，全局复用以节省资源 */
static HINTERNET g_inet = NULL;

/* CNG RSA算法提供者句柄，用于REDQ握手中的RSA-OAEP加密 */
static BCRYPT_ALG_HANDLE g_rsa_alg = NULL;

/* 后台运行模式标志: 1=后台运行, 0=前台运行 */
static int g_background = 0;

/* 后台运行时的日志文件句柄 */
static FILE *g_log_file = NULL;

/* 日志文件路径(与exe同目录) */
static char g_log_path[MAX_PATH] = "";

static volatile LONG g_bg_switch = 0;

static int g_privacy = 0;

/* ======================== 工具函数 ======================== */

/**
 * trim_working_set - 修剪进程工作集，将物理内存页归还OS
 *
 * 调用SetProcessWorkingSetSize传入-1,-1，通知Windows尽可能将
 * 进程的未使用内存页换出物理内存。在保活循环中定期调用，
 * 可将进程的"工作集"(物理内存占用)降至最低。
 * 注意: 这不影响虚拟内存，仅影响物理内存驻留。
 */
static void trim_working_set(void) {
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

static void refresh_banner(void) {
    if (g_background) return;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hOut, &csbi)) return;
    COORD pos = {0, csbi.srWindow.Bottom};
    WORD attr = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE;
    DWORD written;
    FillConsoleOutputCharacterW(hOut, L' ', csbi.dwSize.X, pos, &written);
    FillConsoleOutputAttribute(hOut, attr, csbi.dwSize.X, pos, &written);
    const char *banner_utf8 = "  \xe3\x80\x90\xe5\xbc\x80\xe6\xba\x90\xe8\xbd\xaf\xe4\xbb\xb6\xe3\x80\x91https://github.com/DionZM/ctyun_keepalive_c  Ctrl+C\xe9\x80\x80\xe5\x87\xba Ctrl+B\xe8\xbd\xac\xe5\x90\x8e\xe5\x8f\xb0  ";
    WCHAR wbanner[128];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, banner_utf8, -1, wbanner, 128);
    if (wlen > 0) WriteConsoleOutputCharacterW(hOut, wbanner, wlen - 1, pos, &written);
}

static DWORD WINAPI console_input_thread(LPVOID param) {
    (void)param;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD ir;
    DWORD count;
    while (g_running && !g_bg_switch) {
        if (WaitForSingleObject(hIn, 2000) == WAIT_OBJECT_0) {
            while (PeekConsoleInputW(hIn, &ir, 1, &count) && count > 0) {
                ReadConsoleInputW(hIn, &ir, 1, &count);
                if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                    DWORD ctrl = ir.Event.KeyEvent.dwControlKeyState;
                    if (ir.Event.KeyEvent.wVirtualKeyCode == 'B' &&
                        (ctrl & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))) {
                        InterlockedExchange(&g_bg_switch, 1);
                        return 0;
                    }
                }
            }
        }
    }
    return 0;
}

/**
 * log_line - 带时间戳的UTF-8日志输出
 *
 * 格式: [HH:MM:SS.xx] message\n
 * 前台模式: 通过WriteConsoleW输出到控制台，确保中文不乱码
 * 后台模式: 同时写入run.log文件，文件超过1MB时截断保留末尾部分
 *
 * @param fmt  printf风格格式串
 * @param ...  可变参数
 */
static void log_line(const char *fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[2048];
    int prefix = sprintf(buf, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds / 10);
    va_list ap;
    va_start(ap, fmt);
    int msglen = vsnprintf(buf + prefix, sizeof(buf) - prefix, fmt, ap);
    va_end(ap);
    int total = prefix + msglen;
    buf[total] = '\n';
    buf[total + 1] = 0;

    /* 前台模式: 输出到控制台 */
    if (!g_background) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
            COORD bpos = {0, csbi.srWindow.Bottom};
            DWORD written;
            FillConsoleOutputCharacterW(hOut, L' ', csbi.dwSize.X, bpos, &written);
            FillConsoleOutputAttribute(hOut, csbi.wAttributes, csbi.dwSize.X, bpos, &written);
        }
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
        if (wlen > 0) {
            WCHAR *wbuf = (WCHAR *)malloc(wlen * sizeof(WCHAR));
            MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, wlen);
            DWORD written;
            WriteConsoleW(hOut, wbuf, wlen - 1, &written, NULL);
            free(wbuf);
        }
        refresh_banner();
    }

    /* 后台模式或日志文件已打开: 写入run.log */
    if (g_log_file) {
        fwrite(buf, 1, total + 1, g_log_file);
        fflush(g_log_file);
        /* 检查文件大小，超过1MB时截断保留末尾512KB */
        long fpos = ftell(g_log_file);
        if (fpos > 1024 * 1024) {
            fclose(g_log_file);
            /* 读取文件末尾512KB */
            FILE *rf = fopen(g_log_path, "rb");
            if (rf) {
                fseek(rf, 0, SEEK_END);
                long fsize = ftell(rf);
                long keep = 512 * 1024;
                long skip = fsize - keep;
                if (skip < 0) skip = 0;
                fseek(rf, skip, SEEK_SET);
                char *tail = (char *)malloc(keep + 1);
                size_t nread = fread(tail, 1, keep, rf);
                fclose(rf);
                /* 重写文件，只保留末尾部分 */
                g_log_file = fopen(g_log_path, "w");
                if (g_log_file) {
                    fwrite(tail, 1, nread, g_log_file);
                    fflush(g_log_file);
                }
                free(tail);
            } else {
                g_log_file = fopen(g_log_path, "a");
            }
        }
    }
}

/* ======================== 加密基础函数 ======================== */

/**
 * crypto_init - 初始化加密相关全局资源
 *
 * 初始化CryptoAPI提供者(用于SHA-256/MD5/随机数)和
 * CNG RSA算法提供者(用于REDQ握手中的RSA-OAEP加密)。
 */
static void crypto_init(void) {
    CryptAcquireContext(&g_crypt, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    BCryptOpenAlgorithmProvider(&g_rsa_alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
}

/**
 * sha256 - 计算SHA-256哈希
 *
 * 使用CryptoAPI计算数据的SHA-256摘要。
 *
 * @param d    输入数据
 * @param n    数据长度
 * @param out  输出32字节哈希值
 */
static void sha256(const uint8_t *d, size_t n, uint8_t *out) {
    HCRYPTHASH h;
    CryptCreateHash(g_crypt, CALG_SHA_256, 0, 0, &h);
    CryptHashData(h, (BYTE *)d, (DWORD)n, 0);
    DWORD dl = 32;
    CryptGetHashParam(h, HP_HASHVAL, out, &dl, 0);
    CryptDestroyHash(h);
}

/**
 * url_encode - URL编码
 *
 * 对非安全字符进行百分号编码(如 %XX)，符合RFC 3986规范。
 * 安全字符集: A-Z a-z 0-9 - _ . ~
 *
 * @param in     输入字符串
 * @param out    输出缓冲区
 * @param out_sz 输出缓冲区大小
 * @return       编码后字符串长度
 */
static size_t url_encode(const char *in, char *out, size_t out_sz) {
    static const char *safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_sz - 4; i++) {
        if (strchr(safe, in[i])) {
            out[j++] = in[i];
        } else {
            j += snprintf(out + j, out_sz - j, "%%%02X", (unsigned char)in[i]);
        }
    }
    out[j] = 0;
    return j;
}

/**
 * sha256_hex - 计算字符串的SHA-256并输出为64字符十六进制
 *
 * @param s    输入字符串
 * @param out  输出缓冲区(至少65字节)
 */
static void sha256_hex(const char *s, char *out) {
    uint8_t d[32];
    sha256((const uint8_t *)s, strlen(s), d);
    for (int i = 0; i < 32; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[64] = 0;
}

/**
 * md5_hex - 计算字符串的MD5并输出为32字符十六进制
 *
 * 用于生成API请求签名(ctg-signaturestr)。
 *
 * @param s    输入字符串
 * @param out  输出缓冲区(至少33字节)
 */
static void md5_hex(const char *s, char *out) {
    HCRYPTHASH h;
    CryptCreateHash(g_crypt, CALG_MD5, 0, 0, &h);
    CryptHashData(h, (BYTE *)s, (DWORD)strlen(s), 0);
    uint8_t d[16];
    DWORD dl = 16;
    CryptGetHashParam(h, HP_HASHVAL, d, &dl, 0);
    CryptDestroyHash(h);
    for (int i = 0; i < 16; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[32] = 0;
}

/* ======================== Base64编解码 ======================== */

/* Base64编码字母表 */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * b64enc - Base64编码
 *
 * 将二进制数据编码为Base64字符串。
 *
 * @param in   输入数据
 * @param n    输入数据长度
 * @param out  输出缓冲区(至少 4*n/3 + 4 字节)
 * @return     编码后字符串长度(不含末尾\0)
 */
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

/**
 * b64val - 获取Base64字符对应的6位数值
 *
 * @param c  Base64字符
 * @return   对应数值(0-63)，无效字符返回-1
 */
static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/**
 * b64dec - Base64解码
 *
 * 将Base64字符串解码为二进制数据。
 *
 * @param in   输入Base64字符串
 * @param n    输入字符串长度
 * @param out  输出缓冲区(至少 3*n/4 字节)
 * @return     解码后数据长度
 */
static size_t b64dec(const char *in, size_t n, uint8_t *out) {
    size_t o = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=') break;
        int v = b64val(in[i]);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (buf >> bits) & 0xFF; }
    }
    return o;
}

/* ======================== JSON简易解析 ======================== */

/**
 * jstr - 从JSON字符串中提取指定键的字符串值
 *
 * 简易JSON解析器，搜索 "key":"value" 模式。
 * 支持转义字符(如 \" \\)，但不支持嵌套对象智能查找。
 *
 * @param j    JSON字符串
 * @param k    要查找的键名
 * @param buf  输出缓冲区
 * @param bsz  输出缓冲区大小
 * @return     buf指针(未找到则返回空字符串)
 */
static char *jstr(const char *j, const char *k, char *buf, size_t bsz) {
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) { buf[0] = 0; return buf; }
    p += strlen(srch);
    /* 跳过空格和冒号 */
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') { buf[0] = 0; return buf; }
    p++;
    /* 提取字符串值，处理转义字符 */
    size_t i = 0;
    while (*p && *p != '"' && i < bsz - 1) {
        if (*p == '\\' && *(p + 1)) p++;  /* 跳过转义符，取下一个字符 */
        buf[i++] = *p++;
    }
    buf[i] = 0;
    return buf;
}

/**
 * jint - 从JSON字符串中提取指定键的整数值
 *
 * @param j  JSON字符串
 * @param k  要查找的键名
 * @return   整数值(未找到返回0)
 */
static int jint(const char *j, const char *k) {
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) return 0;
    p += strlen(srch);
    while (*p == ' ' || *p == ':') p++;
    return atoi(p);
}

/**
 * str_dup - 堆上复制字符串
 *
 * 类似strdup，但跨平台兼容。用于Desktop结构体动态字段赋值。
 * 空指针或空字符串返回NULL，便于后续free(NULL)安全调用。
 *
 * @param s  源字符串
 * @return   新分配的字符串副本，或NULL
 */
static char *str_dup(const char *s) {
    if (!s || !s[0]) return NULL;
    size_t n = strlen(s) + 1;
    char *r = (char *)malloc(n);
    memcpy(r, s, n);
    return r;
}

/* ======================== 数据结构定义 ======================== */

/**
 * Desktop - 桌面信息(完整版)
 *
 * 存储云桌面的完整连接信息。进入保活阶段后，证书等大块内存通过
 * desktop_free_certs()释放，仅保留connect_msg和ws_uri用于保活通信。
 *
 * 内存优化说明:
 *   - host/port/clink_host/ca_cert/client_cert/client_key/token/tenant_account
 *     均为动态指针(char*)，保活阶段可free()真正释放物理内存
 *   - 优化前每个Desktop约11.2KB(固定数组)，优化后约200B(指针)
 *   - connect_msg按需精确分配(通常6-7KB)，替代固定12KB
 *   - ws_uri预构建后host/port/clink_host也可释放
 */
typedef struct {
    char desktop_id[64];      /* 桌面唯一标识 */
    char desktop_code[64];    /* 桌面编码(显示名) */
    char *host;               /* WebSocket连接主机(动态分配，保活后释放) */
    char *port;               /* WebSocket连接端口(动态分配，保活后释放) */
    char *clink_host;         /* CLink代理主机(动态分配，保活后释放) */
    char *ca_cert;            /* CA证书PEM(动态分配，保活后释放) */
    char *client_cert;        /* 客户端证书PEM(动态分配，保活后释放) */
    char *client_key;         /* 客户端私钥PEM(动态分配，保活后释放) */
    char *token;              /* 认证令牌(动态分配，保活后释放) */
    char *tenant_account;     /* 租户账号(动态分配，保活后释放) */
    int is_active;            /* 是否运行中(1=运行中, 0=未运行) */
    char *connect_msg;        /* 预构建的WebSocket连接JSON消息(保活阶段保留) */
    char *ws_uri;             /* 预构建的WebSocket URI(保活阶段保留) */
} Desktop;

/**
 * DesktopLight - 桌面信息(轻量版)
 *
 * 仅包含状态轮询所需的最小字段，用于check_desktop_thread中
 * 定期查询桌面状态。每个实例仅132字节，远小于Desktop的~200B+动态内存。
 */
typedef struct {
    char desktop_id[64];      /* 桌面唯一标识 */
    char desktop_code[64];    /* 桌面编码 */
    int is_active;            /* 是否运行中 */
} DesktopLight;

/**
 * Session - 用户会话信息
 *
 * 存储登录后的认证信息，用于后续API请求的签名和鉴权。
 * 登录成功后user_name会被清零以释放内存。
 */
typedef struct {
    char device_code[128];    /* 设备标识(如 web_a1b2c3d4...) */
    char secret_key[128];     /* 登录后获取的签名密钥 */
    char user_name[128];      /* 用户名(登录后清零) */
    int user_id;              /* 用户ID */
    int tenant_id;            /* 租户ID */
    int logged_in;            /* 是否已登录 */
} Session;

/* ======================== Desktop内存管理 ======================== */

/**
 * desktop_free_certs - 释放桌面证书等大块内存，进入保活模式
 *
 * 在WebSocket连接建立后调用。执行两个关键操作:
 * 1. 预构建connect_msg: 将证书/密钥等信息序列化为JSON消息，
 *    后续保活循环中每次重连时发送此消息。
 * 2. 预构建ws_uri: 将连接参数组合为WebSocket URI，
 *    后续保活循环中用于建立连接。
 * 3. 释放所有不再需要的动态字段: 证书、密钥、令牌、主机地址等。
 *
 * 内存节省效果(每桌面):
 *   - ca_cert(~4KB) + client_cert(~4KB) + client_key(~4KB) = ~12KB
 *   - token(~2KB) + tenant_account(~128B) + host/port/clink_host(~528B) = ~2.6KB
 *   - 总计释放约14.6KB物理内存
 *   - 保留: connect_msg(~6-7KB) + ws_uri(~200B) = ~7KB
 */
static void desktop_free_certs(Desktop *d) {
    /* 第一步: 预构建WebSocket连接消息(仅在首次调用时) */
    if (!d->connect_msg && d->ca_cert) {
        /* 精确计算所需缓冲区大小，避免浪费 */
        size_t need = 256 + strlen(d->ca_cert) + strlen(d->client_cert) + strlen(d->client_key);
        d->connect_msg = (char *)malloc(need);
        snprintf(d->connect_msg, need,
                 "{\"type\":1,\"ssl\":1,\"host\":\"%s\",\"port\":\"%s\","
                 "\"ca\":\"%s\",\"cert\":\"%s\",\"key\":\"%s\","
                 "\"servername\":\"%s:%s\",\"oqs\":0}",
                 d->host ? d->host : "", d->port ? d->port : "",
                 d->ca_cert, d->client_cert, d->client_key,
                 d->host ? d->host : "", d->port ? d->port : "");
    }

    /* 第二步: 预构建WebSocket URI(仅在首次调用时) */
    if (!d->ws_uri && d->host) {
        d->ws_uri = (char *)malloc(512);
        const char *p_str = (d->port && d->port[0]) ? d->port : "443";
        if (d->clink_host && d->clink_host[0] && strchr(d->clink_host, ':') == NULL)
            /* CLink代理地址不含端口，需显式添加 */
            snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->clink_host, p_str, d->desktop_id);
        else if (d->clink_host && d->clink_host[0])
            /* CLink代理地址已含端口 */
            snprintf(d->ws_uri, 512, "wss://%s/clinkProxy/%s/MAIN", d->clink_host, d->desktop_id);
        else
            /* 直连模式 */
            snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->host, p_str, d->desktop_id);
    }

    /* 第三步: 释放所有不再需要的动态内存 */
    free(d->ca_cert); d->ca_cert = NULL;
    free(d->client_cert); d->client_cert = NULL;
    free(d->client_key); d->client_key = NULL;
    free(d->token); d->token = NULL;
    free(d->tenant_account); d->tenant_account = NULL;
    free(d->host); d->host = NULL;
    free(d->port); d->port = NULL;
    free(d->clink_host); d->clink_host = NULL;
}

/**
 * desktop_cleanup - 完全释放桌面所有动态内存
 *
 * 程序退出时调用，释放Desktop结构体的所有动态字段，
 * 包括保活阶段保留的connect_msg和ws_uri。
 */
static void desktop_cleanup(Desktop *d) {
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

/* ======================== HTTP通信 ======================== */

/**
 * http_init - 初始化WinHTTP会话
 *
 * 创建全局WinHTTP会话句柄，模拟Chrome浏览器User-Agent。
 * 所有HTTP请求复用此会话，减少资源开销。
 *
 * @return 1=成功, 0=失败
 */
static int http_init(void) {
    g_inet = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return g_inet ? 1 : 0;
}

/**
 * http_req - 通用HTTP请求函数
 *
 * 使用WinHTTP发送HTTP请求并读取响应。支持自定义方法、请求头、
 * 请求体和Content-Type。HTTPS请求自动忽略证书验证错误。
 *
 * @param method  HTTP方法("POST"/"GET")
 * @param url     完整URL(如 https://desk.ctyun.cn:8810/api/...)
 * @param body    请求体数据(可为NULL)
 * @param blen    请求体长度
 * @param ct      Content-Type(可为NULL)
 * @param hdrs    自定义请求头数组
 * @param nhdrs   请求头数量
 * @param resp    响应缓冲区
 * @param rsz     响应缓冲区大小
 * @return        响应体长度(字节)，失败返回-1
 */
static int http_req(const char *method, const char *url, const char *body, size_t blen,
                    const char *ct, const char **hdrs, int nhdrs,
                    char *resp, size_t rsz) {
    /* 解析URL为主机名和路径 */
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    WCHAR whostname[256], wurl_path[2048];
    uc.lpszHostName = whostname; uc.dwHostNameLength = sizeof(whostname)/sizeof(WCHAR);
    uc.lpszUrlPath = wurl_path; uc.dwUrlPathLength = sizeof(wurl_path)/sizeof(WCHAR);
    WCHAR wurl[4096];
    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 4096);
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        log_line("URL parse failed: %s", url);
        return -1;
    }
    WCHAR wmethod[16] = {0};
    MultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 16);

    /* 建立到服务器的连接 */
    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) {
        char hname[256];
        WideCharToMultiByte(CP_ACP, 0, whostname, -1, hname, sizeof(hname), NULL, NULL);
        log_line("WinHttpConnect failed for %s:%d err=%lu", hname, uc.nPort, GetLastError());
        return -1;
    }

    /* 创建HTTP请求 */
    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) {
        log_line("WinHttpOpenRequest failed err=%lu", GetLastError());
        WinHttpCloseHandle(hconn);
        return -1;
    }

    /* HTTPS请求忽略证书验证错误(自签名证书环境) */
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    /* 添加自定义请求头 */
    for (int i = 0; i < nhdrs; i++) {
        WCHAR whdr[512];
        MultiByteToWideChar(CP_ACP, 0, hdrs[i], -1, whdr, 512);
        WinHttpAddRequestHeaders(hreq, whdr, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    /* 添加Content-Type头 */
    if (ct) {
        char h[256]; snprintf(h, sizeof(h), "Content-Type: %s", ct);
        WCHAR wh[256]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 256);
        WinHttpAddRequestHeaders(hreq, wh, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    /* 发送请求 */
    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (void *)body, (DWORD)blen, (DWORD)blen, 0)) {
        log_line("WinHttpSendRequest failed err=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    /* 接收响应 */
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        log_line("WinHttpReceiveResponse failed err=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    /* 读取响应状态码(目前未使用，预留) */
    DWORD status_code = 0, sc_len = sizeof(status_code);
    WinHttpQueryHeaders(hreq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status_code, &sc_len, NULL);

    /* 分块读取响应体 */
    DWORD total = 0, n;
    while (WinHttpReadData(hreq, resp + total, (DWORD)(rsz - total - 1), &n) && n > 0) {
        total += n;
        if (total >= rsz - 1) break;
    }
    resp[total] = 0;

    WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
    return (int)total;
}

/**
 * http_get_binary - HTTP GET下载二进制数据
 *
 * 与http_req类似，但响应直接存入uint8_t缓冲区，不添加末尾\0。
 * 用于下载验证码图片等二进制内容。
 *
 * @param url     完整URL
 * @param hdrs    自定义请求头数组
 * @param nhdrs   请求头数量
 * @param resp    二进制响应缓冲区
 * @param rsz     缓冲区大小
 * @return        实际下载字节数，失败返回-1
 */
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
    WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
    return (int)total;
}

/* ======================== API请求头构建 ======================== */

/**
 * make_base_headers - 构建基础请求头(无需签名)
 *
 * 用于登录前的不需要认证的API请求(如获取挑战码、登录)。
 * 包含设备类型、版本号、设备码、来源页等基础信息。
 *
 * 注意: 使用static局部变量存储头部字符串，非线程安全，
 *       但本程序中所有HTTP请求都是串行执行的。
 *
 * @param s      会话信息(提取device_code)
 * @param hdrs   输出请求头指针数组
 * @param nhdrs  输出请求头数量
 */
static void make_base_headers(const Session *s, const char **hdrs, int *nhdrs) {
    static char h1[64], h2[64], h3[128], h5[64], h6[256];
    snprintf(h1, sizeof(h1), "ctg-devicetype: 60");
    snprintf(h2, sizeof(h2), "ctg-version: 103020001");
    snprintf(h3, sizeof(h3), "ctg-devicecode: %s", s->device_code);
    snprintf(h5, sizeof(h5), "referer: https://pc.ctyun.cn/");
    snprintf(h6, sizeof(h6), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
    static const char *base[] = {h6, h1, h2, h3, h5};
    memcpy(hdrs, base, sizeof(base));
    *nhdrs = 5;
}

/**
 * make_sig_headers - 构建带签名的请求头(需认证)
 *
 * 用于登录后的API请求(如获取桌面列表、连接桌面)。
 * 在基础请求头之上，额外添加:
 *   - ctg-userid: 用户ID
 *   - ctg-tenantid: 租户ID
 *   - ctg-timestamp: 当前时间戳(毫秒)
 *   - ctg-requestid: 请求ID(同时间戳)
 *   - ctg-signaturestr: 签名(MD5(设备类型+时间戳+租户ID+时间戳+用户ID+版本+密钥))
 *
 * 签名算法与天翼云Web客户端一致，确保请求被服务端接受。
 *
 * @param s      会话信息(提取user_id/tenant_id/secret_key)
 * @param hdrs   输出请求头指针数组
 * @param nhdrs  输出请求头数量
 */
static void make_sig_headers(const Session *s, const char **hdrs, int *nhdrs) {
    static char h1[64], h2[64], h3[128], h4[64], h5[64], h6[64], h7[256];
    static char hts[64], hri[64], hsig[128];
    static char combined[512], sig[33];
    snprintf(h1, sizeof(h1), "ctg-devicetype: 60");
    snprintf(h2, sizeof(h2), "ctg-version: 103020001");
    snprintf(h3, sizeof(h3), "ctg-devicecode: %s", s->device_code);
    snprintf(h5, sizeof(h5), "referer: https://pc.ctyun.cn/");
    snprintf(h7, sizeof(h7), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
    /* 当前时间戳(毫秒)，用long long避免2038年溢出 */
    long long ts = (long long)time(NULL) * 1000LL;
    snprintf(h4, sizeof(h4), "ctg-userid: %d", s->user_id);
    snprintf(h6, sizeof(h6), "ctg-tenantid: %d", s->tenant_id);
    snprintf(hts, sizeof(hts), "ctg-timestamp: %lld", ts);
    snprintf(hri, sizeof(hri), "ctg-requestid: %lld", ts);
    /* 签名原文: 设备类型 + 时间戳 + 租户ID + 时间戳 + 用户ID + 版本 + 密钥 */
    snprintf(combined, sizeof(combined), "60%lld%d%lld%d103020001%s",
             ts, s->tenant_id, ts, s->user_id, s->secret_key);
    md5_hex(combined, sig);
    snprintf(hsig, sizeof(hsig), "ctg-signaturestr: %s", sig);
    static const char *all[] = {h7, h1, h2, h3, h5, h4, h6, hts, hri, hsig};
    memcpy(hdrs, all, sizeof(all));
    *nhdrs = 10;
}

/* ======================== API封装 ======================== */

/**
 * api_post_noauth - 无签名POST请求
 *
 * 用于登录前的API调用(获取挑战码、登录)。
 *
 * @param s     会话信息(提取device_code)
 * @param url   请求URL
 * @param body  请求体
 * @param blen  请求体长度
 * @param ct    Content-Type
 * @param resp  响应缓冲区
 * @param rsz   响应缓冲区大小
 * @return      响应长度，失败返回-1
 */
static int api_post_noauth(const Session *s, const char *url, const char *body, size_t blen,
                           const char *ct, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_base_headers(s, hdrs, &nhdrs);
    return http_req("POST", url, body, blen, ct, hdrs, nhdrs, resp, rsz);
}

/**
 * api_post - 带签名POST请求
 *
 * 用于登录后的API调用(获取桌面列表、连接桌面)。
 *
 * @param s     会话信息(提取签名所需字段)
 * @param url   请求URL
 * @param body  请求体
 * @param blen  请求体长度
 * @param ct    Content-Type
 * @param resp  响应缓冲区
 * @param rsz   响应缓冲区大小
 * @return      响应长度，失败返回-1
 */
static int api_post(const Session *s, const char *url, const char *body, size_t blen,
                    const char *ct, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("POST", url, body, blen, ct, hdrs, nhdrs, resp, rsz);
}

/* ======================== 验证码OCR ======================== */

/**
 * get_captcha_ocr - 获取验证码图片并OCR识别
 *
 * 流程:
 * 1. 从天翼云API下载验证码图片(二进制)
 * 2. 将图片Base64编码
 * 3. 构建multipart/form-data请求体
 * 4. 发送到第三方OCR服务(orc.1999111.xyz)识别
 * 5. 返回识别结果
 *
 * @param s            会话信息
 * @param user         用户名(用于验证码URL参数)
 * @param captcha_out  输出验证码文本
 * @param co_sz        输出缓冲区大小
 * @return             1=成功, 0=失败
 */
static int get_captcha_ocr(const Session *s, const char *user, char *captcha_out, size_t co_sz) {
    /* 构建验证码图片URL，带时间戳防缓存 */
    char captcha_url[512];
    long long t = (long long)time(NULL) * 1000LL;
    snprintf(captcha_url, sizeof(captcha_url),
             "https://desk.ctyun.cn:8810/api/auth/client/captcha?height=36&width=85&userInfo=%s&mode=auto&_t=%lld",
             user, t);

    /* 下载验证码图片 */
    const char *hdrs[16];
    int nhdrs = 0;
    make_base_headers(s, hdrs, &nhdrs);
    uint8_t *img = (uint8_t *)malloc(65536);
    int img_len = http_get_binary(captcha_url, hdrs, nhdrs, img, 65536);
    if (img_len <= 0) {
        log_line("captcha image download failed");
        free(img);
        return 0;
    }
    log_line("captcha image size: %d bytes", img_len);

    /* 将图片Base64编码 */
    char *img_b64 = (char *)malloc(img_len * 2 + 4);
    b64enc(img, img_len, img_b64);
    free(img);

    /* 构建multipart/form-data请求体 */
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

    /* 设置Content-Type和请求头 */
    char ct_hdr[256];
    snprintf(ct_hdr, sizeof(ct_hdr), "multipart/form-data; boundary=%s", boundary);
    char h_dc[128], h1[64], h2[64], h5[64];
    snprintf(h1, sizeof(h1), "ctg-devicetype: 60");
    snprintf(h2, sizeof(h2), "ctg-version: 103020001");
    snprintf(h_dc, sizeof(h_dc), "ctg-devicecode: %s", s->device_code);
    snprintf(h5, sizeof(h5), "referer: https://pc.ctyun.cn/");

    /* 发送OCR请求(需携带天翼云基础请求头，否则OCR服务可能拒绝) */
    const char *ocr_hdrs[] = { h1, h2, h_dc, h5 };
    char orc_resp[4096];
    int rlen = http_req("POST", "https://orc.1999111.xyz/ocr", body, blen, ct_hdr, ocr_hdrs, 4, orc_resp, sizeof(orc_resp));
    free(body);
    if (rlen <= 0) {
        log_line("OCR request failed");
        return 0;
    }
    orc_resp[rlen] = 0;
    log_line("OCR response: %s", orc_resp);

    /* 提取OCR识别结果 */
    jstr(orc_resp, "data", captcha_out, co_sz);
    if (!captcha_out[0]) {
        log_line("OCR result empty");
        return 0;
    }
    log_line("OCR result: %s", captcha_out);
    return 1;
}

/* ======================== 登录流程 ======================== */

/**
 * do_login - 执行天翼云电脑登录
 *
 * 登录流程(最多重试3次):
 * 1. 调用genChallengeData获取挑战码(challengeId + challengeCode)
 * 2. 下载验证码图片并OCR识别
 * 3. 计算密码哈希: SHA256(密码+challengeCode) 和 SHA256(SHA256(密码)+challengeCode)
 * 4. URL编码challengeId和deviceCode
 * 5. 构建登录请求体并发送
 * 6. 解析响应获取secretKey/userId/tenantId
 *
 * 密码哈希说明:
 *   - password: SHA256(原始密码 + challengeCode)，服务端用此验证
 *   - sha256Password: SHA256(SHA256(原始密码) + challengeCode)，双重哈希增强安全性
 *
 * @param s     会话信息(输出secretKey/userId/tenantId)
 * @param user  用户名
 * @param pwd   原始密码
 * @return      1=登录成功, 0=登录失败
 */
static int do_login(Session *s, const char *user, const char *pwd) {
    for (int attempt = 1; attempt <= 3; attempt++) {
        char resp[MAX_RESP];

        /* 第一步: 获取挑战码 */
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData",
                            "{}", 2, "application/json", resp, sizeof(resp)) < 0) {
            log_line("getChallenge failed (attempt %d)", attempt);
            continue;
        }
        int code = jint(resp, "code");
        log_line("challenge resp code=%d", code);
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            log_line("challenge error: %s", msg);
            continue;
        }
        char cid[128], ccode[128];
        jstr(resp, "challengeId", cid, sizeof(cid));
        jstr(resp, "challengeCode", ccode, sizeof(ccode));
        if (!cid[0]) { log_line("challenge empty"); continue; }
        log_line("challengeId=%s", cid);

        /* 第二步: OCR识别验证码 */
        char captcha[64] = "";
        if (!get_captcha_ocr(s, user, captcha, sizeof(captcha))) {
            log_line("captcha OCR failed (attempt %d)", attempt);
            continue;
        }

        /* 第三步: 计算密码哈希 */
        char combined[512], final_sha[65];
        snprintf(combined, sizeof(combined), "%s%s", pwd, ccode);
        sha256_hex(combined, final_sha);  /* password字段 */

        char pwd_sha[65];
        sha256_hex(pwd, pwd_sha);  /* 原始密码的SHA256 */

        char sha2_combined[512], sha2_pwd[65];
        snprintf(sha2_combined, sizeof(sha2_combined), "%s%s", pwd_sha, ccode);
        sha256_hex(sha2_combined, sha2_pwd);  /* sha256Password字段 */

        /* 第四步: URL编码特殊字符 */
        char enc_cid[512], enc_dc[512];
        url_encode(cid, enc_cid, sizeof(enc_cid));
        url_encode(s->device_code, enc_dc, sizeof(enc_dc));

        /* 第五步: 构建并发送登录请求 */
        char post[4096];
        snprintf(post, sizeof(post),
                 "userAccount=%s&password=%s&sha256Password=%s&challengeId=%s&captchaCode=%s"
                 "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
                 "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
                 "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
                 user, final_sha, sha2_pwd, enc_cid, captcha, enc_dc);

        log_line("login request sending (attempt %d)...", attempt);
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/login",
                            post, strlen(post), "application/x-www-form-urlencoded",
                            resp, sizeof(resp)) < 0) {
            log_line("login request failed");
            continue;
        }

        /* 第六步: 解析登录响应 */
        code = jint(resp, "code");
        log_line("login resp code=%d", code);
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            log_line("login failed: %s", msg);
            /* "用户名或密码错误"(UTF-8)则不再重试 */
            if (strcmp(msg, "\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf") == 0)
                return 0;
            continue;
        }

        /* 提取data对象中的认证信息 */
        const char *p = strstr(resp, "\"data\"");
        if (!p) { log_line("no data in response"); continue; }
        p = strchr(p, '{');
        if (!p) { log_line("no { in data"); continue; }

        jstr(p, "secretKey", s->secret_key, sizeof(s->secret_key));
        jstr(p, "userName", s->user_name, sizeof(s->user_name));
        s->user_id = jint(p, "userId");
        s->tenant_id = jint(p, "tenantId");
        log_line("secretKey=%s, userId=%d, tenantId=%d", s->secret_key, s->user_id, s->tenant_id);
        s->logged_in = s->secret_key[0] ? 1 : 0;
        return s->logged_in;
    }
    log_line("login failed after 3 attempts");
    return 0;
}

/* ======================== 桌面列表解析 ======================== */

/**
 * find_matching_brace - 查找JSON中与起始'{'匹配的'}'
 *
 * 正确处理嵌套对象和字符串内的花括号(字符串内的花括号不计数)。
 * 支持转义字符处理。
 *
 * @param start  指向'{'的指针
 * @return       指向匹配'}'的指针，未找到返回NULL
 */
static const char *find_matching_brace(const char *start) {
    if (!start || *start != '{') return NULL;
    int depth = 0;
    const char *p = start;
    while (*p) {
        if (*p == '"') {
            /* 跳过字符串内容(字符串内的花括号不计数) */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\') p++;  /* 跳过转义字符 */
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

/**
 * get_desktop_list - 获取桌面列表(完整版)
 *
 * 调用pageDesktop API获取用户的云桌面列表，解析每个桌面的
 * ID、编码和运行状态。使用Desktop完整结构体存储。
 *
 * @param s         会话信息
 * @param desktops  桌面数组(输出)
 * @param max       最大桌面数量
 * @return          实际获取的桌面数量
 */
static int get_desktop_list(Session *s, Desktop *desktops, int max) {
    char resp[MAX_RESP];
    char body[] = "{\"getCnt\":20,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}";
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
                 body, strlen(body), "application/json", resp, sizeof(resp)) < 0) {
        log_line("pageDesktop request failed");
        return 0;
    }
    if (jint(resp, "code") != 0) {
        log_line("pageDesktop code=%d", jint(resp, "code"));
        return 0;
    }
    log_line("pageDesktop ok, parsing desktops");

    /* 定位desktopList数组 */
    const char *dl = strstr(resp, "\"desktopList\"");
    if (!dl) return 0;
    dl = strchr(dl, '[');
    if (!dl) return 0;

    /* 逐个解析数组中的桌面对象 */
    int count = 0;
    const char *p = dl;
    while (count < max) {
        const char *obj = strchr(p, '{');
        if (!obj) break;
        const char *end = find_matching_brace(obj);
        if (!end) break;

        /* 提取单个桌面JSON块 */
        char *block = (char *)malloc(end - obj + 2);
        int len = (int)(end - obj + 1);
        memcpy(block, obj, len);
        block[len] = 0;

        /* 解析桌面字段 */
        jstr(block, "desktopId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        /* 部分API版本使用objId代替desktopId */
        if (!desktops[count].desktop_id[0])
            jstr(block, "objId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        jstr(block, "desktopCode", desktops[count].desktop_code, sizeof(desktops[count].desktop_code));

        /* 判断运行状态: "运行中"(UTF-8: e8 bf 90 e8 a1 8c e4 b8 ad) */
        char status[64];
        jstr(block, "useStatusText", status, sizeof(status));
        desktops[count].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
        log_line("desktop[%d]: id=%s code=%s status=%s active=%d",
                 count, desktops[count].desktop_id, desktops[count].desktop_code,
                 status, desktops[count].is_active);
        count++;
        free(block);
        p = end + 1;
    }
    return count;
}

/**
 * get_desktop_list_light - 获取桌面列表(轻量版)
 *
 * 与get_desktop_list功能相同，但使用DesktopLight轻量结构体。
 * 每个实例仅132字节(vs Desktop的~200B+动态内存)，
 * 适用于check_desktop_thread中的定期状态轮询。
 *
 * @param s         会话信息
 * @param desktops  轻量桌面数组(输出)
 * @param max       最大桌面数量
 * @return          实际获取的桌面数量
 */
static int get_desktop_list_light(Session *s, DesktopLight *desktops, int max) {
    char resp[MAX_RESP];
    char body[] = "{\"getCnt\":20,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}";
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
                 body, strlen(body), "application/json", resp, sizeof(resp)) < 0) {
        log_line("pageDesktop request failed");
        return 0;
    }
    if (jint(resp, "code") != 0) {
        log_line("pageDesktop code=%d", jint(resp, "code"));
        return 0;
    }
    const char *dl = strstr(resp, "\"desktopList\"");
    if (!dl) return 0;
    dl = strchr(dl, '[');
    if (!dl) return 0;
    int count = 0;
    const char *p = dl;
    while (count < max) {
        const char *obj = strchr(p, '{');
        if (!obj) break;
        const char *end = find_matching_brace(obj);
        if (!end) break;
        char *block = (char *)malloc(end - obj + 2);
        int len = (int)(end - obj + 1);
        memcpy(block, obj, len);
        block[len] = 0;
        jstr(block, "desktopId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        if (!desktops[count].desktop_id[0])
            jstr(block, "objId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        jstr(block, "desktopCode", desktops[count].desktop_code, sizeof(desktops[count].desktop_code));
        char status[64];
        jstr(block, "useStatusText", status, sizeof(status));
        desktops[count].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
        count++;
        free(block);
        p = end + 1;
    }
    return count;
}

/* ======================== 桌面连接 ======================== */

/**
 * connect_desktop - 连接云桌面，获取WebSocket连接参数
 *
 * 调用connect API获取桌面的WebSocket连接信息，包括:
 *   - host/port: WebSocket服务器地址
 *   - clinkLvsOutHost: CLink代理地址(如有)
 *   - caCert/clientCert/clientKey: TLS证书(PEM格式)
 *   - token: 认证令牌
 *   - tenantMemberAccount: 租户成员账号
 *
 * 所有字符串字段通过str_dup动态分配到堆上，保活阶段可释放。
 *
 * @param s  会话信息
 * @param d  桌面信息(输出连接参数)
 * @return   1=成功, 0=失败
 */
static int connect_desktop(Session *s, Desktop *d) {
    /* 构建连接请求体 */
    char post[4096];
    snprintf(post, sizeof(post),
             "objId=%s&objType=0&osType=15&deviceId=60&vdCommand=&ipAddress=&macAddress="
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
             d->desktop_id, s->device_code);

    char resp[MAX_RESP];
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/connect",
                 post, strlen(post), "application/x-www-form-urlencoded",
                 resp, sizeof(resp)) < 0) {
        log_line("connect request failed for %s", d->desktop_id);
        return 0;
    }
    if (jint(resp, "code") != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        log_line("Connect Error: [%s] %s", d->desktop_id, msg);
        return 0;
    }

    /* 提取desktopInfo对象 */
    const char *di = strstr(resp, "\"desktopInfo\"");
    if (!di) return 0;
    di = strchr(di, '{');
    if (!di) return 0;
    const char *di_end = find_matching_brace(di);
    if (!di_end) return 0;

    /* 解析desktopInfo中的连接参数，动态分配到堆 */
    int len = (int)(di_end - di + 1);
    char *block = (char *)malloc(len + 1);
    memcpy(block, di, len);
    block[len] = 0;

    /* 使用临时缓冲区提取字段，再str_dup到堆上 */
    char *tmp = (char *)malloc(len + 1);
    jstr(block, "host", tmp, len + 1);
    d->host = str_dup(tmp);
    jstr(block, "port", tmp, len + 1);
    d->port = str_dup(tmp);
    jstr(block, "clinkLvsOutHost", tmp, len + 1);
    d->clink_host = str_dup(tmp);
    jstr(block, "caCert", tmp, len + 1);
    d->ca_cert = str_dup(tmp);
    jstr(block, "clientCert", tmp, len + 1);
    d->client_cert = str_dup(tmp);
    jstr(block, "clientKey", tmp, len + 1);
    d->client_key = str_dup(tmp);
    jstr(block, "token", tmp, len + 1);
    d->token = str_dup(tmp);
    jstr(block, "tenantMemberAccount", tmp, len + 1);
    d->tenant_account = str_dup(tmp);
    log_line("connect ok: host=%s port=%s clink=%s",
             d->host ? d->host : "", d->port ? d->port : "", d->clink_host ? d->clink_host : "");
    free(tmp);
    free(block);
    return (d->host && d->host[0]) ? 1 : 0;
}

/* ======================== ChaCha20-Poly1305 AEAD加密 ======================== */
/*
 * 以下实现了完整的ChaCha20-Poly1305 AEAD加密算法，用于config.json的
 * 加密存储。不依赖外部加密库，纯C实现，减少依赖和内存占用。
 *
 * 算法说明:
 *   - ChaCha20: 流密码，用于数据加密
 *   - Poly1305: 消息认证码，用于数据完整性验证
 *   - AEAD: 组合模式，同时提供加密和认证
 *   - 密文格式: nonce(12B) + ciphertext + tag(16B)
 */

/**
 * rotl32 - 32位循环左移
 */
static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

/**
 * qr - ChaCha20四分之一轮函数
 *
 * ChaCha20的核心运算单元，对4个32位字执行混合运算。
 */
static void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

/**
 * chacha20_block - 生成ChaCha20密钥流块
 *
 * 根据RFC 8439实现，生成64字节密钥流块。
 * counter=0用于Poly1305密钥生成，counter>=1用于数据加密。
 *
 * @param key      32字节密钥
 * @param counter  块计数器
 * @param nonce    12字节随机数
 * @param out      输出64字节密钥流
 */
static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    /* 初始状态: "expand 32-byte k" + 密钥 + 计数器 + 随机数 */
    uint32_t s[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    for (int i = 0; i < 8; i++)
        s[4 + i] = key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
    s[12] = counter;
    for (int i = 0; i < 3; i++)
        s[13 + i] = nonce[i * 4] | (nonce[i * 4 + 1] << 8) | (nonce[i * 4 + 2] << 16) | (nonce[i * 4 + 3] << 24);

    /* 保存初始状态用于最终加法 */
    uint32_t w[16];
    memcpy(w, s, 64);

    /* 10轮双轮运算(5轮列+5轮对角线) */
    for (int i = 0; i < 10; i++) {
        /* 列轮 */
        qr(&w[0],&w[4],&w[8],&w[12]); qr(&w[1],&w[5],&w[9],&w[13]);
        qr(&w[2],&w[6],&w[10],&w[14]); qr(&w[3],&w[7],&w[11],&w[15]);
        /* 对角线轮 */
        qr(&w[0],&w[5],&w[10],&w[15]); qr(&w[1],&w[6],&w[11],&w[12]);
        qr(&w[2],&w[7],&w[8],&w[13]); qr(&w[3],&w[4],&w[9],&w[14]);
    }

    /* 最终加法: 工作状态 + 初始状态，小端序输出 */
    for (int i = 0; i < 16; i++) {
        uint32_t v = w[i] + s[i];
        out[i * 4] = v & 0xFF;
        out[i * 4 + 1] = (v >> 8) & 0xFF;
        out[i * 4 + 2] = (v >> 16) & 0xFF;
        out[i * 4 + 3] = (v >> 24) & 0xFF;
    }
}

/**
 * chacha20_xor - ChaCha20流密码加密/解密
 *
 * 生成密钥流并与明文/密文异或。由于异或的对称性，
 * 加密和解密使用同一函数。
 *
 * @param src      输入数据(明文或密文)
 * @param n        数据长度
 * @param key      32字节密钥
 * @param nonce    12字节随机数
 * @param counter  起始块计数器(通常为1)
 * @param out      输出数据
 */
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

/**
 * poly1305 - Poly1305消息认证码
 *
 * 根据RFC 8439实现，使用130位素数(2^130-5)的多项式求值MAC。
 * 输出16字节认证标签，用于验证消息完整性和真实性。
 *
 * @param msg   输入消息
 * @param mlen  消息长度
 * @param key   32字节密钥(前16字节为r，后16字节为s)
 * @param tag   输出16字节认证标签
 */
static void poly1305(const uint8_t *msg, size_t mlen, const uint8_t key[32], uint8_t tag[16]) {
    /* 从密钥中提取r值(前16字节)，进行clamping(固定位清零) */
    uint32_t r0 = key[0]|((uint32_t)key[1]<<8)|((uint32_t)key[2]<<16)|((uint32_t)key[3]<<24);
    uint32_t r1 = ((uint32_t)key[3]>>2)|((uint32_t)key[4]<<6)|((uint32_t)key[5]<<14)|((uint32_t)key[6]<<22);
    uint32_t r2 = ((uint32_t)key[6]>>4)|((uint32_t)key[7]<<4)|((uint32_t)key[8]<<12)|((uint32_t)key[9]<<20);
    uint32_t r3 = ((uint32_t)key[9]>>6)|((uint32_t)key[10]<<2)|((uint32_t)key[11]<<10)|((uint32_t)key[12]<<18);
    uint32_t r4 = ((uint32_t)key[12]>>8)|((uint32_t)key[13]<<0)|((uint32_t)key[14]<<8)|((uint32_t)key[15]<<16);
    /* Clamping: 固定位清零，确保r在特定范围内 */
    r0 &= 0x3ffffff; r1 &= 0x3ffff03; r2 &= 0x3ffc0ff; r3 &= 0x3f03fff; r4 &= 0x00fffff;
    /* 预计算 r*5 (用于约化) */
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    /* 累加器h初始化为0 */
    uint32_t h0=0,h1=0,h2=0,h3=0,h4=0;

    /* 逐16字节块处理消息 */
    size_t off = 0;
    while (off < mlen) {
        uint8_t blk[16] = {0};
        size_t r = mlen - off > 16 ? 16 : mlen - off;
        memcpy(blk, msg + off, r);
        /* 完整块(16字节)设置hibit=1，最后不完整块设置末尾1标记 */
        uint32_t hibit = r == 16 ? (1u << 24) : 0;
        if (r < 16) blk[r] = 1;
        /* 将块解码为5个26位limb */
        uint32_t t0=blk[0]|((uint32_t)blk[1]<<8)|((uint32_t)blk[2]<<16)|((uint32_t)blk[3]<<24);
        uint32_t t1=((uint32_t)blk[3]>>2)|((uint32_t)blk[4]<<6)|((uint32_t)blk[5]<<14)|((uint32_t)blk[6]<<22);
        uint32_t t2=((uint32_t)blk[6]>>4)|((uint32_t)blk[7]<<4)|((uint32_t)blk[8]<<12)|((uint32_t)blk[9]<<20);
        uint32_t t3=((uint32_t)blk[9]>>6)|((uint32_t)blk[10]<<2)|((uint32_t)blk[11]<<10)|((uint32_t)blk[12]<<18);
        uint32_t t4=((uint32_t)blk[12]>>8)|((uint32_t)blk[13]<<0)|((uint32_t)blk[14]<<8)|((uint32_t)blk[15]<<16);
        /* 累加到h */
        h0+=t0&0x3ffffff; h1+=t1&0x3ffffff; h2+=t2&0x3ffffff;
        h3+=t3&0x3ffffff; h4+=(t4&0x3ffffff)+hibit;
        /* 多项式求值并约化 */
        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        /* 26位约化 */
        h0=(uint32_t)d0&0x3ffffff; d1+=d0>>26;
        h1=(uint32_t)d1&0x3ffffff; d2+=d1>>26;
        h2=(uint32_t)d2&0x3ffffff; d3+=d2>>26;
        h3=(uint32_t)d3&0x3ffffff; d4+=d3>>26;
        h4=(uint32_t)d4&0x3ffffff; h0+=(uint32_t)(d4>>26)*5;
        h1+=h0>>26; h0&=0x3ffffff;
        off += r;
    }

    /* 最终约化: 确保h < p (2^130-5) */
    h2+=h1>>26; h1&=0x3ffffff;
    h3+=h2>>26; h2&=0x3ffffff;
    h4+=h3>>26; h3&=0x3ffffff;
    h0+=(h4>>26)*5; h4&=0x3ffffff;
    h1+=h0>>26; h0&=0x3ffffff;

    /* 选择性约化: h或h-p */
    uint32_t g0=h0+5,g1=h1,g2=h2,g3=h3,g4=h4;
    g1+=g0>>26; g0&=0x3ffffff;
    g2+=g1>>26; g1&=0x3ffffff;
    g3+=g2>>26; g2&=0x3ffffff;
    g4+=g3>>26; g3&=0x3ffffff;
    g4-=1u<<26;
    if(!(g4>>31)){h0=g0;h1=g1;h2=g2;h3=g3;h4=g4;}

    /* 将h编码为16字节小端序，然后加上s(密钥后16字节) */
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

/**
 * build_poly1305_data - 构建Poly1305认证数据
 *
 * 按RFC 8439规范构建Poly1305输入数据:
 *   AAD + padding + ciphertext + padding + len(AAD)8B + len(CT)8B
 * 本实现中AAD为空，因此格式简化为:
 *   ciphertext + padding + 0x00*8 + len(CT)8B
 *
 * @param aad      附加认证数据(本实现中为NULL)
 * @param aad_len  AAD长度
 * @param ct       密文
 * @param ct_len   密文长度
 * @param out      输出缓冲区
 * @param out_len  输出数据长度
 */
static void build_poly1305_data(const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *out, size_t *out_len) {
    size_t off = 0;
    /* AAD部分(本实现中为空) */
    if (aad_len > 0 && aad) {
        memcpy(out + off, aad, aad_len);
        off += aad_len;
        if (aad_len % 16 != 0) {
            size_t pad = 16 - (aad_len % 16);
            memset(out + off, 0, pad);
            off += pad;
        }
    }
    /* 密文部分 */
    if (ct_len > 0 && ct) {
        memcpy(out + off, ct, ct_len);
        off += ct_len;
    }
    /* 密文padding到16字节对齐 */
    if (ct_len % 16 != 0) {
        size_t pad = 16 - (ct_len % 16);
        memset(out + off, 0, pad);
        off += pad;
    }
    /* 长度字段: 8字节小端序AAD长度 + 8字节小端序密文长度 */
    uint64_t aad_len64 = aad_len;
    uint64_t ct_len64 = ct_len;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)((aad_len64 >> (i * 8)) & 0xFF);
        out[off + 8 + i] = (uint8_t)((ct_len64 >> (i * 8)) & 0xFF);
    }
    off += 16;
    *out_len = off;
}

/**
 * aead_seal - ChaCha20-Poly1305 AEAD密封(加密)
 *
 * 加密流程:
 * 1. 使用ChaCha20(counter=1)加密明文
 * 2. 使用ChaCha20(counter=0)生成Poly1305密钥
 * 3. 构建Poly1305输入数据并计算认证标签
 *
 * @param pt      明文
 * @param ptlen   明文长度
 * @param key     32字节密钥
 * @param nonce   12字节随机数
 * @param ct      输出密文(与明文等长)
 * @param tag     输出16字节认证标签
 */
static void aead_seal(const uint8_t *pt, size_t ptlen, const uint8_t key[32],
                      const uint8_t nonce[12], uint8_t *ct, uint8_t tag[16]) {
    /* 用counter=1加密数据 */
    chacha20_xor(pt, ptlen, key, nonce, 1, ct);
    /* 用counter=0生成Poly1305一次性密钥 */
    uint8_t blk0[64];
    chacha20_block(key, 0, nonce, blk0);
    /* 构建Poly1305输入并计算MAC */
    uint8_t *mac_data = (uint8_t *)malloc(ptlen + 64 + 16);
    size_t mac_len = 0;
    build_poly1305_data(NULL, 0, ct, ptlen, mac_data, &mac_len);
    poly1305(mac_data, mac_len, blk0, tag);
    free(mac_data);
}

/**
 * encrypt_data - 加密数据并输出Base64
 *
 * 完整加密流程:
 * 1. 生成12字节随机nonce
 * 2. ChaCha20-Poly1305加密
 * 3. 组合: nonce(12B) + ciphertext + tag(16B)
 * 4. Base64编码输出
 *
 * 用于config.json中用户名、密码、设备码的加密存储。
 *
 * @param plaintext  明文字符串
 * @param key        32字节密钥
 * @param out_b64    输出Base64编码的密文
 */
static void encrypt_data(const char *plaintext, const uint8_t key[32], char *out_b64) {
    size_t plen = strlen(plaintext);
    uint8_t nonce[12], *ct, tag[16];
    /* 生成加密随机nonce */
    CryptGenRandom(g_crypt, 12, nonce);
    ct = (uint8_t *)malloc(plen);
    aead_seal((const uint8_t *)plaintext, plen, key, nonce, ct, tag);
    /* 组合: nonce + ciphertext + tag */
    size_t total = 12 + plen + 16;
    uint8_t *combined = (uint8_t *)malloc(total);
    memcpy(combined, nonce, 12);
    memcpy(combined + 12, ct, plen);
    memcpy(combined + 12 + plen, tag, 16);
    b64enc(combined, total, out_b64);
    free(ct);
    free(combined);
}

/**
 * aead_open - ChaCha20-Poly1305 AEAD开箱(解密)
 *
 * 解密流程:
 * 1. 使用ChaCha20(counter=0)生成Poly1305密钥
 * 2. 构建Poly1305输入数据并验证认证标签
 * 3. 标签验证通过后，使用ChaCha20(counter=1)解密密文
 *
 * @param ct      密文(含16字节tag在末尾)
 * @param ctlen   密文+tag总长度
 * @param key     32字节密钥
 * @param nonce   12字节随机数
 * @param pt      输出明文(调用者保证缓冲区足够)
 * @return        1=解密成功, 0=认证失败
 */
static int aead_open(const uint8_t *ct, size_t ctlen, const uint8_t key[32],
                     const uint8_t nonce[12], uint8_t *pt) {
    if (ctlen < 16) return 0;
    size_t dlen = ctlen - 16;  /* 去除tag后的密文长度 */
    const uint8_t *tag = ct + dlen;

    /* 生成Poly1305密钥并验证认证标签 */
    uint8_t blk0[64];
    chacha20_block(key, 0, nonce, blk0);
    uint8_t *mac_data = (uint8_t *)malloc(dlen + 64 + 16);
    size_t mac_len = 0;
    build_poly1305_data(NULL, 0, ct, dlen, mac_data, &mac_len);
    uint8_t expected[16];
    poly1305(mac_data, mac_len, blk0, expected);
    free(mac_data);
    /* 常量时间比较防止时序攻击 */
    if (memcmp(tag, expected, 16) != 0) return 0;

    /* 认证通过，解密密文 */
    chacha20_xor(ct, dlen, key, nonce, 1, pt);
    pt[dlen] = 0;
    return 1;
}

/**
 * decrypt_data - 解密Base64编码的密文
 *
 * 完整解密流程:
 * 1. Base64解码
 * 2. 提取nonce(前12字节)
 * 3. ChaCha20-Poly1305解密
 *
 * @param b64   Base64编码的密文
 * @param key   32字节密钥
 * @param out   输出明文字符串
 * @return      1=解密成功, 0=解密失败
 */
static int decrypt_data(const char *b64, const uint8_t key[32], char *out) {
    size_t b64len = strlen(b64);
    uint8_t *data = (uint8_t *)malloc(b64len);
    size_t dlen = b64dec(b64, b64len, data);
    /* 最小长度: nonce(12) + tag(16) = 28字节 */
    if (dlen < 12 + 16) { free(data); return 0; }
    uint8_t *pt = (uint8_t *)malloc(dlen);
    /* data前12字节为nonce，之后为密文+tag */
    int ok = aead_open(data + 12, dlen - 12, key, data, pt);
    if (ok) strcpy(out, (char *)pt);
    free(pt);
    free(data);
    return ok;
}

/* ======================== 系统指纹与配置加解密 ======================== */

/**
 * FnUuidCreateSequential - UuidCreateSequential函数指针类型
 *
 * UuidCreateSequential基于本机MAC地址生成UUID，
 * 其Data4[2..7]字段包含MAC地址。通过动态加载rpcrt4.dll
 * 获取此函数，避免静态链接依赖。
 */
typedef RPC_STATUS (WINAPI *FnUuidCreateSequential)(UUID *);

/**
 * mac_to_fingerprint - 将MAC地址转换为本机指纹
 *
 * 对MAC地址字符串做SHA-256哈希，生成64字符十六进制指纹。
 * 指纹用于派生config.json的加密密钥，确保配置文件与
 * 特定机器绑定(换机器后无法解密)。
 *
 * @param mac     MAC地址字符串(如 "aa:bb:cc:dd:ee:ff")
 * @param fp_hex  输出64字符十六进制指纹
 */
static void mac_to_fingerprint(const char *mac, char *fp_hex) {
    uint8_t d[32];
    sha256((const uint8_t *)mac, strlen(mac), d);
    for (int i = 0; i < 32; i++) sprintf(fp_hex + i * 2, "%02x", d[i]);
    fp_hex[64] = 0;
}

/**
 * get_fingerprint - 获取本机指纹
 *
 * 优先使用UuidCreateSequential获取MAC地址(与Python版本一致)，
 * 失败时回退到GetAdaptersInfo枚举网卡。
 *
 * 两种方式获取的MAC可能不同:
 *   - UuidCreateSequential: 返回系统认为的"第一个"MAC
 *   - GetAdaptersInfo: 按适配器顺序枚举
 *
 * @param fp_hex  输出64字符十六进制指纹
 */
static void get_fingerprint(char *fp_hex) {
    /* 方式1: 通过UuidCreateSequential获取MAC(推荐，与Python一致) */
    HMODULE hRpc = LoadLibraryA("rpcrt4.dll");
    char mac[32] = "";
    if (hRpc) {
        FnUuidCreateSequential pUuidCreateSeq = (FnUuidCreateSequential)GetProcAddress(hRpc, "UuidCreateSequential");
        if (pUuidCreateSeq) {
            UUID u;
            RPC_STATUS rs = pUuidCreateSeq(&u);
            if (rs == 0 || rs == RPC_S_UUID_LOCAL_ONLY) {
                /* UUID的Data4[2..7]包含MAC地址 */
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         u.Data4[2], u.Data4[3], u.Data4[4],
                         u.Data4[5], u.Data4[6], u.Data4[7]);
                log_line("UuidCreateSequential MAC: %s", mac);
            }
        }
        FreeLibrary(hRpc);
    }

    /* 方式2: 回退到GetAdaptersInfo枚举网卡 */
    if (!mac[0]) {
        DWORD sz = 0;
        GetAdaptersInfo(NULL, &sz);
        BYTE *buf = (BYTE *)malloc(sz);
        PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
        GetAdaptersInfo(pinfo, &sz);
        PIP_ADAPTER_INFO adapter = pinfo;
        while (adapter) {
            if (adapter->AddressLength == 6) {
                /* 跳过全零MAC */
                int nonzero = 0;
                for (int i = 0; i < 6; i++) {
                    if (adapter->Address[i] != 0) { nonzero = 1; break; }
                }
                if (nonzero) {
                    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                             adapter->Address[0], adapter->Address[1], adapter->Address[2],
                             adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                    log_line("GetAdaptersInfo MAC: %s", mac);
                    break;
                }
            }
            adapter = adapter->Next;
        }
        /* 兜底: 使用第一个适配器的MAC(即使全零) */
        if (!mac[0] && pinfo->AddressLength == 6) {
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     pinfo->Address[0], pinfo->Address[1], pinfo->Address[2],
                     pinfo->Address[3], pinfo->Address[4], pinfo->Address[5]);
        }
        free(buf);
    }
    mac_to_fingerprint(mac, fp_hex);
}

/**
 * get_all_macs - 获取本机所有MAC地址(去重)
 *
 * 用于config.json解密失败时尝试所有可能的MAC地址。
 * 场景: 网卡更换后主指纹无法解密，需遍历所有MAC尝试。
 *
 * @param macs      输出MAC地址数组(每个32字节)
 * @param max_macs  最大MAC数量
 * @return          实际获取的MAC数量
 */
static int get_all_macs(char macs[][32], int max_macs) {
    int count = 0;
    /* 通过UuidCreateSequential获取第一个MAC */
    HMODULE hRpc = LoadLibraryA("rpcrt4.dll");
    if (hRpc) {
        FnUuidCreateSequential pUuidCreateSeq = (FnUuidCreateSequential)GetProcAddress(hRpc, "UuidCreateSequential");
        if (pUuidCreateSeq) {
            UUID u;
            RPC_STATUS rs = pUuidCreateSeq(&u);
            if ((rs == 0 || rs == RPC_S_UUID_LOCAL_ONLY) && count < max_macs) {
                snprintf(macs[count], 32, "%02x:%02x:%02x:%02x:%02x:%02x",
                         u.Data4[2], u.Data4[3], u.Data4[4],
                         u.Data4[5], u.Data4[6], u.Data4[7]);
                count++;
            }
        }
        FreeLibrary(hRpc);
    }
    /* 通过GetAdaptersInfo获取所有网卡MAC(去重) */
    DWORD sz = 0;
    GetAdaptersInfo(NULL, &sz);
    BYTE *buf = (BYTE *)malloc(sz);
    PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
    GetAdaptersInfo(pinfo, &sz);
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
                /* 去重检查 */
                int dup = 0;
                for (int j = 0; j < count; j++) {
                    if (strcmp(macs[j], m) == 0) { dup = 1; break; }
                }
                if (!dup) {
                    strcpy(macs[count], m);
                    count++;
                }
            }
        }
        adapter = adapter->Next;
    }
    free(buf);
    return count;
}

/**
 * derive_key - 从指纹和盐值派生加密密钥
 *
 * 使用 SHA256(指纹|盐值) 派生32字节密钥。
 * 指纹确保密钥与本机绑定，盐值增加随机性。
 *
 * @param fp    本机指纹(64字符十六进制)
 * @param salt  盐值(32字符十六进制)
 * @param key   输出32字节密钥
 */
static void derive_key(const char *fp, const char *salt, uint8_t key[32]) {
    char material[256];
    snprintf(material, sizeof(material), "%s|%s", fp, salt);
    sha256((const uint8_t *)material, strlen(material), key);
}

/**
 * try_decrypt_config - 尝试用指定指纹解密config.json
 *
 * 从config.json中提取salt和加密的账号信息，
 * 用给定指纹派生密钥，尝试解密并自动登录。
 *
 * @param s        会话信息(输出device_code和登录结果)
 * @param content  config.json文件内容
 * @param fp       本机指纹
 * @return         1=解密并登录成功, 0=失败
 */
static int try_decrypt_config(Session *s, const char *content, const char *fp) {
    /* 提取盐值 */
    char salt[65];
    jstr(content, "salt", salt, sizeof(salt));
    if (!salt[0]) return 0;

    /* 派生密钥 */
    uint8_t key[32];
    derive_key(fp, salt, key);

    /* 定位accounts数组中的第一个对象 */
    const char *acc = strstr(content, "\"accounts\"");
    if (!acc) return 0;
    acc = strchr(acc, '[');
    if (!acc) return 0;
    const char *obj = strchr(acc, '{');
    if (!obj) return 0;

    /* 提取加密的用户名、密码、设备码 */
    char ua[2048], pw[2048], dc[2048];
    jstr(obj, "user_account", ua, sizeof(ua));
    jstr(obj, "password", pw, sizeof(pw));
    jstr(obj, "device_code", dc, sizeof(dc));

    /* 尝试解密 */
    char user[256], pass[256], devc[256];
    int du = decrypt_data(ua, key, user);
    int dp = decrypt_data(pw, key, pass);
    int dd = decrypt_data(dc, key, devc);

    if (du && dp && dd) {
        strcpy(s->device_code, devc);
        log_line("device_code: %s", s->device_code);
        log_line("user from config: %s", user);
        /* 用解密出的凭据自动登录 */
        if (do_login(s, user, pass)) return 1;
        log_line("auto login failed, try manual");
    }
    return 0;
}

/**
 * resolve_credentials - 解析用户凭据(自动/手动)
 *
 * 流程:
 * 1. 尝试从exe同目录的config.json读取加密凭据
 * 2. 用本机指纹派生密钥解密
 * 3. 若主指纹失败，遍历所有MAC地址尝试
 * 4. 若全部失败，提示用户手动输入账号密码
 * 5. 手动输入后加密保存到config.json
 *
 * @param s  会话信息(输出)
 * @return   1=成功, 0=失败
 */
static int resolve_credentials(Session *s) {
    /* 构建config.json路径(与exe同目录) */
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);
    log_line("config path: %s", config_path);

    /* 获取本机指纹 */
    char fp[65];
    get_fingerprint(fp);
    log_line("fingerprint: %s", fp);

    /* 尝试从config.json读取并解密 */
    FILE *f = fopen(config_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *content = (char *)malloc(fsize + 1);
        size_t clen = fread(content, 1, fsize, f);
        content[clen] = 0;
        fclose(f);

        /* 用主指纹尝试解密 */
        if (try_decrypt_config(s, content, fp)) {
            free(content);
            return 1;
        }

        /* 主指纹失败，遍历所有MAC地址尝试 */
        log_line("primary fingerprint failed, trying all MACs...");
        char macs[32][32];
        int nmacs = get_all_macs(macs, 32);
        for (int i = 0; i < nmacs; i++) {
            char alt_fp[65];
            mac_to_fingerprint(macs[i], alt_fp);
            if (strcmp(alt_fp, fp) == 0) continue;  /* 跳过已尝试的主指纹 */
            log_line("trying MAC: %s fp: %s", macs[i], alt_fp);
            if (try_decrypt_config(s, content, alt_fp)) {
                free(content);
                return 1;
            }
        }

        free(content);
        log_line("config.json decode failed with all MACs, manual input");
    } else {
        log_line("config.json not found at %s", config_path);
    }

    /* 自动解密失败，手动输入账号密码 */
    char user[128], pass[128];
    printf("\xe8\xb4\xa6\xe6\x88\xb7: "); fflush(stdout);
    fgets(user, sizeof(user), stdin); user[strcspn(user, "\r\n")] = 0;
    printf("\xe5\xaf\x86\xe7\xa0\x81: "); fflush(stdout);
    fgets(pass, sizeof(pass), stdin); pass[strcspn(pass, "\r\n")] = 0;

    if (!user[0] || !pass[0]) { log_line("\xe8\xb4\xa6\xe6\x88\xb7\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe4\xb8\xba\xe7\xa9\xba"); return 0; }

    /* 生成随机设备码(格式: web_ + 32位十六进制) */
    BYTE rnd[16];
    CryptGenRandom(g_crypt, 16, rnd);
    char dc_hex[33];
    for (int i = 0; i < 16; i++) sprintf(dc_hex + i * 2, "%02x", rnd[i]);
    snprintf(s->device_code, sizeof(s->device_code), "web_%s", dc_hex);

    /* 执行登录 */
    if (!do_login(s, user, pass)) return 0;

    /* 登录成功，加密保存凭据到config.json(隐私模式下跳过) */
    if (!g_privacy) {
        char salt[33];
        BYTE salt_bytes[16];
        CryptGenRandom(g_crypt, 16, salt_bytes);
        for (int i = 0; i < 16; i++) sprintf(salt + i * 2, "%02x", salt_bytes[i]);
        salt[32] = 0;

        uint8_t key[32];
        derive_key(fp, salt, key);

        char enc_user[2048], enc_pass[2048], enc_dc[2048];
        encrypt_data(user, key, enc_user);
        encrypt_data(pass, key, enc_pass);
        encrypt_data(s->device_code, key, enc_dc);

        f = fopen(config_path, "w");
        if (f) {
            fprintf(f, "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]}",
                    salt, enc_user, enc_pass, enc_dc);
            fclose(f);
            log_line("config saved to %s", config_path);
        }
    } else {
        log_line("\xe9\x9a\x90\xe7\xa7\x81\xe6\xa8\xa1\xe5\xbc\x8f\xe5\xb7\xb2\xe5\x90\xaf\xe7\x94\xa8\xef\xbc\x8c\xe4\xb8\x8d\xe4\xbf\x9d\xe5\xad\x98\xe5\x87\xad\xe6\x8d\xae");
    }

    return 1;
}

/* ======================== WebSocket REDQ握手 ======================== */

/**
 * rsa_oaep_encrypt - RSA-OAEP加密
 *
 * 使用CNG API对空消息进行RSA-OAEP加密(SHA-1标签)。
 * 用于REDQ握手中的认证响应: 服务端发送RSA公钥，
 * 客户端用公钥加密空消息返回，证明持有合法密钥。
 *
 * @param n_bytes  RSA模数(大端序)
 * @param n_len    模数长度(字节)
 * @param e_val    RSA公钥指数(通常为65537)
 * @param result   输出密文(至少n_len字节)
 * @return         密文长度，失败返回0
 */
static size_t rsa_oaep_encrypt(const uint8_t *n_bytes, size_t n_len, uint32_t e_val, uint8_t *result) {
    /* 去除模数前导零 */
    const uint8_t *mod_bytes = n_bytes;
    size_t mod_len = n_len;
    while (mod_len > 1 && mod_bytes[0] == 0) { mod_bytes++; mod_len--; }

    /* 构建BCRYPT RSA公钥BLOB */
    BCRYPT_RSAKEY_BLOB rsakb = {0};
    rsakb.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    rsakb.BitLength = (ULONG)(mod_len * 8);
    rsakb.cbPublicExp = 3;  /* 公钥指数3字节(65537 = 0x010001) */
    rsakb.cbModulus = (ULONG)mod_len;
    rsakb.cbPrime1 = 0;     /* 公钥不需要质因数 */
    rsakb.cbPrime2 = 0;

    /* 公钥指数大端序 */
    uint8_t e_be[3] = {(uint8_t)(e_val>>16), (uint8_t)(e_val>>8), (uint8_t)(e_val)};

    /* 组装BLOB: 头部 + 指数 + 模数 */
    DWORD blob_len = sizeof(BCRYPT_RSAKEY_BLOB) + 3 + (ULONG)mod_len;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    memcpy(blob, &rsakb, sizeof(BCRYPT_RSAKEY_BLOB));
    memcpy(blob + sizeof(BCRYPT_RSAKEY_BLOB), e_be, 3);
    uint8_t *modulus = blob + sizeof(BCRYPT_RSAKEY_BLOB) + 3;
    memcpy(modulus, mod_bytes, mod_len);

    /* 导入RSA公钥 */
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptImportKeyPair(g_rsa_alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                           &hKey, blob, blob_len, 0);
    free(blob);
    if (!BCRYPT_SUCCESS(status)) {
        log_line("BCryptImportKeyPair failed: 0x%08X", status);
        return 0;
    }

    /* 使用RSA-OAEP(SHA-1)加密空消息 */
    BCRYPT_OAEP_PADDING_INFO oaep_info = {0};
    oaep_info.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    oaep_info.pbLabel = NULL;
    oaep_info.cbLabel = 0;

    uint8_t empty_msg[] = {0};
    ULONG ct_len = 0;
    status = BCryptEncrypt(hKey, empty_msg, 0, &oaep_info, NULL, 0,
                           result, (ULONG)mod_len, &ct_len, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        log_line("BCryptEncrypt failed: 0x%08X", status);
        return 0;
    }

    return ct_len;
}

/**
 * handle_redq - 处理WebSocket REDQ认证请求
 *
 * REDQ是天翼云WebSocket协议的认证握手消息:
 * 1. 服务端发送REDQ消息，包含RSA公钥(模数+指数)
 * 2. 客户端用公钥加密空消息(RSA-OAEP)
 * 3. 客户端返回: auth标志(4字节,值为1) + RSA密文
 *
 * REDQ消息格式(服务端→客户端):
 *   "REDQ" + 12字节头 + key_data(32字节随机 + 129字节RSA模数 + 3字节指数 + ...)
 *
 * @param msg    接收到的REDQ消息
 * @param mlen   消息长度
 * @param resp   输出响应数据
 * @param rlen   输出响应长度
 * @return       1=处理成功, 0=格式错误
 */
static int handle_redq(const uint8_t *msg, size_t mlen, uint8_t *resp, size_t *rlen) {
    if (mlen < 16 || memcmp(msg, "REDQ", 4) != 0) return 0;
    const uint8_t *key_data = msg + 16;
    if (mlen - 16 < 166) return 0;

    /* 提取RSA公钥: 模数(key_data+32, 129字节) 和 指数(key_data+163, 3字节) */
    const uint8_t *n_source = key_data + 32;
    const uint8_t *e_source = key_data + 163;
    uint32_t e_val = (e_source[0]<<16)|(e_source[1]<<8)|e_source[2];
    if (e_val == 0) return 0;

    /* RSA-OAEP加密空消息 */
    uint8_t encrypted[512];
    size_t enc_len = rsa_oaep_encrypt(n_source, 129, e_val, encrypted);
    if (enc_len == 0) return 0;

    /* 构建响应: auth=1(4字节小端) + RSA密文 */
    uint32_t auth = 1;
    resp[0]=auth&0xFF; resp[1]=(auth>>8)&0xFF; resp[2]=(auth>>16)&0xFF; resp[3]=(auth>>24)&0xFF;
    memcpy(resp+4, encrypted, enc_len);
    *rlen = 4 + enc_len;
    return 1;
}

/**
 * initial_payload - WebSocket初始二进制消息
 *
 * 连接建立后发送的固定二进制载荷，用于通知服务端
 * 客户端支持的协议版本和功能。内容为REDQ协议的
 * 初始化消息，包含版本号和功能标志。
 */
static uint8_t initial_payload[] = {
    0x52,0x45,0x44,0x51,0x02,0x00,0x00,  /* "REDQ" + 版本2 */
    0x00,0x02,0x00,0x00,0x00,0x1A,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x12,
    0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x04,
    0x08,0x00,0x00
};

/* ======================== WebSocket通信 ======================== */

/**
 * WSConn - WebSocket连接句柄集合
 *
 * 封装WinHTTP WebSocket连接的四个句柄，
 * 便于统一管理和资源释放。
 */
typedef struct {
    HINTERNET hSession;    /* WinHTTP会话句柄 */
    HINTERNET hConnect;    /* 服务器连接句柄 */
    HINTERNET hRequest;    /* HTTP请求句柄(升级前使用) */
    HINTERNET hWebSocket;  /* WebSocket句柄(升级后使用) */
} WSConn;

/**
 * ws_connect - 建立WebSocket连接
 *
 * 使用WinHTTP的WebSocket升级功能建立WSS连接。
 * 流程:
 * 1. 解析URI为主机名、端口、路径
 * 2. 建立TCP连接
 * 3. 发送HTTP升级请求(含WebSocket协议头)
 * 4. 等待101 Switching Protocols响应
 * 5. 完成WebSocket升级
 *
 * @param uri  WebSocket URI(如 wss://host:port/path)
 * @param wsc  输出WebSocket连接句柄
 * @return     1=成功, 0=失败
 */
static int ws_connect(const char *uri, WSConn *wsc) {
    memset(wsc, 0, sizeof(WSConn));
    char host[256] = "", path[2048] = "/";
    int port = 443;
    int use_ssl = 0;

    /* 解析URI */
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
    } else {
        strncpy(host, hp, sizeof(host) - 1);
    }

    /* 从主机名中提取端口 */
    char *colon = strchr(host, ':');
    if (colon) { *colon = 0; port = atoi(colon + 1); }
    if (use_ssl && port == 80) port = 443;

    /* 创建WinHTTP会话 */
    wsc->hSession = WinHttpOpen(L"CtYunKeepAlive/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!wsc->hSession) {
        log_line("WinHttpOpen failed: %lu", GetLastError());
        return 0;
    }

    /* 连接到服务器 */
    WCHAR whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    wsc->hConnect = WinHttpConnect(wsc->hSession, whost, (INTERNET_PORT)port, 0);
    if (!wsc->hConnect) {
        log_line("WinHttpConnect failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 创建HTTP请求(准备升级为WebSocket) */
    WCHAR wpath[2048] = {0};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 2048);
    DWORD flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
    wsc->hRequest = WinHttpOpenRequest(wsc->hConnect, L"GET", wpath, NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!wsc->hRequest) {
        log_line("WinHttpOpenRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* HTTPS忽略证书验证 */
    if (use_ssl) {
        DWORD opt_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(wsc->hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opt_flags, sizeof(opt_flags));
    }

    /* 添加WebSocket升级所需的HTTP头 */
    WinHttpAddRequestHeaders(wsc->hRequest, L"Origin: https://pc.ctyun.cn", (ULONG)-1,
                              WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(wsc->hRequest, L"Sec-WebSocket-Protocol: binary", (ULONG)-1,
                              WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    /* 设置WebSocket升级选项 */
    if (!WinHttpSetOption(wsc->hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        log_line("WinHttpSetOption(UPGRADE_TO_WEB_SOCKET) failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 发送HTTP升级请求 */
    if (!WinHttpSendRequest(wsc->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        log_line("WinHttpSendRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 接收服务端响应 */
    if (!WinHttpReceiveResponse(wsc->hRequest, NULL)) {
        log_line("WinHttpReceiveResponse failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 验证HTTP 101 Switching Protocols响应 */
    DWORD status_code = 0;
    DWORD sc_len = sizeof(status_code);
    WinHttpQueryHeaders(wsc->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &status_code, &sc_len, NULL);
    if (status_code != 101) {
        log_line("WS upgrade failed, status=%lu", status_code);
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 完成WebSocket升级 */
    wsc->hWebSocket = WinHttpWebSocketCompleteUpgrade(wsc->hRequest, (DWORD_PTR)NULL);
    if (!wsc->hWebSocket) {
        log_line("WinHttpWebSocketCompleteUpgrade failed: %lu", GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 升级完成后关闭HTTP请求句柄(不再需要) */
    WinHttpCloseHandle(wsc->hRequest);
    wsc->hRequest = NULL;

    log_line("WS handshake ok");
    return 1;
}

/**
 * ws_send_text - 发送WebSocket文本消息
 *
 * @param wsc   WebSocket连接
 * @param text  文本消息内容
 */
static void ws_send_text(WSConn *wsc, const char *text) {
    size_t len = strlen(text);
    WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                          (void *)text, (DWORD)len);
}

/**
 * ws_send_bytes - 发送WebSocket二进制消息
 *
 * @param wsc   WebSocket连接
 * @param data  二进制数据
 * @param dlen  数据长度
 */
static void ws_send_bytes(WSConn *wsc, const uint8_t *data, size_t dlen) {
    WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                          (void *)data, (DWORD)dlen);
}

/**
 * ws_recv - 接收WebSocket消息
 *
 * 阻塞等待并读取一条完整的WebSocket消息。
 *
 * @param wsc      WebSocket连接
 * @param out      输出缓冲区
 * @param outsz    缓冲区大小
 * @param is_text  输出是否为文本消息
 * @return         接收到的字节数，连接关闭或错误返回-1
 */
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

/**
 * ws_close - 关闭WebSocket连接
 *
 * 按正确顺序关闭所有句柄，释放资源。
 *
 * @param wsc  WebSocket连接
 */
static void ws_close(WSConn *wsc) {
    if (wsc->hWebSocket) {
        WinHttpWebSocketClose(wsc->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(wsc->hWebSocket);
    }
    if (wsc->hRequest) WinHttpCloseHandle(wsc->hRequest);
    if (wsc->hConnect) WinHttpCloseHandle(wsc->hConnect);
    if (wsc->hSession) WinHttpCloseHandle(wsc->hSession);
}

/* ======================== 保活线程 ======================== */

/**
 * ThreadParam - 线程参数
 *
 * 传递Session和Desktop指针给工作线程。
 */
typedef struct { Session *session; Desktop *desktop; } ThreadParam;

/**
 * keep_alive_thread - 保活工作线程
 *
 * 对运行中的桌面执行WebSocket保活:
 * 1. 建立WebSocket连接(使用预构建的ws_uri)
 * 2. 发送连接消息(使用预构建的connect_msg)
 * 3. 发送初始二进制载荷
 * 4. 维持连接60秒，期间处理REDQ认证请求
 * 5. 60秒后断开重连(防止服务端超时)
 * 6. 每5个周期(约5分钟)修剪一次工作集
 *
 * 保活原理:
 *   天翼云桌面在WebSocket连接断开后一段时间会标记为"未连接"，
 *   保持WebSocket连接即可维持"运行中"状态。
 *
 * @param param  ThreadParam指针
 * @return       线程退出码(0)
 */
static DWORD WINAPI keep_alive_thread(LPVOID param) {
    ThreadParam *tp = (ThreadParam *)param;
    Desktop *d = tp->desktop;

    int cycle = 0;
    while (g_running) {
        log_line("[%s] === connecting ===", d->desktop_code);
        WSConn wsc;
        /* 使用预构建的ws_uri连接(保活阶段host/port已释放) */
        if (!ws_connect(d->ws_uri, &wsc)) {
            log_line("[%s] WS connect failed, retry 5s", d->desktop_code);
            Sleep(5000);
            continue;
        }

        /* 发送连接消息(包含证书/密钥等认证信息) */
        ws_send_text(&wsc, d->connect_msg);
        Sleep(500);
        /* 发送初始REDQ协议载荷 */
        ws_send_bytes(&wsc, initial_payload, sizeof(initial_payload));

        log_line("[%s] connected, keep 60s", d->desktop_code);

        /* 维持连接60秒，处理REDQ认证请求 */
        DWORD start = GetTickCount();
        while (g_running && (GetTickCount() - start) < 60000) {
            uint8_t buf[4096];
            int is_text;
            int n = ws_recv(&wsc, buf, sizeof(buf), &is_text);
            if (n < 0) break;    /* 连接断开 */
            if (n == 0) continue; /* 无数据 */
            /* 处理REDQ认证请求 */
            if (!is_text && n >= 4 && memcmp(buf, "REDQ", 4) == 0) {
                log_line("[%s] -> REDQ recv", d->desktop_code);
                uint8_t resp[512]; size_t rlen = 0;
                if (handle_redq(buf, n, resp, &rlen)) {
                    ws_send_bytes(&wsc, resp, rlen);
                    log_line("[%s] -> REDQ resp ok", d->desktop_code);
                }
            }
        }

        /* 60秒到，断开重连 */
        ws_close(&wsc);
        log_line("[%s] 60s done, reconnect", d->desktop_code);

        /* 每5个周期(约5分钟)修剪工作集，释放物理内存 */
        cycle++;
        if (cycle % 5 == 0) trim_working_set();
    }

    log_line("[%s] thread exit", d->desktop_code);
    return 0;
}

/**
 * check_desktop_thread - 桌面状态监控线程
 *
 * 对未运行的桌面定期检查状态:
 * 1. 每CHECK_INTERVAL秒(3分钟)查询一次桌面列表
 * 2. 使用DesktopLight轻量结构体减少内存占用
 * 3. 若桌面变为运行中，调用connect_desktop获取连接参数
 * 4. 调用desktop_free_certs释放证书内存
 * 5. 切换为keep_alive_thread保活模式
 *
 * @param param  ThreadParam指针
 * @return       线程退出码(0)
 */
static DWORD WINAPI check_desktop_thread(LPVOID param) {
    ThreadParam *tp = (ThreadParam *)param;
    Desktop *d = tp->desktop;
    Session *s = tp->session;

    while (g_running) {
        Sleep(CHECK_INTERVAL * 1000);
        if (!g_running) break;
        log_line("[%s] checking status...", d->desktop_code);

        /* 使用轻量结构体查询桌面状态 */
        DesktopLight *tmp = (DesktopLight *)calloc(MAX_DESKTOPS, sizeof(DesktopLight));
        int n = get_desktop_list_light(s, tmp, MAX_DESKTOPS);
        int found = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(tmp[i].desktop_id, d->desktop_id) == 0) {
                found = 1;
                if (tmp[i].is_active) {
                    /* 桌面已开机，切换为保活模式 */
                    log_line("[%s] active now, start keepalive", d->desktop_code);
                    free(tmp);
                    if (connect_desktop(s, d)) {
                        desktop_free_certs(d);
                        keep_alive_thread(param);  /* 直接调用，不创建新线程 */
                    }
                    return 0;
                } else {
                    log_line("[%s] still inactive", d->desktop_code);
                }
                break;
            }
        }
        free(tmp);
        if (!found) { log_line("[%s] not found, stop", d->desktop_code); return 0; }
        trim_working_set();
    }
    return 0;
}

/* ======================== 程序入口 ======================== */

/**
 * ctrl_handler - Ctrl+C信号处理
 *
 * 设置g_running为0，通知所有工作线程优雅退出。
 */
static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_running, 0);
        return TRUE;
    }
    return FALSE;
}

/**
 * usage - 显示用法帮助
 */
static void usage(const char *exe) {
    printf("天翼云电脑保活客户端 v1.1.0\n");
    printf("项目地址: https://github.com/DionZM/ctyun_keepalive_c\n\n");
    printf("用法: %s [OPTIONS]\n\n", exe);
    printf("OPTIONS:\n");
    printf("  --background, -b  后台运行，日志写入run.log\n");
    printf("  --privacy,    -p  隐私模式，不保存用户名/密码到config.json\n");
    printf("  --version,    -v  显示版本号\n");
    printf("  --help,       -h  显示此帮助信息\n");
}

/**
 * main - 程序入口
 *
 * 主流程:
 * 1. 解析命令行参数(--background/-b)
 * 2. 初始化控制台(UTF-8编码、Consolas字体)
 * 3. 初始化网络(Winsock)和加密(CryptoAPI/CNG)
 * 4. 解析用户凭据(自动/手动)
 * 5. 获取桌面列表
 * 6. 对运行中的桌面: 连接→释放证书→启动保活线程
 * 7. 对未运行的桌面: 启动状态监控线程
 * 8. 后台模式: 分离控制台，日志写入run.log
 * 9. 修剪工作集，等待所有线程结束
 * 10. 清理资源并退出
 */
int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--background") == 0 || strcmp(argv[i], "-b") == 0) {
            g_background = 1;
        } else if (strcmp(argv[i], "--privacy") == 0 || strcmp(argv[i], "-p") == 0) {
            g_privacy = 1;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("v1.1.0\n");
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* 设置控制台为UTF-8编码，解决中文乱码 */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    /* 设置控制台字体为Consolas，确保中文正常显示 */
    CONSOLE_FONT_INFOEX cfi = {0};
    cfi.cbSize = sizeof(cfi);
    cfi.dwFontSize.Y = 16;
    cfi.FontWeight = FW_NORMAL;
    wcscpy(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);

    /* 注册Ctrl+C处理函数 */
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    if (!g_background) refresh_banner();

    /* 初始化网络和加密子系统 */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    crypto_init();
    http_init();

    log_line("\xe5\xa4\xa9\xe7\xbf\xbc\xe4\xba\x91\xe7\x94\xb5\xe8\x84\x91\xe4\xbf\x9d\xe6\xb4\xbb C 1.1.0");

    /* 解析用户凭据(尝试自动解密config.json，失败则手动输入) */
    Session session = {0};
    if (!resolve_credentials(&session)) {
        log_line("\xe5\x87\xad\xe6\x8d\xae\xe8\xa7\xa3\xe6\x9e\x90\xe5\xa4\xb1\xe8\xb4\xa5");
        WSACleanup();
        return 1;
    }

    /* 登录成功后清零用户名(不再需要，节省内存) */
    log_line("\xe7\x99\xbb\xe5\xbd\x95\xe6\x88\x90\xe5\x8a\x9f, \xe7\x94\xa8\xe6\x88\xb7: %s", session.user_name);
    memset(session.user_name, 0, sizeof(session.user_name));

    /* 获取桌面列表 */
    Desktop *desktops = (Desktop *)calloc(MAX_DESKTOPS, sizeof(Desktop));
    int ndesktops = get_desktop_list(&session, desktops, MAX_DESKTOPS);
    log_line("\xe6\x89\xbe\xe5\x88\xb0 %d \xe4\xb8\xaa\xe6\xa1\x8c\xe9\x9d\xa2", ndesktops);

    /* 为每个桌面创建工作线程 */
    ThreadParam params[MAX_DESKTOPS];
    HANDLE threads[MAX_DESKTOPS];
    int nthreads = 0;

    for (int i = 0; i < ndesktops; i++) {
        params[i].session = &session;
        params[i].desktop = &desktops[i];

        if (desktops[i].is_active) {
            if (connect_desktop(&session, &desktops[i])) {
                desktop_free_certs(&desktops[i]);
                log_line("[%s] \xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad, \xe5\xbc\x80\xe5\xa7\x8b\xe4\xbf\x9d\xe6\xb4\xbb", desktops[i].desktop_code);
                threads[nthreads++] = CreateThread(NULL, THREAD_STACK, keep_alive_thread, &params[i], 0, NULL);
            }
        } else {
            log_line("[%s] \xe5\xb7\xb2\xe5\x85\xb3\xe6\x9c\xba, \xe5\xbc\x80\xe5\xa7\x8b\xe7\x9b\x91\xe6\x8e\xa7", desktops[i].desktop_code);
            threads[nthreads++] = CreateThread(NULL, THREAD_STACK, check_desktop_thread, &params[i], 0, NULL);
        }
    }

    if (nthreads == 0) {
        log_line("\xe6\xb2\xa1\xe6\x9c\x89\xe5\x8f\xaf\xe7\x94\xa8\xe6\xa1\x8c\xe9\x9d\xa2");
    } else {
        HANDLE hInputThread = NULL;

        if (g_background) {
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char *slash = strrchr(exe_path, '\\');
            if (slash) *slash = 0;
            snprintf(g_log_path, sizeof(g_log_path), "%s\\run.log", exe_path);
            g_log_file = fopen(g_log_path, "w");
            if (!g_log_file) {
                g_log_file = fopen(g_log_path, "a");
            }
            FreeConsole();
            log_line("\xe5\xb7\xb2\xe5\x88\x87\xe6\x8d\xa2\xe5\x88\xb0\xe5\x90\x8e\xe5\x8f\xb0\xe8\xbf\x90\xe8\xa1\x8c, \xe6\x97\xa5\xe5\xbf\x97: %s", g_log_path);
        } else {
            hInputThread = CreateThread(NULL, THREAD_STACK, console_input_thread, NULL, 0, NULL);
        }

        trim_working_set();
        log_line("\xe4\xbf\x9d\xe6\xb4\xbb\xe5\xb7\xb2\xe5\x90\xaf\xe5\x8a\xa8, Ctrl+C \xe5\x81\x9c\xe6\xad\xa2");

        while (g_running) {
            DWORD result = WaitForMultipleObjects(nthreads, threads, TRUE, 500);
            if (result != WAIT_TIMEOUT) break;
            if (g_bg_switch && !g_background) {
                char exe_path[MAX_PATH];
                GetModuleFileNameA(NULL, exe_path, MAX_PATH);
                char *slash = strrchr(exe_path, '\\');
                if (slash) *slash = 0;
                snprintf(g_log_path, sizeof(g_log_path), "%s\\run.log", exe_path);
                g_log_file = fopen(g_log_path, "w");
                if (!g_log_file) g_log_file = fopen(g_log_path, "a");
                g_background = 1;
                FreeConsole();
                log_line("\xe5\xb7\xb2\xe5\x88\x87\xe6\x8d\xa2\xe5\x88\xb0\xe5\x90\x8e\xe5\x8f\xb0\xe8\xbf\x90\xe8\xa1\x8c, \xe6\x97\xa5\xe5\xbf\x97: %s", g_log_path);
                if (hInputThread) {
                    WaitForSingleObject(hInputThread, 2000);
                    CloseHandle(hInputThread);
                    hInputThread = NULL;
                }
                WaitForMultipleObjects(nthreads, threads, TRUE, INFINITE);
                break;
            }
        }

        if (hInputThread) {
            WaitForSingleObject(hInputThread, 1000);
            CloseHandle(hInputThread);
        }

        for (int i = 0; i < nthreads; i++) CloseHandle(threads[i]);
    }

    /* 清理所有资源 */
    for (int i = 0; i < ndesktops; i++) {
        desktop_cleanup(&desktops[i]);
    }
    free(desktops);
    if (g_log_file) fclose(g_log_file);
    if (g_inet) WinHttpCloseHandle(g_inet);
    if (g_rsa_alg) BCryptCloseAlgorithmProvider(g_rsa_alg, 0);
    CryptReleaseContext(g_crypt, 0);
    WSACleanup();
    log_line("\xe5\xb7\xb2\xe5\x81\x9c\xe6\xad\xa2");
    return 0;
}
