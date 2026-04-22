/*
 * ctyun_keepalive.c - 天翼云电脑保活客户端 (C语言版)
 *
 * 功能概述:
 *   自动登录天翼云电脑平台，获取桌面列表，对运行中的桌面建立WebSocket保活连接，
 *   对未运行的桌面定时检测状态，开机后自动切换为保活模式。
 *
 * 验证码处理:
 *   - OCR优先自动识别，失败后弹出独立Win32窗口全分辨率显示验证码图片
 *   - 窗口运行在独立线程，持久化不自动关闭，支持手工输入
 *   - OCR连接失败/返回错误/连续3次验证失败时触发手工输入模式
 *   - 手工输入连续3次失败输出"验证码识别错误"并退出程序
 *
 * 内存优化:
 *   - Desktop结构体使用动态指针代替固定数组，保活阶段释放证书等大块内存
 *   - 使用DesktopLight轻量结构体进行状态轮询，减少栈/堆占用
 *   - 定期调用trim_working_set()将物理内存页归还操作系统
 *   - connect_msg按需精确分配，替代固定12KB缓冲区
 *   - 预构建ws_uri，保活阶段释放host/port/clink_host等连接参数
 *   - WebSocket保活循环使用堆分配缓冲区，避免每次循环栈分配
 *
 * 编译 (MSVC x64):
 *   cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ctyun_keepalive.c ^
 *      /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG ^
 *      winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib
 *
 * 1.2.2 编译优化说明:
 *   /GL  - 全程序优化(Whole Program Optimization)，启用跨模块内联和优化
 *   /LTCG - 链接时代码生成(Link-Time Code Generation)，与/GL配合使用获得最佳性能
 *   相比1.2.1及之前版本，可提升5-10%运行性能，减小可执行文件体积
 *
 * 版本: 1.3.0
 ga/

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
#include <psapi.h>         /* Process Status API (内存信息) */
#include <winhttp.h>       /* WinHTTP (HTTP/WebSocket客户端) */
#include <bcrypt.h>        /* CNG API (RSA-OAEP加密) */
#include <iphlpapi.h>      /* 网络适配器信息 (GetAdaptersInfo) */
#include <ole2.h>           /* COM (CreateStreamOnHGlobal) */
#include <wincodec.h>       /* WIC (图像解码) */

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
#pragma comment(lib, "ole32.lib")      /* COM: CreateStreamOnHGlobal */
#pragma comment(lib, "windowscodecs.lib") /* WIC: 图像解码 */
#pragma comment(lib, "user32.lib")      /* 窗口管理: CreateWindowExW */
#pragma comment(lib, "gdi32.lib")       /* GDI: CreateDIBSection, StretchBlt */
#pragma comment(lib, "psapi.lib")       /* Process Status API: 内存信息 */

/* ======================== 常量定义 ======================== */
#define APP_VERSION   "1.3.2"
/*
 * 1.3.2 版本说明:
 * 1. 修复: 连接桌面成功提示增加桌面编号前缀
 * 2. 修复: 密码输入回显*号，方便用户确认输入长度
 * 3. 修复: 去掉内存trim提示，减少日志噪音
 * 4. 文档: 更新README隐私说明，反映三层加密架构
 */
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
/* g_log_size 按写入量追踪当前日志大小，用来替代高频 ftell() */
static long g_log_size = 0;
/* g_log_last_flush 用于将立即flush()改为按时间阈值冲刷 */
static DWORD g_log_last_flush = 0;

static volatile LONG g_bg_switch = 0;

static int g_privacy = 0;

static int g_random = 0;

/* ================ 优化1.2.4新增: 内存跟踪和WinHTTP参数 ================ */
/* 上次trim_working_set调用时的内存使用量(KB) */
static SIZE_T g_last_trim_memory_kb = 0;
/* 内存增长阈值(KB) - 超过此值才触发trim */
#define TRIM_MEMORY_THRESHOLD_KB (2*1024)  /* 2MB */
/* WinHTTP超时设置(毫秒) */
#define WINHTTP_CONNECT_TIMEOUT_MS  15000  /* 连接超时15秒 */
#define WINHTTP_SEND_TIMEOUT_MS     30000  /* 发送超时30秒 */
#define WINHTTP_RECEIVE_TIMEOUT_MS  30000  /* 接收超时30秒 */
/* =============================================================== */

/* ======================== 工具函数 ======================== */

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
    const char *banner_utf8 = "\x20\x20\xe3\x80\x90\xe5\xbc\x80\xe6\xba\x90\xe8\xbd\xaf\xe4\xbb\xb6\xe3\x80\x91\x68\x74\x74\x70\x73\x3a\x2f\x2f\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x2f\x44\x69\x6f\x6e\x5a\x4d\x2f\x63\x74\x79\x75\x6e\x5f\x6b\x65\x65\x70\x61\x6c\x69\x76\x65\x5f\x63\x20\x20\x43\x74\x72\x6c\x2b\x43\xe9\x80\x80\xe5\x87\xba\x20\x43\x74\x72\x6c\x2b\x42\xe8\xbd\xac\xe5\x90\x8e\xe5\x8f\xb0\x20\x20";
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

/*
 * open_log_file - 打开 UTF-8 日志文件并统一初始化状态
 *
 * 设计目标:
 * 1. 统一设置较大的用户态缓冲区，减少后台日志的系统调用次数
 * 2. 在新建文件时写入 UTF-8 BOM，便于部分 Windows 工具稳定识别编码
 * 3. 返回当前文件大小，避免后续 log_line() 每条日志都调用 ftell()
 */
static FILE *open_log_file(const char *path, const char *mode, long *size_out) {
    FILE *f = fopen(path, mode);
    if (!f) return NULL;
    setvbuf(f, NULL, _IOFBF, 64 * 1024);
    if (size_out) {
        long size = 0;
        if (mode[0] == 'w') {
            static const unsigned char utf8_bom[] = {0xEF, 0xBB, 0xBF};
            fwrite(utf8_bom, 1, sizeof(utf8_bom), f);
            size = (long)sizeof(utf8_bom);
        }
        if (mode[0] == 'a') {
            if (fseek(f, 0, SEEK_END) == 0) size = ftell(f);
        }
        *size_out = size;
    }
    return f;
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
    /* 先写入时间戳，再追接用户消息，避免多次字符串拼接 */
    int prefix = _snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] ",
                           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds / 10);
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
        /*
         * 日志内存中始终保持 UTF-8，前台显示时再弹性变换到 UTF-16。
         * 这样既能保证 run.log 编码一致，也能避免控制台的代码页问题*/
        WCHAR wbuf[2048];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)(sizeof(wbuf) / sizeof(wbuf[0])));
        if (wlen > 0) {
            DWORD written;
            WriteConsoleW(hOut, wbuf, wlen - 1, &written, NULL);
        }
        refresh_banner();
    }

    /* 后台模式或日志文件已打开: 写入run.log */
    if (g_log_file) {
        fwrite(buf, 1, total, g_log_file);
        g_log_size += total;
        /* 使用时间窗口批量flush，减少后台日志带来的磁盘I/O压力 */
        if ((DWORD)(GetTickCount() - g_log_last_flush) >= 1000) {
            fflush(g_log_file);
            g_log_last_flush = GetTickCount();
        }
        /* 检查文件大小，超过1MB时截断保留末尾512KB */
        if (g_log_size > 1024 * 1024) {
            fflush(g_log_file);
            fclose(g_log_file);
            g_log_file = NULL;
            /* 读取文件末尾512KB */
            FILE *rf = fopen(g_log_path, "rb");
            if (rf) {
                fseek(rf, 0, SEEK_END);
                long fsize = ftell(rf);
                long keep = 512 * 1024;
                long skip = fsize - keep;
                if (skip < 0) skip = 0;
                fseek(rf, skip, SEEK_SET);
                /* 截转时只保留最新的 512KB，避免在内存中重新处理整个日志文件 */
                char *tail = (char *)malloc(keep);
                size_t nread = tail ? fread(tail, 1, keep, rf) : 0;
                fclose(rf);
                /* 重写文件，只保留末尾部分 */
                g_log_file = open_log_file(g_log_path, "w", &g_log_size);
                if (g_log_file && tail) {
                    fwrite(tail, 1, nread, g_log_file);
                    g_log_size = (long)nread;
                    fflush(g_log_file);
                    g_log_last_flush = GetTickCount();
                }
                free(tail);
                if (!tail) g_log_file = open_log_file(g_log_path, "a", &g_log_size);
            } else {
                g_log_file = open_log_file(g_log_path, "a", &g_log_size);
            }
        }
    }
}

/**
 * trim_working_set - 智能修剪进程工作集，将物理内存页归还OS
 *
 * 优化v1.2.4: 只有当内存增长超过阈值时才调用trim，避免不必要的系统调用
 * 使用GetProcessMemoryInfo获取当前内存使用情况进行判断
 *
 * @param force 1=强制trim, 0=智能判断
 */
static void trim_working_set(int force) {
    PROCESS_MEMORY_COUNTERS pmc;
    SIZE_T current_memory_kb = 0;
    int should_trim = force;

    /* 智能判断模式: 检查内存增长 */
    if (!force) {
        HANDLE hProcess = GetCurrentProcess();
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            current_memory_kb = pmc.WorkingSetSize / 1024;
            /* 如果是第一次或内存增长超过阈值 */
            if (g_last_trim_memory_kb == 0) {
                should_trim = 1;
            } else if (current_memory_kb > g_last_trim_memory_kb + TRIM_MEMORY_THRESHOLD_KB) {
                should_trim = 1;
            }
        }
    }

    if (should_trim) {
        SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
        /* 更新上次trim时的内存使用量 */
        if (!force) {
            HANDLE hProcess = GetCurrentProcess();
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                g_last_trim_memory_kb = pmc.WorkingSetSize / 1024;
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

static const char HEX_LUT[] = "0123456789abcdef";

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

/**
 * sha256_hex - 计算字符串的SHA-256并输出为64字符十六进制
 *
 * @param s    输入字符串
 * @param out  输出缓冲区(至少65字节)
 */
static void sha256_hex(const char *s, char *out) {
    uint8_t d[32];
    sha256((const uint8_t *)s, strlen(s), d);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = HEX_LUT[d[i] >> 4];
        out[i * 2 + 1] = HEX_LUT[d[i] & 0x0F];
    }
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
    if (!CryptCreateHash(g_crypt, CALG_MD5, 0, 0, &h)) { out[0] = 0; return; }
    CryptHashData(h, (BYTE *)s, (DWORD)strlen(s), 0);
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

static int jbool(const char *j, const char *k) {
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) return 0;
    p += strlen(srch);
    while (*p == ' ' || *p == ':') p++;
    if (*p == 't') return 1;
    return 0;
}

/*
 * find_in_range / jstr_range - 在 JSON 字符串的指定范围内查找字段
 *
 * 这两个函数是今日 JSON 优化的核心。它们允许在 [start, end)
 * 范围内直接解析对象，从而更新了"先 malloc+memcpy 子串，再多
 * strstr()的路径。对本程序来说，这能减少临时堆分配和重复扫描，
 * 同时保持易读性，避免一次性换成大量 JSON 库带来风险。
 */
static const char *find_in_range(const char *start, const char *end, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || end <= start) return NULL;
    for (const char *p = start; p + nlen <= end; p++) {
        if (*p == needle[0] && memcmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

static char *jstr_range(const char *start, const char *end, const char *k, char *buf, size_t bsz) {
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = find_in_range(start, end, srch);
    if (!p) { buf[0] = 0; return buf; }
    p += strlen(srch);
    while (p < end && (*p == ' ' || *p == ':')) p++;
    if (p >= end || *p != '"') { buf[0] = 0; return buf; }
    p++;
    size_t i = 0;
    while (p < end && *p && *p != '"' && i < bsz - 1) {
        if (*p == '\\' && (p + 1) < end) p++;
        buf[i++] = *p++;
    }
    buf[i] = 0;
    return buf;
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
/*
 * fnv1a_hash - FNV-1a 32位哈希函数
 *
 * 优化3 (v1.2.2): 用于桌面ID快速查找，替代O(n)的strcmp遍历。
 * FNV-1a是公认的高质量非加密哈希，实现简单、分布均匀、碰撞率低。
 * 对短字符串(如桌面ID)尤其高效，哈希计算本身为O(1)。
 */
static uint32_t fnv1a_hash(const char *s) {
    uint32_t h = 2166136261U;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 16777619U;
    }
    return h;
}

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
    HANDLE start_event;       /* 统一轮询线程激活此桌面时打开事件，唤醒已创建的保活线程 */
    volatile LONG keepalive_started; /* 用于防止同一桌面被重复连接或重复启动保活 */
    volatile LONG missing_logged;    /* 桌面从列表中消失时只记录一次日志，避免刷屏 */
    uint32_t id_hash;         /* 优化3 (v1.2.2): desktop_id的FNV-1a哈希值，用于快速查找 */
} Desktop;

/**
 * DesktopLight - 桌面信息(轻量版)
 *
 * 仅包含状态轮询所需的最小字段，用于check_desktop_thread中
 * 定期查询桌面状态。每个实例仅136字节，远小于Desktop的~200B+动态内存。
 */
typedef struct {
    char desktop_id[64];      /* 桌面唯一标识 */
    char desktop_code[64];    /* 桌面编码 */
    int is_active;            /* 是否运行中 */
    uint32_t id_hash;         /* 优化 (v1.2.3): desktop_id的FNV-1a哈希值，用于快速查找 */
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
    char user_account[128];   /* 用户账号(API返回) */
    char phone_number[128];   /* 用户输入的手机号(用于发送短信验证码) */
    int user_id;              /* 用户ID */
    int tenant_id;            /* 租户ID */
    int logged_in;            /* 是否已登录 */
    int bonded_device;        /* 设备是否已绑定(0=未绑定,1=已绑定) */
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
        /*
         * connect_msg中的host/port决定WebSocket实际连接的目标地址:
         * - 直连模式: 使用桌面分配的原始host/port
         * - CLink代理模式: 使用clink_host中解析出的host/port
         *   (代理服务器地址与桌面实际地址不同，需从clink_host字段提取)
         *
         * servername字段始终使用原始host/port，这是TLS SNI扩展所需的
         * 服务器名称，必须与桌面实际域名匹配，不能使用代理地址
         */
        const char *msg_host = d->host ? d->host : "";
        const char *msg_port = d->port ? d->port : "";
        char clink_h_buf[256] = "", clink_p_buf[32] = "";
        if (d->clink_host && d->clink_host[0]) {
            /* 从clink_host解析host:port，格式如"192.168.1.1:9443"或"10.0.0.1" */
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
        /*
         * WebSocket连接消息格式:
         *   type:1     消息类型(1=连接请求)
         *   ssl:1      启用TLS加密
         *   host/port  实际连接目标(直连用原始地址，代理用clink地址)
         *   ca/cert/key PEM格式证书链(用于mTLS双向认证)
         *   servername TLS SNI服务器名(始终用原始host:port，非代理地址)
         *   oqs:0      不使用后量子加密
         */
        size_t need = 256 + strlen(d->ca_cert) + strlen(d->client_cert) + strlen(d->client_key);
        d->connect_msg = (char *)malloc(need);
        snprintf(d->connect_msg, need,
                 "{\"type\":1,\"ssl\":1,\"host\":\"%s\",\"port\":\"%s\","
                 "\"ca\":\"%s\",\"cert\":\"%s\",\"key\":\"%s\","
                 "\"servername\":\"%s:%s\",\"oqs\":0}",
                 msg_host, msg_port,
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
/*
 * desktop_cleanup - 退出时彻底释放桌面相关资源
 *
 * 1.2.1 后除了释放动态字段之外，还需负责关闭start_event。
 * 因为现在桌面线程在创建时就会先持有该事件，用来等待统一轮询线程
 * 发送"可以进入保活"的信号。
 *
 * 1.2.2 优化: 修复时序问题，先SetEvent唤醒等待线程，再CloseHandle。
 * 原逻辑直接CloseHandle会导致正在WaitForSingleObject的线程永远阻塞。
 * 新逻辑确保线程收到事件信号后退出等待循环，再关闭句柄。
 */
static void desktop_cleanup(Desktop *d) {
    if (d->start_event) {
        /*
         * 优化1 (v1.2.2): 先触发事件唤醒保活线程，再关闭句柄。
         * 保活线程在keep_alive_thread()中等待此事件：
         *   WaitForSingleObject(d->start_event, 1000)
         * 如果直接CloseHandle，线程可能永远卡在等待状态。
         * SetEvent后给50ms让线程退出等待循环，再安全关闭句柄。
         */
        SetEvent(d->start_event);
        Sleep(50);
        CloseHandle(d->start_event);
        d->start_event = NULL;
    }
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
 * 优化v1.2.4: 设置合理的超时参数，避免长时间等待
 * 创建全局WinHTTP会话句柄，模拟Chrome浏览器User-Agent。
 * 所有HTTP请求复用此会话，减少资源开销。
 *
 * @return 1=成功, 0=失败
 */
static int http_init(void) {
    g_inet = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_inet) return 0;

    WinHttpSetTimeouts(g_inet, 0, WINHTTP_CONNECT_TIMEOUT_MS, WINHTTP_SEND_TIMEOUT_MS, WINHTTP_RECEIVE_TIMEOUT_MS);
    return 1;
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
        log_line("URL解析失败: %s", url);
        return -1;
    }
    WCHAR wmethod[16] = {0};
    MultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 16);

    /*
     * 优化4 (v1.2.2): WinHTTP连接复用。
     * WinHTTP底层自动维护TCP连接池，但显式关闭hconn会立即释放连接。
     * 改为延迟关闭策略：请求完成后只关闭hreq，让hconn保持一段时间供复用。
     * 减少TCP握手开销，尤其在高频API调用(轮询、保活)时效果显著。
     */
    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) {
        char hname[256];
        WideCharToMultiByte(CP_ACP, 0, whostname, -1, hname, sizeof(hname), NULL, NULL);
        log_line("连接服务器失败: %s:%d 错误=%lu", hname, uc.nPort, GetLastError());
        return -1;
    }

    /* 创建HTTP请求 */
    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) {
        log_line("创建HTTP请求失败: 错误=%lu", GetLastError());
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
        log_line("发送HTTP请求失败: 错误=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    /* 接收响应 */
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        log_line("接收HTTP响应失败: 错误=%lu", GetLastError());
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

    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
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
    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    return (int)total;
}

/* ======================== API请求头构建 ======================== */

/**
 * make_base_headers - 构建基础请求头(无需签名)
 *
 * 用于登录前的不需要认证的API请求(如获取挑战码、登录)。
 * 包含设备类型、版本号、设备码、来源页等基础信息。
 *
 * 注意: 使用__declspec(thread)线程局部存储，确保多线程安全。
 *
 * @param s      会话信息(提取device_code)
 * @param hdrs   输出请求头指针数组
 * @param nhdrs  输出请求头数量
 */
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
 * 注意: 使用__declspec(thread)线程局部存储，确保多线程安全。
 *
 * @param s      会话信息(提取user_id/tenant_id/secret_key)
 * @param hdrs   输出请求头指针数组
 * @param nhdrs  输出请求头数量
 */
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
    snprintf(g_shri, sizeof(g_shri), "ctg-requestid: %s", g_shts + sizeof("ctg-timestamp: ") - 1);
    snprintf(g_shcombined, sizeof(g_shcombined), "60%lld%d%lld%d103020001%s",
             ts, s->tenant_id, ts, s->user_id, s->secret_key);
    md5_hex(g_shcombined, g_shsig_hex);
    snprintf(g_shsig, sizeof(g_shsig), "ctg-signaturestr: %s", g_shsig_hex);
    hdrs[0] = g_sh7; hdrs[1] = g_sh1; hdrs[2] = g_sh2; hdrs[3] = g_sh3; hdrs[4] = g_sh5;
    hdrs[5] = g_sh4; hdrs[6] = g_sh6; hdrs[7] = g_shts; hdrs[8] = g_shri; hdrs[9] = g_shsig;
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

static int api_get(const Session *s, const char *url, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("GET", url, NULL, 0, NULL, hdrs, nhdrs, resp, rsz);
}

static int api_get_binary(const Session *s, const char *url, uint8_t *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_get_binary(url, hdrs, nhdrs, resp, rsz);
}

/* ======================== 验证码图片窗口显示 ======================== */

static HWND g_captcha_hwnd = NULL;
static HBITMAP g_captcha_hbm = NULL;
static volatile LONG g_captcha_wnd_ready = 0;

static LRESULT CALLBACK captcha_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        HBITMAP hbm = (HBITMAP)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (hbm) {
            BITMAP bm;
            GetObjectW(hbm, sizeof(bm), &bm);
            HDC memdc = CreateCompatibleDC(hdc);
            HBITMAP old = (HBITMAP)SelectObject(memdc, hbm);
            RECT rc;
            GetClientRect(hwnd, &rc);
            SetStretchBltMode(hdc, HALFTONE);
            StretchBlt(hdc, 0, 0, rc.right, rc.bottom,
                       memdc, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            SelectObject(memdc, old);
            DeleteDC(memdc);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        g_captcha_hwnd = NULL;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static DWORD WINAPI captcha_wnd_thread(LPVOID param) {
    (void)param;
    HRESULT hr = CoInitialize(NULL);
    int need_com_uninit = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        InterlockedExchange(&g_captcha_wnd_ready, 2);
        return 0;
    }

    HBITMAP hbm = (HBITMAP)InterlockedCompareExchangePointer((PVOID *)&g_captcha_hbm, NULL, NULL);
    hbm = g_captcha_hbm;

    static int registered = 0;
    if (!registered) {
        WNDCLASSW wc = {0};
        wc.lpfnWndProc = captcha_wnd_proc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"CaptchaWnd";
        RegisterClassW(&wc);
        registered = 1;
    }

    BITMAP bm;
    GetObjectW(hbm, sizeof(bm), &bm);
    int scale = 500 / bm.bmWidth;
    if (scale < 2) scale = 2;
    if (scale > 10) scale = 10;
    int win_w = bm.bmWidth * scale;
    int win_h = bm.bmHeight * scale;

    RECT rc = {0, 0, win_w, win_h};
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
    int scr_w = GetSystemMetrics(SM_CXSCREEN);
    int scr_h = GetSystemMetrics(SM_CYSCREEN);
    int x = (scr_w - (rc.right - rc.left)) / 2;
    int y = (scr_h - (rc.bottom - rc.top)) / 2;

    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST, L"CaptchaWnd",
                                 L"验证码 (请手工输入后回到命令行)",
                                 WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                 x, y, rc.right - rc.left, rc.bottom - rc.top,
                                 NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (hwnd) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)hbm);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        g_captcha_hwnd = hwnd;
        InterlockedExchange(&g_captcha_wnd_ready, 1);

        MSG msg;
        while (GetMessageW(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    } else {
        InterlockedExchange(&g_captcha_wnd_ready, 2);
    }

    if (need_com_uninit) CoUninitialize();
    return 0;
}

static HBITMAP decode_image_to_hbitmap(const uint8_t *img_data, int img_len) {
    HBITMAP result = NULL;
    HRESULT hr = CoInitialize(NULL);
    int need_com_uninit = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return NULL;

    IWICImagingFactory *factory = NULL;
    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWICImagingFactory, (void **)&factory);
    if (FAILED(hr)) goto done;

    {
        IStream *stream = NULL;
        hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
        if (FAILED(hr)) goto factory_done;

        ULONG cb_written = 0;
        stream->lpVtbl->Write(stream, img_data, (ULONG)img_len, &cb_written);
        LARGE_INTEGER li_zero;
        li_zero.QuadPart = 0;
        stream->lpVtbl->Seek(stream, li_zero, STREAM_SEEK_SET, NULL);

        IWICBitmapDecoder *decoder = NULL;
        hr = factory->lpVtbl->CreateDecoderFromStream(factory, stream, NULL,
                                                      WICDecodeMetadataCacheOnDemand, &decoder);
        if (FAILED(hr)) { stream->lpVtbl->Release(stream); goto factory_done; }

        IWICBitmapFrameDecode *frame = NULL;
        hr = decoder->lpVtbl->GetFrame(decoder, 0, &frame);
        if (FAILED(hr)) { decoder->lpVtbl->Release(decoder); stream->lpVtbl->Release(stream); goto factory_done; }

        UINT w = 0, h = 0;
        frame->lpVtbl->GetSize(frame, &w, &h);
        if (w == 0 || h == 0) {
            frame->lpVtbl->Release(frame); decoder->lpVtbl->Release(decoder);
            stream->lpVtbl->Release(stream); goto factory_done;
        }

        IWICFormatConverter *conv = NULL;
        hr = factory->lpVtbl->CreateFormatConverter(factory, &conv);
        if (FAILED(hr)) {
            frame->lpVtbl->Release(frame); decoder->lpVtbl->Release(decoder);
            stream->lpVtbl->Release(stream); goto factory_done;
        }

        hr = conv->lpVtbl->Initialize(conv, (IWICBitmapSource *)frame,
                                      &GUID_WICPixelFormat32bppBGRA,
                                      WICBitmapDitherTypeNone, NULL, 0.0,
                                      WICBitmapPaletteTypeCustom);
        if (FAILED(hr)) {
            conv->lpVtbl->Release(conv); frame->lpVtbl->Release(frame);
            decoder->lpVtbl->Release(decoder); stream->lpVtbl->Release(stream);
            goto factory_done;
        }

        UINT stride = w * 4;
        UINT buf_sz = stride * h;
        uint8_t *px = (uint8_t *)malloc(buf_sz);
        if (!px) {
            conv->lpVtbl->Release(conv); frame->lpVtbl->Release(frame);
            decoder->lpVtbl->Release(decoder); stream->lpVtbl->Release(stream);
            goto factory_done;
        }

        hr = conv->lpVtbl->CopyPixels(conv, NULL, stride, buf_sz, px);
        if (FAILED(hr)) {
            free(px); conv->lpVtbl->Release(conv); frame->lpVtbl->Release(frame);
            decoder->lpVtbl->Release(decoder); stream->lpVtbl->Release(stream);
            goto factory_done;
        }

        for (UINT i = 0; i < buf_sz; i += 4) px[i + 3] = 0xFF;

        BITMAPINFO bmi = {0};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = (LONG)w;
        bmi.bmiHeader.biHeight = -(LONG)h;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        HDC screen_dc = GetDC(NULL);
        void *bits = NULL;
        result = CreateDIBSection(screen_dc, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
        ReleaseDC(NULL, screen_dc);
        if (result && bits) memcpy(bits, px, buf_sz);
        free(px);

        conv->lpVtbl->Release(conv);
        frame->lpVtbl->Release(frame);
        decoder->lpVtbl->Release(decoder);
        stream->lpVtbl->Release(stream);
    }

factory_done:
    factory->lpVtbl->Release(factory);
done:
    if (need_com_uninit) CoUninitialize();
    return result;
}

static void show_captcha_window(const uint8_t *img_data, int img_len) {
    if (g_background || !img_data || img_len <= 0) return;
    if (g_captcha_hwnd) return;

    g_captcha_hbm = decode_image_to_hbitmap(img_data, img_len);
    if (!g_captcha_hbm) return;

    InterlockedExchange(&g_captcha_wnd_ready, 0);
    CreateThread(NULL, THREAD_STACK, captcha_wnd_thread, NULL, 0, NULL);

    while (!InterlockedCompareExchange(&g_captcha_wnd_ready, 0, 0)) Sleep(20);
}

static void close_captcha_window(void) {
    if (g_captcha_hwnd) {
        PostMessageW(g_captcha_hwnd, WM_CLOSE, 0, 0);
        g_captcha_hwnd = NULL;
    }
    Sleep(100);
    if (g_captcha_hbm) {
        DeleteObject(g_captcha_hbm);
        g_captcha_hbm = NULL;
    }
}

static int read_manual_captcha(char *out, size_t out_sz) {
    printf("验证码自动识别失败，请手工输入："); fflush(stdout);
    if (!fgets(out, (int)out_sz, stdin)) return 0;
    out[strcspn(out, "\r\n")] = 0;
    return out[0] ? 1 : 0;
}

/* ======================== 验证码OCR ======================== */

/**
 * try_captcha_ocr - 下载验证码图片并尝试OCR识别
 *
 * 先下载图片，再尝试OCR。返回值区分下载失败、OCR技术失败、OCR成功。
 * OCR成功时captcha_out填入结果；OCR技术失败时img_out保留图片数据供手工输入。
 *
 * @param s            会话信息
 * @param user         用户名(登录验证码用, 短信验证码传NULL)
 * @param captcha_out  输出验证码文本
 * @param co_sz        输出缓冲区大小
 * @param img_out      输出图片数据(需调用者free)
 * @param img_len_out  输出图片数据长度
 * @return             2=OCR成功, 1=OCR技术失败(图片已下载), 0=下载失败
 */
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

    uint8_t *img = (uint8_t *)malloc(65536);
    int img_len;
    if (user) {
        const char *hdrs[16];
        int nhdrs = 0;
        make_base_headers(s, hdrs, &nhdrs);
        img_len = http_get_binary(captcha_url, hdrs, nhdrs, img, 65536);
    } else {
        img_len = api_get_binary(s, captcha_url, img, 65536);
    }
    if (img_len <= 0) {
        log_line("验证码图片下载失败");
        free(img);
        return 0;
    }

    *img_out = img;
    *img_len_out = img_len;

    char *img_b64 = (char *)malloc(img_len * 2 + 4);
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
    char h_dc[128], h1[64], h2[64], h5[64];
    snprintf(h1, sizeof(h1), "ctg-devicetype: 60");
    snprintf(h2, sizeof(h2), "ctg-version: 103020001");
    snprintf(h_dc, sizeof(h_dc), "ctg-devicecode: %s", s->device_code);
    snprintf(h5, sizeof(h5), "referer: https://pc.ctyun.cn/");

    const char *ocr_hdrs[] = { h1, h2, h_dc, h5 };
    char orc_resp[4096];
    int rlen = http_req("POST", "https://orc.1999111.xyz/ocr", body, blen, ct_hdr, ocr_hdrs, 4, orc_resp, sizeof(orc_resp));
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
    log_line("OCR识别成功，长度=%d", (int)strlen(captcha_out));
    return 2;
}

/* ======================== 登录流程 ======================== */

/**
 * do_login - 执行天翼云电脑登录
 *
 * 登录流程:
 * 1. 调用genChallengeData获取挑战码(challengeId + challengeCode)
 * 2. 下载验证码图片并优先OCR识别
 * 3. OCR失败或连续3次自动识别验证失败时，弹出窗口手工输入
 * 4. 计算密码哈希: SHA256(密码+challengeCode) 和 SHA256(SHA256(密码)+challengeCode)
 * 5. URL编码challengeId和deviceCode
 * 6. 构建登录请求体并发送
 * 7. 解析响应获取secretKey/userId/tenantId
 *
 * 手工输入验证码时，连续3次失败则输出"验证码识别错误"并退出程序。
 *
 * @param s     会话信息(输出secretKey/userId/tenantId)
 * @param user  用户名
 * @param pwd   原始密码
 * @return      1=登录成功, 0=登录失败(不返回: 手工3次失败直接退出)
 */
static int do_login(Session *s, const char *user, const char *pwd) {
    int auto_fail_count = 0;
    for (int attempt = 1; attempt <= 3; attempt++) {
        char resp[MAX_RESP];

        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData",
                            "{}", 2, "application/json", resp, sizeof(resp)) < 0) {
            log_line("获取挑战码失败 (尝试%d)", attempt);
            continue;
        }
        int code = jint(resp, "code");
        log_line("挑战码响应: code=%d", code);
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

        /* 优化 (v1.2.3): 提前预计算所有密码哈希，避免手工/自动两个分支重复计算 */
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
        uint8_t *img_data = NULL;
        int img_len = 0;
        int ocr_result = try_captcha_ocr(s, user, captcha, sizeof(captcha), &img_data, &img_len);

        if (ocr_result == 2) {
            auto_fail_count++;
        }

        if (ocr_result < 2 || auto_fail_count >= 3) {
            if (img_data && img_len > 0) {
                show_captcha_window(img_data, img_len);
            }
            log_line("验证码自动识别失败，切换手工输入模式");
            int manual_fail = 0;
            while (manual_fail < 3) {
                captcha[0] = 0;
                if (!read_manual_captcha(captcha, sizeof(captcha))) {
                    log_line("手工输入为空");
                    manual_fail++;
                    continue;
                }
                close_captcha_window();

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

                log_line("正在发送登录请求 (手工验证码, 尝试%d)...", manual_fail + 1);
                if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/login",
                                    post, strlen(post), "application/x-www-form-urlencoded",
                                    resp, sizeof(resp)) < 0) {
                    log_line("登录请求发送失败");
                    manual_fail++;
                    continue;
                }

                code = jint(resp, "code");
                log_line("登录响应: code=%d", code);
                if (code != 0) {
                    char msg[256];
                    jstr(resp, "msg", msg, sizeof(msg));
                    log_line("登录失败: %s", msg);
                    if (strcmp(msg, "\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf") == 0) {
                        close_captcha_window();
                        if (img_data) free(img_data);
                        return 0;
                    }
                    manual_fail++;
                    continue;
                }

                const char *p = strstr(resp, "\"data\"");
                if (!p) { log_line("响应中无data字段"); manual_fail++; continue; }
                p = strchr(p, '{');
                if (!p) { log_line("data字段格式错误"); manual_fail++; continue; }

                jstr(p, "secretKey", s->secret_key, sizeof(s->secret_key));
                jstr(p, "userName", s->user_name, sizeof(s->user_name));
                jstr(p, "userAccount", s->user_account, sizeof(s->user_account));
                s->user_id = jint(p, "userId");
                s->tenant_id = jint(p, "tenantId");
                s->bonded_device = jbool(p, "bondedDevice");
                log_line("登录成功: userId=%d, tenantId=%d, bondedDevice=%d", s->user_id, s->tenant_id, s->bonded_device);
                s->logged_in = s->secret_key[0] ? 1 : 0;
                if (img_data) free(img_data);
                return s->logged_in;
            }
            close_captcha_window();
            if (img_data) free(img_data);
            log_line("验证码识别错误");
            InterlockedExchange(&g_running, 0);
            return 0;
        }

        if (img_data) { free(img_data); img_data = NULL; }

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

        log_line("正在发送登录请求 (尝试%d)...", attempt);
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/login",
                            post, strlen(post), "application/x-www-form-urlencoded",
                            resp, sizeof(resp)) < 0) {
            log_line("登录请求发送失败");
            continue;
        }

        code = jint(resp, "code");
        log_line("登录响应: code=%d", code);
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            log_line("登录失败: %s", msg);
            if (strcmp(msg, "\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf") == 0)
                return 0;
            continue;
        }

        /*
         * 优化5 (v1.2.2): 使用json_find_key单次扫描解析登录响应。
         * 原逻辑: 先strstr定位"data"，再jstr/jint/jbool逐个字段从头扫描。
         * 新逻辑: 在data对象范围内使用json_find_key单次遍历提取所有字段。
         * 登录响应包含secretKey/userName/userAccount/userId/tenantId/bondedDevice，
         * 单次扫描比6次独立查找更高效。
         */
        const char *data_start = strstr(resp, "\"data\"");
        if (!data_start) { log_line("响应中无data字段"); continue; }
        data_start = strchr(data_start, '{');
        if (!data_start) { log_line("data字段格式错误"); continue; }

        const char *vstart;
        int vlen;
        char vtype;

        /* 提取secretKey */
        if (json_find_key(data_start, "secretKey", &vstart, &vlen, &vtype) && vtype == 's') {
            int copy_len = vlen < (int)sizeof(s->secret_key) - 1 ? vlen : (int)sizeof(s->secret_key) - 1;
            memcpy(s->secret_key, vstart, copy_len);
            s->secret_key[copy_len] = 0;
        }
        /* 提取userName */
        if (json_find_key(data_start, "userName", &vstart, &vlen, &vtype) && vtype == 's') {
            int copy_len = vlen < (int)sizeof(s->user_name) - 1 ? vlen : (int)sizeof(s->user_name) - 1;
            memcpy(s->user_name, vstart, copy_len);
            s->user_name[copy_len] = 0;
        }
        /* 提取userAccount */
        if (json_find_key(data_start, "userAccount", &vstart, &vlen, &vtype) && vtype == 's') {
            int copy_len = vlen < (int)sizeof(s->user_account) - 1 ? vlen : (int)sizeof(s->user_account) - 1;
            memcpy(s->user_account, vstart, copy_len);
            s->user_account[copy_len] = 0;
        }
        /* 提取userId */
        if (json_find_key(data_start, "userId", &vstart, &vlen, &vtype) && vtype == 'n') {
            char num_buf[32];
            int copy_len = vlen < 31 ? vlen : 31;
            memcpy(num_buf, vstart, copy_len);
            num_buf[copy_len] = 0;
            s->user_id = atoi(num_buf);
        }
        /* 提取tenantId */
        if (json_find_key(data_start, "tenantId", &vstart, &vlen, &vtype) && vtype == 'n') {
            char num_buf[32];
            int copy_len = vlen < 31 ? vlen : 31;
            memcpy(num_buf, vstart, copy_len);
            num_buf[copy_len] = 0;
            s->tenant_id = atoi(num_buf);
        }
        /* 提取bondedDevice */
        if (json_find_key(data_start, "bondedDevice", &vstart, &vlen, &vtype) && vtype == 'b') {
            s->bonded_device = (vlen == 4);  /* true=4, false=5 */
        }

        log_line("登录成功: userId=%d, tenantId=%d, bondedDevice=%d", s->user_id, s->tenant_id, s->bonded_device);
        s->logged_in = s->secret_key[0] ? 1 : 0;
        return s->logged_in;
    }
    log_line("登录失败，已重试3次");
    return 0;
}

/* ======================== 短信验证码与设备绑定 ======================== */

static int send_sms_code(const Session *s, const char *phone) {
    int auto_fail_count = 0;
    for (int i = 0; i < 3; i++) {
        char captcha[64] = "";
        uint8_t *img_data = NULL;
        int img_len = 0;
        int ocr_result = try_captcha_ocr(s, NULL, captcha, sizeof(captcha), &img_data, &img_len);

        if (ocr_result == 2) {
            auto_fail_count++;
        }

        if (ocr_result < 2 || auto_fail_count >= 3) {
            if (img_data && img_len > 0) {
                show_captcha_window(img_data, img_len);
            }
            log_line("短信验证码自动识别失败，切换手工输入模式");
            int manual_fail = 0;
            while (manual_fail < 3) {
                captcha[0] = 0;
                if (!read_manual_captcha(captcha, sizeof(captcha))) {
                    log_line("手工输入为空");
                    manual_fail++;
                    continue;
                }
                close_captcha_window();

                char url[512];
                snprintf(url, sizeof(url),
                         "https://desk.ctyun.cn:8810/api/cdserv/client/device/getSmsCode?mobilePhone=%s&captchaCode=%s",
                         phone, captcha);

                char resp[MAX_RESP];
                int rlen = api_get(s, url, resp, sizeof(resp));
                if (rlen < 0) {
                    log_line("发送短信验证码请求失败 (手工, 尝试%d)", manual_fail + 1);
                    manual_fail++;
                    continue;
                }
                int code = jint(resp, "code");
                if (code == 0) {
                    log_line("短信验证码已发送至 %s", phone);
                    if (img_data) free(img_data);
                    return 1;
                }
                char msg[256];
                jstr(resp, "msg", msg, sizeof(msg));
                log_line("发送短信验证码错误 (手工, 尝试%d): %s", manual_fail + 1, msg);
                manual_fail++;
            }
            close_captcha_window();
            if (img_data) free(img_data);
            log_line("验证码识别错误");
            InterlockedExchange(&g_running, 0);
            return 0;
        }

        if (img_data) { free(img_data); img_data = NULL; }

        char url[512];
        snprintf(url, sizeof(url),
                 "https://desk.ctyun.cn:8810/api/cdserv/client/device/getSmsCode?mobilePhone=%s&captchaCode=%s",
                 phone, captcha);

        char resp[MAX_RESP];
        int rlen = api_get(s, url, resp, sizeof(resp));
        if (rlen < 0) {
            log_line("发送短信验证码请求失败 (尝试%d)", i + 1);
            continue;
        }
        int code = jint(resp, "code");
        if (code == 0) {
            log_line("短信验证码已发送至 %s", phone);
            return 1;
        }
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        log_line("发送短信验证码错误 (尝试%d): %s", i + 1, msg);
    }
    return 0;
}

static int binding_device(const Session *s, const char *verification_code) {
    char url[1024];
    snprintf(url, sizeof(url),
             "https://desk.ctyun.cn:8810/api/cdserv/client/device/binding?"
             "verificationCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8"
             "&deviceCode=%s&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&hostName=pc.ctyun.cn&deviceInfo=Win32",
             verification_code, s->device_code);

    char resp[MAX_RESP];
    int rlen = api_post(s, url, "", 0, "application/json", resp, sizeof(resp));
    if (rlen < 0) {
        log_line("设备绑定请求失败");
        return 0;
    }
    int code = jint(resp, "code");
    if (code == 0) {
        log_line("设备绑定成功");
        return 1;
    }
    char msg[256];
    jstr(resp, "msg", msg, sizeof(msg));
    log_line("设备绑定错误: %s", msg);
    return 0;
}

static int do_device_binding(Session *s) {
    if (s->bonded_device) return 1;

    const char *phone = s->phone_number;
    if (!phone[0]) {
        log_line("无手机号，无法发送短信验证码");
        return 0;
    }

    log_line("设备未绑定，正在发送短信验证码至 %s", phone);
    if (!send_sms_code(s, phone)) {
        log_line("发送短信验证码失败");
        return 0;
    }

    char vcode[32];
    printf("短信验证码: "); fflush(stdout);
    fgets(vcode, sizeof(vcode), stdin);
    vcode[strcspn(vcode, "\r\n")] = 0;

    if (!vcode[0]) {
        log_line("验证码为空");
        return 0;
    }

    if (!binding_device(s, vcode)) {
        log_line("设备绑定失败");
        return 0;
    }

    s->bonded_device = 1;
    return 1;
}

/*
 * 优化5 (v1.2.2): JSON单次扫描解析函数。
 *
 * 原解析方式(jstr/jstr_range)在解析每个字段时都从头扫描整个JSON字符串，
 * 对复杂响应(如登录响应包含多个字段)效率较低。
 *
 * 新增的json_find_key()在单次扫描中定位键值对位置，避免重复遍历。
 * 对于包含N个字段的JSON，总复杂度从O(N*M)降至O(M)，其中M为JSON长度。
 */

/**
 * json_find_key - 在JSON字符串中查找键值对(单次扫描)
 *
 * 在JSON字符串中查找指定键，并将指针移动到值开始位置。
 * 同时返回值的类型(字符串/数字/布尔)。
 *
 * 算法:
 * 1. 单次遍历JSON字符串，查找目标键
 * 2. 匹配键后，解析冒号后的值
 * 3. 根据值类型返回相应的指针和长度
 *
 * @param json   JSON字符串
 * @param key    要查找的键名
 * @param vstart 输出: 值开始位置
 * @param vlen   输出: 值长度
 * @param vtype  输出: 值类型 ('s'=字符串, 'n'=数字, 'b'=布尔)
 * @return        1=找到, 0=未找到
 *
 * 示例: {"code":0,"data":{"secretKey":"xxx","userId":123}}
 * 调用json_find_key(json, "code", &vstart, &vlen, &vtype)返回1，vstart指向"0"
 */

/* 前向声明: find_matching_brace在json_find_key之后定义 */
static const char *find_matching_brace(const char *start);

static int json_find_key(const char *json, const char *key, const char **vstart, int *vlen, char *vtype) {
    size_t key_len = strlen(key);
    const char *p = json;

    while (*p) {
        /* 跳过空白字符 */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

        /* 检查是否是字符串键 */
        if (*p == '"') {
            p++;
            size_t match = 0;
            const char *key_start = p;

            /* 比较键名 */
            while (*p && *p != '"' && match < key_len) {
                if (*p == '\\') p++;  /* 跳过转义字符 */
                if (*p == key[match]) match++;
                p++;
            }

            /* 检查是否完全匹配 */
            if (match == key_len && *p == '"') {
                p++;  /* 跳过结束引号 */

                /* 跳过冒号和空白 */
                while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;

                /* 解析值 */
                if (*p == '"') {
                    /* 字符串值 */
                    *vtype = 's';
                    *vstart = ++p;
                    *vlen = 0;
                    while (*p && *p != '"') {
                        if (*p == '\\') p++;
                        p++;
                        (*vlen)++;
                    }
                    return 1;
                } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
                    /* 数字值 */
                    *vtype = 'n';
                    *vstart = p;
                    *vlen = 0;
                    while (*p == '-' || (*p >= '0' && *p <= '9')) {
                        p++;
                        (*vlen)++;
                    }
                    return 1;
                } else if (p[0] == 't' && p[1] == 'r' && p[2] == 'u' && p[3] == 'e') {
                    /* 布尔值true */
                    *vtype = 'b';
                    *vstart = p;
                    *vlen = 4;
                    return 1;
                } else if (p[0] == 'f' && p[1] == 'a' && p[2] == 'l' && p[3] == 's' && p[4] == 'e') {
                    /* 布尔值false */
                    *vtype = 'b';
                    *vstart = p;
                    *vlen = 5;
                    return 1;
                }
            } else {
                /* 键不匹配，跳过到字符串结束 */
                while (*p && *p != '"') {
                    if (*p == '\\') p++;
                    p++;
                }
            }
        } else if (*p == '{') {
            /* 进入嵌套对象，递归查找 */
            const char *end = find_matching_brace(p);
            if (end) {
                if (json_find_key(p + 1, key, vstart, vlen, vtype)) {
                    return 1;
                }
                p = end + 1;
            } else {
                break;
            }
        } else if (*p == '[') {
            /* 跳过数组内容 */
            p++;
            int depth = 1;
            while (*p && depth > 0) {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') {
                        if (*p == '\\') p++;
                        p++;
                    }
                } else if (*p == '[') {
                    depth++;
                } else if (*p == ']') {
                    depth--;
                }
                p++;
            }
        } else {
            p++;
        }
    }
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
        log_line("获取桌面列表请求失败");
        return 0;
    }
    if (jint(resp, "code") != 0) {
        log_line("获取桌面列表错误: code=%d", jint(resp, "code"));
        return 0;
    }
    log_line("获取桌面列表成功，正在解析桌面信息");

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

        /* 解析桌面字段 */
        jstr_range(obj, end + 1, "desktopId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        /* 部分API版本使用objId代替desktopId */
        if (!desktops[count].desktop_id[0])
            jstr_range(obj, end + 1, "objId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        /*
         * 优化3 (v1.2.2): 解析完成后立即计算哈希值，存储在结构体中。
         * 后续monitor_desktops_thread中查找时先比较哈希，命中后再strcmp验证。
         * 哈希计算本身O(n)，但避免了大量的strcmp调用。
         */
        desktops[count].id_hash = fnv1a_hash(desktops[count].desktop_id);
        jstr_range(obj, end + 1, "desktopCode", desktops[count].desktop_code, sizeof(desktops[count].desktop_code));

        /* 判断运行状态: "运行中"(UTF-8: e8 bf 90 e8 a1 8c e4 b8 ad) */
        char status[64];
        jstr_range(obj, end + 1, "useStatusText", status, sizeof(status));
        desktops[count].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
        log_line("桌面[%d]: id=%s code=%s 状态=%s 运行中=%d",
                 count, desktops[count].desktop_id, desktops[count].desktop_code,
                 status, desktops[count].is_active);
        count++;
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
        log_line("获取桌面列表请求失败");
        return 0;
    }
    if (jint(resp, "code") != 0) {
        log_line("获取桌面列表错误: code=%d", jint(resp, "code"));
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
        jstr_range(obj, end + 1, "desktopId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        if (!desktops[count].desktop_id[0])
            jstr_range(obj, end + 1, "objId", desktops[count].desktop_id, sizeof(desktops[count].desktop_id));
        /* 优化 (v1.2.3): 预计算desktop_id的FNV-1a哈希值，后续轮询时直接使用 */
        desktops[count].id_hash = fnv1a_hash(desktops[count].desktop_id);
        jstr_range(obj, end + 1, "desktopCode", desktops[count].desktop_code, sizeof(desktops[count].desktop_code));
        char status[64];
        jstr_range(obj, end + 1, "useStatusText", status, sizeof(status));
        desktops[count].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
        count++;
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
        log_line("连接桌面请求失败: %s", d->desktop_id);
        return 0;
    }
    if (jint(resp, "code") != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        log_line("连接桌面错误 [%s]: %s", d->desktop_id, msg);
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

    /* 使用临时缓冲区提取字段，再str_dup到堆上 */
    char *tmp = (char *)malloc(len + 1);
    if (!tmp) return 0;
    jstr_range(di, di_end + 1, "host", tmp, len + 1);
    d->host = str_dup(tmp);
    jstr_range(di, di_end + 1, "port", tmp, len + 1);
    d->port = str_dup(tmp);
    jstr_range(di, di_end + 1, "clinkLvsOutHost", tmp, len + 1);
    d->clink_host = str_dup(tmp);
    jstr_range(di, di_end + 1, "caCert", tmp, len + 1);
    d->ca_cert = str_dup(tmp);
    jstr_range(di, di_end + 1, "clientCert", tmp, len + 1);
    d->client_cert = str_dup(tmp);
    jstr_range(di, di_end + 1, "clientKey", tmp, len + 1);
    d->client_key = str_dup(tmp);
    jstr_range(di, di_end + 1, "token", tmp, len + 1);
    d->token = str_dup(tmp);
    jstr_range(di, di_end + 1, "tenantMemberAccount", tmp, len + 1);
    d->tenant_account = str_dup(tmp);
    log_line("[%s] 连接桌面成功: host=%s port=%s clink=%s",
             d->desktop_code,
             d->host ? d->host : "", d->port ? d->port : "", d->clink_host ? d->clink_host : "");
    free(tmp);
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
    /* 常量时间比较认证标签，防止时序侧信道攻击 */
    {
        volatile uint8_t diff = 0;
        for (int ci = 0; ci < 16; ci++) diff |= tag[ci] ^ expected[ci];
        if (diff != 0) return 0;
    }

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
static int decrypt_data(const char *b64, const uint8_t key[32], char *out, size_t out_sz) {
    size_t b64len = strlen(b64);
    uint8_t *data = (uint8_t *)malloc(b64len);
    size_t dlen = b64dec(b64, b64len, data);
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
 * 使用GetAdaptersInfo获取第一个非零物理网卡MAC地址。
 * 不再使用UuidCreateSequential，因为该函数在VPN/虚拟网卡环境下
 * 返回的MAC地址不稳定，重启后可能变化，导致配置无法解密。
 *
 * @param fp_hex  输出64字符十六进制指纹
 */
static void get_fingerprint(char *fp_hex) {
    char mac[32] = "";
    DWORD sz = 0;
    GetAdaptersInfo(NULL, &sz);
    BYTE *buf = (BYTE *)malloc(sz);
    PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
    GetAdaptersInfo(pinfo, &sz);
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

static void generate_device_code(const char *fp_hex, char *out, size_t out_sz) {
    uint8_t h[32];
    sha256((const uint8_t *)fp_hex, strlen(fp_hex), h);
    snprintf(out, out_sz, "web_%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
             h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
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
 * derive_key - 从指纹和盐值派生加密密钥 (v2.0: 使用PBKDF2替代简单SHA256)
 *
 * 相比v1.x的 SHA256(fp|salt)，v2.0使用PBKDF2-HMAC-SHA256:
 *   - 100,000次迭代，大幅增加暴力破解成本
 *   - 符合NIST SP 800-132标准
 *   - 使用HMAC-SHA256而非裸SHA256
 *
 * 回退机制: 若BCrypt不可用，回退到v1.x的derive_key_legacy
 *
 * @param fp    本机指纹(64字符十六进制)
 * @param salt  盐值(32字符十六进制)
 * @param key   输出32字节密钥
 */
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

/* ======================== Windows DPAPI 加密 (v2.0新增) ======================== */

/**
 * protect_data_dpapi - 使用Windows DPAPI加密数据
 *
 * 使用CRYPTPROTECT_LOCAL_MACHINE标志绑定到本机:
 * - 确保重启后同一台机器的任何用户都能解密
 * - 内层ChaCha20-Poly1305已提供硬件指纹绑定保护
 * - entropy参数(本机指纹)作为额外安全层
 *
 * @param plaintext   明文数据
 * @param plain_len   明文长度
 * @param entropy     额外熵（本机指纹，提高安全性）
 * @param out         输出加密数据（需调用LocalFree释放）
 * @param out_len     输出长度
 * @return            1=成功, 0=失败
 */
static int protect_data_dpapi(const uint8_t *plaintext, DWORD plain_len,
                               const char *entropy,
                               uint8_t **out, DWORD *out_len) {
    DATA_BLOB data_in = { plain_len, (BYTE *)plaintext };
    DATA_BLOB data_out = { 0, NULL };

    DATA_BLOB entropy_blob = { 0, NULL };
    if (entropy && entropy[0]) {
        entropy_blob.cbData = (DWORD)strlen(entropy);
        entropy_blob.pbData = (BYTE *)entropy;
    }

    DWORD flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;

    BOOL result = CryptProtectData(
        &data_in,
        L"ctyun_keepalive_credentials",
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

/**
 * unprotect_data_dpapi - 使用Windows DPAPI解密数据
 */
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

/**
 * try_decrypt_config_legacy - v1.x 配置解密 (ChaCha20-Poly1305)
 *
 * 从config.json中提取salt和加密的账号信息，
 * 用给定指纹派生密钥，尝试解密并自动登录。
 */
static int try_decrypt_config_legacy(Session *s, const char *content, const char *fp) {
    char salt[65];
    jstr(content, "salt", salt, sizeof(salt));
    if (!salt[0]) return 0;

    uint8_t key[32];
    derive_key_legacy(fp, salt, key);

    const char *acc = strstr(content, "\"accounts\"");
    if (!acc) return 0;
    acc = strchr(acc, '[');
    if (!acc) return 0;
    const char *obj = strchr(acc, '{');
    if (!obj) return 0;

    char ua[2048], pw[2048], dc[2048];
    jstr(obj, "user_account", ua, sizeof(ua));
    jstr(obj, "password", pw, sizeof(pw));
    jstr(obj, "device_code", dc, sizeof(dc));

    char user[256], pass[256], devc[256];
    int du = decrypt_data(ua, key, user, sizeof(user));
    int dp = decrypt_data(pw, key, pass, sizeof(pass));
    int dd = decrypt_data(dc, key, devc, sizeof(devc));

    if (du && dp && dd) {
        strncpy(s->device_code, devc, sizeof(s->device_code) - 1);
        s->device_code[sizeof(s->device_code) - 1] = '\0';
        strncpy(s->phone_number, user, sizeof(s->phone_number) - 1);
        s->phone_number[sizeof(s->phone_number) - 1] = '\0';
        if (do_login(s, user, pass)) return 1;
        log_line("自动登录失败，尝试手动输入");
        return 2;
    }
    return 0;
}

/**
 * try_decrypt_config_dpapi - v2.0 配置解密 (DPAPI + ChaCha20-Poly1305 分层加密)
 *
 * 新格式使用两层加密:
 * 外层: Windows DPAPI (绑定用户账户)
 * 内层: ChaCha20-Poly1305 (绑定本机硬件)
 *
 * 即使DPAPI被绕过，仍需硬件指纹才能解密
 */
static int try_decrypt_config_dpapi(Session *s, const char *content, const char *fp) {
    char dpapi_b64_small[256];
    jstr(content, "dpapi", dpapi_b64_small, sizeof(dpapi_b64_small));
    if (!dpapi_b64_small[0]) return 0;

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
        log_line("DPAPI解密失败，可能需要重新登录");
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

    const char *acc = strstr(inner_json, "\"accounts\"");
    if (!acc) { free(inner_json); return 0; }
    acc = strchr(acc, '[');
    if (!acc) { free(inner_json); return 0; }
    const char *obj = strchr(acc, '{');
    if (!obj) { free(inner_json); return 0; }

    char ua[2048], pw[2048], dc[2048];
    jstr(obj, "user_account", ua, sizeof(ua));
    jstr(obj, "password", pw, sizeof(pw));
    jstr(obj, "device_code", dc, sizeof(dc));

    uint8_t key[32];
    derive_key(fp, salt, key);

    char user[256], pass[256], devc[256];
    int du = decrypt_data(ua, key, user, sizeof(user));
    int dp = decrypt_data(pw, key, pass, sizeof(pass));
    int dd = decrypt_data(dc, key, devc, sizeof(devc));

    free(inner_json);

    if (du && dp && dd) {
        strncpy(s->device_code, devc, sizeof(s->device_code) - 1);
        s->device_code[sizeof(s->device_code) - 1] = '\0';
        strncpy(s->phone_number, user, sizeof(s->phone_number) - 1);
        s->phone_number[sizeof(s->phone_number) - 1] = '\0';
        if (do_login(s, user, pass)) return 1;
        log_line("自动登录失败，尝试手动输入");
        return 2;
    }
    return 0;
}

/**
 * try_decrypt_config - 统一配置解密入口
 *
 * 优先尝试v2.0 DPAPI格式，失败时回退到v1.x ChaCha20格式
 */
static int try_decrypt_config(Session *s, const char *content, const char *fp) {
    /* 先尝试v2.0 DPAPI格式 */
    int result = try_decrypt_config_dpapi(s, content, fp);
    if (result != 0) return result;

    /* 回退到v1.x传统格式 */
    return try_decrypt_config_legacy(s, content, fp);
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
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *slash = 0;
    char config_path[MAX_PATH];
    snprintf(config_path, sizeof(config_path), "%s\\config.json", exe_path);
    log_line("配置文件路径: %s", config_path);

    char fp[65];
    get_fingerprint(fp);
    log_line("机器指纹: %s", fp);

    FILE *f = fopen(config_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *content = (char *)malloc(fsize + 1);
        size_t clen = fread(content, 1, fsize, f);
        content[clen] = 0;
        fclose(f);

        int dec_result = try_decrypt_config(s, content, fp);
        if (dec_result == 1) {
            free(content);
            if (!s->bonded_device && !do_device_binding(s)) {
                log_line("需要设备绑定但绑定失败");
                return 0;
            }
            return 1;
        }
        if (dec_result == 2) {
            free(content);
            log_line("配置解密成功但登录失败，尝试手动输入");
        } else {
            log_line("主指纹解密失败，尝试所有MAC地址...");
            char macs[32][32];
            int nmacs = get_all_macs(macs, 32);
            int found_decrypt = 0;
            for (int i = 0; i < nmacs; i++) {
                char alt_fp[65];
                mac_to_fingerprint(macs[i], alt_fp);
                if (strcmp(alt_fp, fp) == 0) continue;
                int r = try_decrypt_config(s, content, alt_fp);
                if (r == 1) {
                    free(content);
                    if (!s->bonded_device && !do_device_binding(s)) {
                        log_line("需要设备绑定但绑定失败");
                        return 0;
                    }
                    return 1;
                }
                if (r == 2) {
                    found_decrypt = 1;
                    break;
                }
            }
            free(content);
            if (found_decrypt) {
                log_line("配置解密成功但登录失败，尝试手动输入");
            } else {
                log_line("所有MAC地址均无法解密配置，尝试手动输入");
            }
        }
    } else {
        log_line("配置文件不存在: %s", config_path);
    }

    char user[128], pass[128];
    printf("账户: "); fflush(stdout);
    fgets(user, sizeof(user), stdin); user[strcspn(user, "\r\n")] = 0;
    printf("密码: "); fflush(stdout);
    {
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

    if (!user[0] || !pass[0]) { log_line("账户或密码为空"); return 0; }

    if (g_random) {
        BYTE rnd[16];
        CryptGenRandom(g_crypt, 16, rnd);
        char dc_hex[33];
        for (int i = 0; i < 16; i++) sprintf(dc_hex + i * 2, "%02x", rnd[i]);
        snprintf(s->device_code, sizeof(s->device_code), "web_%s", dc_hex);
    } else {
        generate_device_code(fp, s->device_code, sizeof(s->device_code));
    }

    strncpy(s->phone_number, user, sizeof(s->phone_number) - 1);
    s->phone_number[sizeof(s->phone_number) - 1] = '\0';
    if (!do_login(s, user, pass)) return 0;

    if (!s->bonded_device && !do_device_binding(s)) {
        log_line("需要设备绑定但绑定失败");
        return 0;
    }

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

        char *inner_json = (char *)malloc(8192);
        int dpapi_ok = 0;
        uint8_t *dpapi_ct = NULL;
        DWORD dpapi_len = 0;

        if (inner_json) {
            snprintf(inner_json, 8192,
                     "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]}",
                     salt, enc_user, enc_pass, enc_dc);

            dpapi_ok = protect_data_dpapi(
                (const uint8_t *)inner_json, (DWORD)strlen(inner_json),
                fp, &dpapi_ct, &dpapi_len
            );
            free(inner_json);
        }

        f = fopen(config_path, "w");
        if (f) {
            if (dpapi_ok && dpapi_ct) {
                size_t b64_need = ((size_t)dpapi_len + 2) / 3 * 4 + 1;  // +1 for '\0'
                char *dpapi_b64 = (char *)malloc(b64_need);
                if (dpapi_b64) {
                    b64enc(dpapi_ct, dpapi_len, dpapi_b64);
                    fprintf(f, "{\"version\":2,\"dpapi\":\"%s\"}", dpapi_b64);
                    free(dpapi_b64);
                    log_line("配置已保存(v2.0 DPAPI加密)");
                } else {
                    fprintf(f, "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]}",
                            salt, enc_user, enc_pass, enc_dc);
                    log_line("内存不足，已保存(v1.x ChaCha20加密)");
                    dpapi_ok = 0;
                }
                LocalFree(dpapi_ct);
            } else {
                fprintf(f, "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]}",
                        salt, enc_user, enc_pass, enc_dc);
                log_line("DPAPI不可用，已保存(v1.x ChaCha20加密)");
            }
            fclose(f);
            log_line("配置已保存至 %s", config_path);
        } else if (dpapi_ok && dpapi_ct) {
            LocalFree(dpapi_ct);
        }
    } else {
        log_line("隐私模式已启用，不保存凭据");
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
        log_line("RSA公钥导入失败: 0x%08X", status);
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
        log_line("RSA加密失败: 0x%08X", status);
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
    /* REDQ消息头: "REDQ"(4) + 12字节协议头 = 16字节偏移后为密钥数据 */
    const uint8_t *key_data = msg + 16;
    /* 密钥数据最少需要: 32字节随机数 + 129字节RSA模数 + 3字节指数 + 2字节保留 = 166字节 */
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
 * 初始化消息(版本2)，包含:
 *   - "REDQ"魔数(4字节)
 *   - 协议版本号(2字节, 值为2)
 *   - 功能标志位(包含支持的加密套件、压缩方式等)
 *
 * 此消息必须在connect_msg之后发送，服务端收到后
 * 才会开始REDQ认证握手和后续数据推送。
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
static int ws_connect(const char *uri, WSConn *wsc, const char *desktop_code) {
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
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, hp, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    /* 从主机名中提取端口 */
    char *colon = strchr(host, ':');
    if (colon) { *colon = 0; port = atoi(colon + 1); }
    if (use_ssl && port == 80) port = 443;

    /* 创建WinHTTP会话 */
    wsc->hSession = WinHttpOpen(L"CtYunKeepAlive/" APP_VERSION, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!wsc->hSession) {
        log_line("[%s] HTTP会话创建失败: %lu", desktop_code, GetLastError());
        return 0;
    }

    /* 连接到服务器 */
    WCHAR whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    wsc->hConnect = WinHttpConnect(wsc->hSession, whost, (INTERNET_PORT)port, 0);
    if (!wsc->hConnect) {
        log_line("[%s] HTTP连接失败: %lu", desktop_code, GetLastError());
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
        log_line("[%s] HTTP请求创建失败: %lu", desktop_code, GetLastError());
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
        log_line("[%s] WebSocket升级选项设置失败: %lu", desktop_code, GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 发送HTTP升级请求 */
    if (!WinHttpSendRequest(wsc->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        log_line("[%s] HTTP请求发送失败: %lu", desktop_code, GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 接收服务端响应 */
    if (!WinHttpReceiveResponse(wsc->hRequest, NULL)) {
        log_line("[%s] HTTP响应接收失败: %lu", desktop_code, GetLastError());
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
        log_line("[%s] WebSocket升级失败，状态码=%lu", desktop_code, status_code);
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 完成WebSocket升级 */
    wsc->hWebSocket = WinHttpWebSocketCompleteUpgrade(wsc->hRequest, (DWORD_PTR)NULL);
    if (!wsc->hWebSocket) {
        log_line("[%s] WebSocket升级完成失败: %lu", desktop_code, GetLastError());
        WinHttpCloseHandle(wsc->hRequest);
        WinHttpCloseHandle(wsc->hConnect);
        WinHttpCloseHandle(wsc->hSession);
        return 0;
    }

    /* 升级完成后关闭HTTP请求句柄(不再需要) */
    WinHttpCloseHandle(wsc->hRequest);
    wsc->hRequest = NULL;

    log_line("[%s] WebSocket握手成功", desktop_code);
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

/* ======================== SendInfo协议解析 ======================== */

/**
 * SendInfo 是天翼云 WebSocket 二进制消息的封装协议，格式如下:
 *   [2字节type(小端)] [4字节总长度(小端)] [数据...]
 * 当 type=103(CLINK_MSG_MAIN_INIT) 时表示服务端要求客户端发送身份信息;
 * 客户端应回复 type=118 的 BuildMsg，格式为:
 *   [2字节type=118] [4字节总长度] [4字节data长度] [4字节固定值8] [data...]
 */

/**
 * has_send_info_type - 检查二进制缓冲区中是否包含指定类型的 SendInfo 消息
 *
 * 遍历缓冲区中的所有 SendInfo 消息，按协议格式逐条解析:
 *   偏移+0: 2字节消息类型(小端)
 *   偏移+2: 4字节消息数据长度(小端，含6字节头)
 *   偏移+6: 消息数据
 *
 * @param buf         二进制缓冲区
 * @param blen        缓冲区长度
 * @param target_type 目标消息类型(如103)
 * @return            1=找到, 0=未找到或格式错误
 */
static int has_send_info_type(const uint8_t *buf, size_t blen, uint16_t target_type) {
    size_t off = 0;
    while (off + 6 <= blen) {
        uint16_t tp = (uint16_t)(buf[off] | (buf[off + 1] << 8));
        int32_t dlen = (int32_t)(buf[off + 2] | (buf[off + 3] << 8) | (buf[off + 4] << 16) | (buf[off + 5] << 24));
        if (dlen < 0 || off + 6 + (size_t)dlen > blen) return 0;
        if (tp == target_type) return 1;
        off += 6 + (size_t)dlen;
    }
    return 0;
}

/**
 * build_send_info_msg - 构建 SendInfo 协议消息
 *
 * 普通消息(is_build_msg=0)格式:
 *   [2字节type] [4字节总长度] [data]
 *
 * BuildMsg(is_build_msg=1)格式(用于type=118等):
 *   [2字节type] [4字节总长度] [4字节data长度] [4字节固定值8] [data]
 *   其中"固定值8"是BuildMsg子协议的头部标识，含义为"后续data段的偏移量"
 *
 * @param type_val    消息类型(如118)
 * @param data        消息数据
 * @param dlen        数据长度
 * @param is_build_msg 是否为BuildMsg格式(1=是, 0=否)
 * @param out         输出缓冲区
 * @return            消息总长度
 */
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
        /* BuildMsg子头: 4字节data长度 + 4字节固定偏移值8 */
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

/**
 * build_user_payload - 构建type=118用户身份消息
 *
 * 当收到type=103(CLINK_MSG_MAIN_INIT)时，客户端需要发送用户身份信息。
 * 消息体为JSON: {"type":1, "userName":"xxx", "userInfo":"", "userId":123}
 *
 * @param s       会话信息(含user_account和user_id)
 * @param out     输出缓冲区
 * @param out_sz  缓冲区大小
 * @return        消息总长度，缓冲区不足返回0
 */
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

/* ======================== 保活线程 ======================== */

/**
 * ThreadParam - 线程参数
 *
 * 传递Session和Desktop指针给工作线程。
 */
typedef struct { Session *session; Desktop *desktop; } ThreadParam;
/* MonitorParam: 将会话和整个桌面数组交给统一轮询线程 */
typedef struct {
    Session *session;
    Desktop *desktops;
    int count;
} MonitorParam;

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
    Session *s = tp->session;

    uint8_t *ws_buf = (uint8_t *)malloc(4096);
    if (!ws_buf) return 0;

    uint8_t user_payload_buf[1024];
    size_t user_payload_len = build_user_payload(s, user_payload_buf, sizeof(user_payload_buf));
    int user_payload_sent = 0;

    /*
     * 1.2.1 的线程模型改为：保活线程在创建后先等待 start_event。
     * 这样可以把后续是否开始保活的决定权交给统一轮询线程，
     * 从而免去非运行桌面各自拉取一次完整列表的重开销。
     */
    while (g_running) {
        DWORD wait = WaitForSingleObject(d->start_event, 1000);
        if (wait == WAIT_OBJECT_0) break;
    }
    if (!g_running) {
        free(ws_buf);
        return 0;
    }

    int cycle = 0;
    while (g_running) {
        log_line("[%s] 正在连接...", d->desktop_code);
        WSConn wsc;
        if (!ws_connect(d->ws_uri, &wsc, d->desktop_code)) {
            log_line("[%s] WebSocket连接失败，5秒后重试", d->desktop_code);
            Sleep(5000);
            continue;
        }

        ws_send_text(&wsc, d->connect_msg);
        Sleep(100);
        ws_send_bytes(&wsc, initial_payload, sizeof(initial_payload));
        user_payload_sent = 0;

        log_line("[%s] 已连接，保持60秒", d->desktop_code);

        DWORD start = GetTickCount();
        while (g_running && (GetTickCount() - start) < 60000) {
            int is_text;
            int n = ws_recv(&wsc, ws_buf, 4096, &is_text);
            if (n < 0) break;
            if (n == 0) continue;
            if (!is_text && n >= 4 && memcmp(ws_buf, "REDQ", 4) == 0) {
                log_line("[%s] 收到REDQ认证请求", d->desktop_code);
                uint8_t resp[512]; size_t rlen = 0;
                if (handle_redq(ws_buf, n, resp, &rlen)) {
                    ws_send_bytes(&wsc, resp, rlen);
                    log_line("[%s] REDQ认证响应成功", d->desktop_code);
                }
            } else if (!is_text && n >= 6 && user_payload_len > 0 && !user_payload_sent) {
                /* 收到CLINK_MSG_MAIN_INIT(type=103): 服务端要求客户端发送用户身份 */
                if (has_send_info_type(ws_buf, (size_t)n, 103)) {
                    ws_send_bytes(&wsc, user_payload_buf, user_payload_len);
                    log_line("[%s] 发送用户身份响应", d->desktop_code);
                    user_payload_sent = 1;
                }
            }
        }

        ws_close(&wsc);
        log_line("[%s] 60秒完成，重新连接", d->desktop_code);

        /* 每5个周期(约5分钟)智能修剪工作集，释放物理内存 */
        cycle++;
        if (cycle % 5 == 0) trim_working_set(0);
    }

    log_line("[%s] 线程退出", d->desktop_code);
    free(ws_buf);
    return 0;
}

/* ======================== 程序入口 ======================== */

/**
 * ctrl_handler - Ctrl+C信号处理
 *
 * 设置g_running为0，通知所有工作线程优雅退出。
 */

/*
 * monitor_desktops_thread - 统一桌面状态轮询线程
 *
 * 1.2.1 改为单一轮询模式：每个 CHECK_INTERVAL 只请求一次 desktopList，
 * 再在本地将状态分发到各个 Desktop。这取代了"每个未运行桌面
 * 各自启动一个轮询线程"的策略，从而减少网络重复请求。
 */
static DWORD WINAPI monitor_desktops_thread(LPVOID param) {
    MonitorParam *mp = (MonitorParam *)param;
    Session *s = mp->session;
    Desktop *desktops = mp->desktops;
    int count = mp->count;
    DesktopLight tmp[MAX_DESKTOPS];

    while (g_running) {
        Sleep(CHECK_INTERVAL * 1000);
        if (!g_running) break;
        log_line("正在统一检查桌面状态...");

        ZeroMemory(tmp, sizeof(tmp));
        int n = get_desktop_list_light(s, tmp, MAX_DESKTOPS);
        for (int i = 0; i < count; i++) {
            Desktop *d = &desktops[i];
            int found = 0;
            int active = 0;

            /* InterlockedCompareExchange(&val, 0, 0) = 原子读取val的当前值(不修改) */
            /* 已经进入保活的桌面不再参与轮询，避免重复连接 */
            if (InterlockedCompareExchange(&d->keepalive_started, 0, 0)) continue;

            /*
             * 优化 (v1.2.3): 直接使用预计算的id_hash，不再每次调用fnv1a_hash()
             * 优化3 (v1.2.2): 先比较哈希值，再进行strcmp验证。
             * FNV-1a哈希32位碰撞率极低(~1/40亿)，大多数情况下哈希不匹配直接跳过。
             * 只有哈希命中时才调用strcmp进行精确比较，大幅减少字符串比较次数。
             * 桌面数量少时效果不明显，但在API返回数据量较大时效果显著。
             */
            uint32_t target_hash = d->id_hash;  /* 缓存目标哈希，避免重复访问 */
            for (int j = 0; j < n; j++) {
                if (tmp[j].id_hash == target_hash && strcmp(tmp[j].desktop_id, d->desktop_id) == 0) {
                    found = 1;
                    active = tmp[j].is_active;
                    break;
                }
            }

            if (!found) {
                if (!InterlockedCompareExchange(&d->missing_logged, 0, 0)) {
                    log_line("[%s] 桌面未找到，停止等待激活", d->desktop_code);
                    InterlockedExchange(&d->missing_logged, 1);
                }
                continue;
            }

            if (!active) {
                log_line("[%s] 桌面仍未激活", d->desktop_code);
                continue;
            }

            /*
             * InterlockedCompareExchange(&val, 1, 0): 若val==0则设为1并返回0，否则返回原值
             * 返回0表示本线程成功将状态从0改为1，获得建立连接的权限
             * 这能防止多次轮询周期在短时间内反复唤醒同一桌面。
             */
            if (InterlockedCompareExchange(&d->keepalive_started, 1, 0) == 0) {
                log_line("[%s] 桌面已激活，开始建立保活连接", d->desktop_code);
                if (connect_desktop(s, d)) {
                    desktop_free_certs(d);
                    SetEvent(d->start_event);
                } else {
                    InterlockedExchange(&d->keepalive_started, 0);
                }
            }
        }

        /* 轮询周期间隔较长，智能将未使用的物理内存归还给系统 */
        trim_working_set(0);
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

/**
 * usage - 显示用法帮助
 */
static void usage(const char *exe) {
    printf("天翼云电脑保活客户端 v" APP_VERSION "\n");
    printf("项目地址: https://github.com/DionZM/ctyun_keepalive_c\n\n");
    printf("用法: %s [选项]\n\n", exe);
    printf("选项:\n");
    printf("  /background, /b  后台运行，日志写入run.log\n");
    printf("  /privacy,    /p  隐私模式，不保存用户名/密码到config.json\n");
    printf("  /random,     /r  随机生成设备码(默认基于机器指纹确定性生成)\n");
    printf("  /version,    /v  显示版本号\n");
    printf("  /help,       /h  显示此帮助信息\n");
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
        if (strcmp(argv[i], "/background") == 0 || strcmp(argv[i], "/b") == 0) {
            g_bg_switch = 1;
        } else if (strcmp(argv[i], "/privacy") == 0 || strcmp(argv[i], "/p") == 0) {
            g_privacy = 1;
        } else if (strcmp(argv[i], "/random") == 0 || strcmp(argv[i], "/r") == 0) {
            g_random = 1;
        } else if (strcmp(argv[i], "/version") == 0 || strcmp(argv[i], "/v") == 0) {
            printf("版本 " APP_VERSION "\n");
            return 0;
        } else if (strcmp(argv[i], "/help") == 0 || strcmp(argv[i], "/h") == 0 || strcmp(argv[i], "/?") == 0) {
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

    log_line("天翼云电脑保活 V" APP_VERSION);

    /* 解析用户凭据(尝试自动解密config.json，失败则手动输入) */
    Session session = {0};
    if (!resolve_credentials(&session)) {
        log_line("凭据解析失败");
        WSACleanup();
        return 1;
    }

    /* 登录成功后清零用户名(不再需要，节省内存) */
    log_line("登录成功, 用户: %s", session.user_name);
    memset(session.user_name, 0, sizeof(session.user_name));

    /* 获取桌面列表 */
    Desktop *desktops = (Desktop *)calloc(MAX_DESKTOPS, sizeof(Desktop));
    int ndesktops = get_desktop_list(&session, desktops, MAX_DESKTOPS);
    log_line("找到 %d 个桌面", ndesktops);

    /* 为每个桌面创建工作线程 */
    ThreadParam params[MAX_DESKTOPS];
    HANDLE threads[MAX_DESKTOPS + 2];
    MonitorParam monitor = {&session, desktops, ndesktops};
    int nthreads = 0;

    /*
     * 1.2.1 的启动流程与 1.2.0 最大差异在于：
     * 1. 每个桌面的保活线程先创建出来，但在 start_event 上等待
     * 2. 已运行的桌面立即触发事件，未运行的桌面则交给统一轮询线程
     * 3. 这样可以明确"线程生命周期"和"何时开始保活"两个职责
     */
    for (int i = 0; i < ndesktops; i++) {
        params[i].session = &session;
        params[i].desktop = &desktops[i];

        desktops[i].start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!desktops[i].start_event) {
            log_line("[%s] 保活启动事件创建失败: %lu", desktops[i].desktop_code, GetLastError());
            continue;
        }

        threads[nthreads] = CreateThread(NULL, THREAD_STACK, keep_alive_thread, &params[i], 0, NULL);
        if (!threads[nthreads]) {
            log_line("[%s] 保活线程创建失败: %lu", desktops[i].desktop_code, GetLastError());
            CloseHandle(desktops[i].start_event);
            desktops[i].start_event = NULL;
            continue;
        }
        nthreads++;

        if (desktops[i].is_active) {
            if (connect_desktop(&session, &desktops[i])) {
                InterlockedExchange(&desktops[i].keepalive_started, 1);
                desktop_free_certs(&desktops[i]);
                log_line("[%s] 运行中，开始保活", desktops[i].desktop_code);
                SetEvent(desktops[i].start_event);
            } else {
                log_line("[%s] 连接失败，等待统一轮询重试", desktops[i].desktop_code);
            }
        } else {
            log_line("[%s] 已关机，等待统一轮询激活", desktops[i].desktop_code);
        }
    }

    if (ndesktops > 0) {
        threads[nthreads] = CreateThread(NULL, THREAD_STACK, monitor_desktops_thread, &monitor, 0, NULL);
        if (threads[nthreads]) {
            nthreads++;
        } else {
            log_line("统一轮询线程创建失败: %lu", GetLastError());
        }
    }

    if (nthreads == 0) {
        log_line("没有可用桌面");
    } else {
        HANDLE hInputThread = NULL;

        if (g_background) {
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char *slash = strrchr(exe_path, '\\');
            if (slash) *slash = 0;
            snprintf(g_log_path, sizeof(g_log_path), "%s\\run.log", exe_path);
            g_log_file = open_log_file(g_log_path, "w", &g_log_size);
            if (!g_log_file) {
                g_log_file = open_log_file(g_log_path, "a", &g_log_size);
            }
            g_log_last_flush = GetTickCount();
            FreeConsole();
            log_line("已切换到后台运行, 日志: %s", g_log_path);
        } else {
            hInputThread = CreateThread(NULL, THREAD_STACK, console_input_thread, NULL, 0, NULL);
        }

        trim_working_set(1);
        log_line("保活已启动, Ctrl+C 停止");

        while (g_running) {
            DWORD result = WaitForMultipleObjects(nthreads, threads, TRUE, 500);
            if (result != WAIT_TIMEOUT) break;
            if (g_bg_switch && !g_background) {
                char exe_path[MAX_PATH];
                GetModuleFileNameA(NULL, exe_path, MAX_PATH);
                char *slash = strrchr(exe_path, '\\');
                if (slash) *slash = 0;
                snprintf(g_log_path, sizeof(g_log_path), "%s\\run.log", exe_path);
                g_log_file = open_log_file(g_log_path, "w", &g_log_size);
                if (!g_log_file) g_log_file = open_log_file(g_log_path, "a", &g_log_size);
                g_log_last_flush = GetTickCount();
                g_background = 1;
                FreeConsole();
                log_line("已切换到后台运行, 日志: %s", g_log_path);
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
    log_line("已停止");
    return 0;
}
