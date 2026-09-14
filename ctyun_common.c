/*
 * ctyun_common.c - ctyun_keepalive / ctyun_points 共享公共层
 * 由 gen_split.py 机械切片生成，勿手改业务逻辑。
 */
#include "ctyun_common.h"

/* 公共全局 */
HCRYPTPROV g_crypt = 0;
HINTERNET g_inet = NULL;
BCRYPT_ALG_HANDLE g_rsa_alg = NULL;
volatile LONG g_running = 1;

/* ===== common section 1 ===== */
/* ======================== 加密基础函数 ======================== */

/**
 * crypto_init - 初始化加密相关全局资源
 *
 * 初始化CryptoAPI提供者(用于SHA-256/MD5/随机数)和
 * CNG RSA算法提供者(用于REDQ握手中的RSA-OAEP加密)。
 */
int crypto_init(void) {
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

/**
 * sha256 - 计算SHA-256哈希
 *
 * 使用CryptoAPI计算数据的SHA-256摘要。
 *
 * @param d    输入数据
 * @param n    数据长度
 * @param out  输出32字节哈希值
 */
void sha256(const uint8_t *d, size_t n, uint8_t *out) {
    HCRYPTHASH h = 0;
    if (!CryptCreateHash(g_crypt, CALG_SHA_256, 0, 0, &h)) { memset(out, 0, 32); return; }
    if (!CryptHashData(h, (BYTE *)d, (DWORD)n, 0)) { CryptDestroyHash(h); memset(out, 0, 32); return; }
    DWORD dl = 32;
    if (!CryptGetHashParam(h, HP_HASHVAL, out, &dl, 0)) { memset(out, 0, 32); }
    CryptDestroyHash(h);
}

const char HEX_LUT[] = "0123456789abcdef";

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
size_t url_encode(const char *in, char *out, size_t out_sz) {
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
    /* 输出缓冲区至少需要 4 字节(最坏情况: 1个安全字符 + 3字节 %XX 仍需收尾的 '\0')。
     * 当 out_sz < 4 时，out_sz - 4 会下溢成巨大值导致越界写入，这里直接防御。 */
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

/**
 * sha256_hex - 计算字符串的SHA-256并输出为64字符十六进制
 *
 * @param s    输入字符串
 * @param out  输出缓冲区(至少65字节)
 */
void sha256_hex(const char *s, char *out) {
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
void md5_hex(const char *s, char *out) {
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
size_t b64enc(const uint8_t *in, size_t n, char *out) {
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
int b64val(char c) {
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
size_t b64dec(const char *in, size_t n, uint8_t *out) {
    size_t o = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=') break;
        int v = b64val(in[i]);
        if (v < 0) {
            return 0;
        }
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
 * 局限性: 使用strstr全局搜索，可能匹配到嵌套对象中的同名键。
 * 对于可能存在键名冲突的场景，应先定位到目标对象范围，
 * 再使用jstr_range或json_find_key进行精确提取。
 *
 * @param j    JSON字符串
 * @param k    要查找的键名
 * @param buf  输出缓冲区
 * @param bsz  输出缓冲区大小
 * @return     buf指针(未找到则返回空字符串)
 */
char *jstr(const char *j, const char *k, char *buf, size_t bsz) {
    if (strlen(k) > 120) { buf[0] = 0; return buf; }
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

/**
 * jint - 从JSON字符串中提取指定键的整数值
 *
 * @param j  JSON字符串
 * @param k  要查找的键名
 * @return   整数值(未找到返回0)
 */
int jint(const char *j, const char *k) {
    if (strlen(k) > 120) return 0;
    char srch[128];
    snprintf(srch, sizeof(srch), "\"%s\"", k);
    const char *p = strstr(j, srch);
    if (!p) return 0;
    p += strlen(srch);
    while (*p == ' ' || *p == ':') p++;
    return atoi(p);
}

int jbool(const char *j, const char *k) {
    if (strlen(k) > 120) return 0;
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

char *jstr_range(const char *start, const char *end, const char *k, char *buf, size_t bsz) {
    /* 与 jstr() 保持一致: 超长键名直接判失败，避免 srch 被静默截断导致误匹配 */
    if (strlen(k) > 120) { buf[0] = 0; return buf; }
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

/**
 * str_dup - 堆上复制字符串
 *
 * 类似strdup，但跨平台兼容。用于Desktop结构体动态字段赋值。
 * 空指针或空字符串返回NULL，便于后续free(NULL)安全调用。
 *
 * @param s  源字符串
 * @return   新分配的字符串副本，或NULL
 */
char *str_dup(const char *s) {
    if (!s || !s[0]) return NULL;
    size_t n = strlen(s) + 1;
    char *r = (char *)malloc(n);
    if (!r) return NULL;
    memcpy(r, s, n);
    return r;
}
/* ===== common section 2 ===== */
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
/* ===== common section 3 ===== */

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
void desktop_free_certs(Desktop *d) {
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
        if (!d->connect_msg) {
            ct_log("[%s] 警告: connect_msg内存分配失败，保留证书信息", d->desktop_code);
            return;
        }
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
        if (!d->ws_uri) {
            ct_log("[%s] 警告: ws_uri内存分配失败", d->desktop_code);
        } else {
            const char *p_str = (d->port && d->port[0]) ? d->port : "443";
            if (d->clink_host && d->clink_host[0] && strchr(d->clink_host, ':') == NULL)
                snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->clink_host, p_str, d->desktop_id);
            else if (d->clink_host && d->clink_host[0])
                snprintf(d->ws_uri, 512, "wss://%s/clinkProxy/%s/MAIN", d->clink_host, d->desktop_id);
            else
                snprintf(d->ws_uri, 512, "wss://%s:%s/clinkProxy/%s/MAIN", d->host, p_str, d->desktop_id);
        }
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
void desktop_cleanup(Desktop *d) {
    if (d->start_event) {
        /*
         * 优化1 (v1.2.2): 先触发事件唤醒保活线程，再关闭句柄。
         * 保活线程在keep_alive_thread()中等待此事件：
         *   WaitForSingleObject(d->start_event, 1000)
         * 如果直接CloseHandle，线程可能永远卡在等待状态。
         * SetEvent后给50ms让线程退出等待循环，再安全关闭句柄。
         */
        SetEvent(d->start_event);
        Sleep(DESKTOP_CLEANUP_MS);
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
int http_init(void) {
    g_inet = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_inet) return 0;

    WinHttpSetTimeouts(g_inet, DNS_RESOLVE_TIMEOUT_MS, WINHTTP_CONNECT_TIMEOUT_MS, WINHTTP_SEND_TIMEOUT_MS, WINHTTP_RECEIVE_TIMEOUT_MS);
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
int http_req(const char *method, const char *url, const char *body, size_t blen,
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
        ct_log("URL解析失败: %s", url);
        return -1;
    }
    WCHAR wmethod[16] = {0};
    MultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 16);

    /*
     * WinHTTP连接复用: 会话句柄g_inet内部自动维护TCP连接池，
     * 关闭hconn不影响连接池中的TCP连接复用，因此每次请求后正常关闭hconn。
     */
    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) {
        char hname[256];
        WideCharToMultiByte(CP_ACP, 0, whostname, -1, hname, sizeof(hname), NULL, NULL);
        ct_log("连接服务器失败: %s:%d 错误=%lu", hname, uc.nPort, GetLastError());
        return -1;
    }

    /* 创建HTTP请求 */
    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) {
        ct_log("创建HTTP请求失败: 错误=%lu", GetLastError());
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
        ct_log("发送HTTP请求失败: 错误=%lu", GetLastError());
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn);
        return -1;
    }

    /* 接收响应 */
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        ct_log("接收HTTP响应失败: 错误=%lu", GetLastError());
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
int http_get_binary(const char *url, const char **hdrs, int nhdrs,
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

/**
 * http_req_with_cookies - 带Cookie请求并捕获Set-Cookie
 *
 * eaichat.ctyun.cn 认证依赖 cookie(YL-Token/YL-Ssid)，WinHTTP默认不自动管理cookie。
 * 本函数在请求头附加 Cookie: 字符串，并从响应头解析所有 Set-Cookie 合并回写。
 *
 * @param method        HTTP方法
 * @param url           完整URL
 * @param body          请求体(可NULL)
 * @param blen          请求体长度
 * @param ct            Content-Type(可NULL)
 * @param hdrs          自定义请求头数组
 * @param nhdrs         请求头数量
 * @param cookies_in    请求时发送的Cookie串(可NULL)
 * @param cookie_out    输出: 合并后的Cookie串(传入已有cookie，本函数追加/更新)
 * @param cookie_sz     cookie_out缓冲区大小
 * @param resp          响应缓冲区
 * @param rsz           响应缓冲区大小
 * @param status_out    输出HTTP状态码(可NULL)
 * @return              响应体长度，失败返回-1
 */
int http_req_with_cookies(const char *method, const char *url,
                                  const char *body, size_t blen,
                                  const char *ct, const char **hdrs, int nhdrs,
                                  const char *cookies_in,
                                  char *cookie_out, size_t cookie_sz,
                                  char *resp, size_t rsz, int *status_out) {
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    WCHAR whostname[256], wurl_path[2048];
    uc.lpszHostName = whostname; uc.dwHostNameLength = sizeof(whostname)/sizeof(WCHAR);
    uc.lpszUrlPath = wurl_path; uc.dwUrlPathLength = sizeof(wurl_path)/sizeof(WCHAR);
    WCHAR wurl[4096];
    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 4096);
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return -1;
    WCHAR wmethod[16] = {0};
    MultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 16);

    HINTERNET hconn = WinHttpConnect(g_inet, whostname, (INTERNET_PORT)uc.nPort, 0);
    if (!hconn) return -1;
    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) { WinHttpCloseHandle(hconn); return -1; }
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
    if (cookies_in && cookies_in[0]) {
        char h[2048]; snprintf(h, sizeof(h), "Cookie: %s", cookies_in);
        WCHAR wh[2048]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 2048);
        WinHttpAddRequestHeaders(hreq, wh, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (void *)body, (DWORD)blen, (DWORD)blen, 0)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }

    /* 状态码 */
    DWORD status_code = 0, sc_len = sizeof(status_code);
    WinHttpQueryHeaders(hreq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status_code, &sc_len, NULL);
    if (status_out) *status_out = (int)status_code;

    /* 解析Set-Cookie并合并到cookie_out */
    if (cookie_out && cookie_sz > 0) {
        DWORD idx = 0;
        for (;;) {
            DWORD sz = 0;
            /* 先用 NULL 缓冲查询第 idx 个 Set-Cookie 的所需大小。
             * WinHttpQueryHeaders 对 SET_COOKIE 用索引枚举: idx 是 0-based，
             * 每次成功查询后 idx 自动递增。失败时 idx 不变。 */
            if (!WinHttpQueryHeaders(hreq, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
                                     NULL, &sz, &idx)) {
                DWORD e = GetLastError();
                if (e == ERROR_WINHTTP_HEADER_NOT_FOUND) break;  /* 无更多Set-Cookie */
                if (e != ERROR_INSUFFICIENT_BUFFER) break;       /* 其他错误 */
            }
            if (sz == 0) break;
            sz += 4;  /* 余量 */
            WCHAR *wsc = (WCHAR *)malloc(sz);
            if (!wsc) break;
            char sc[1024];
            if (WinHttpQueryHeaders(hreq, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
                                    wsc, &sz, &idx)) {
                WideCharToMultiByte(CP_ACP, 0, wsc, -1, sc, sizeof(sc), NULL, NULL);
                /* 提取 name=value (分号前) */
                char *semi = strchr(sc, ';');
                if (semi) *semi = 0;
                char *eq = strchr(sc, '=');
                if (eq) {
                    /* CAS 响应的 Set-Cookie 顺序:
                     *   [1] name=有效值 (Path=当前路径)
                     *   [2] name=; Max-Age=0 (Path=/ 不同路径, 删除指令)
                     * [2]的删除是针对其他path的，不应清掉[1]的有效值。
                     * 策略: 空值(Max-Age=0删除指令)一律忽略，保留已有有效cookie。 */
                    const char *val_start = eq + 1;
                    int is_delete = (*val_start == 0);
                    if (is_delete) {
                        /* 跳过删除指令，不动已有cookie */
                    } else {
                        char name[128];
                        size_t nl = (size_t)(eq - sc);
                        if (nl >= sizeof(name)) nl = sizeof(name) - 1;
                        memcpy(name, sc, nl); name[nl] = 0;
                        /* 在cookie_out中查找同名cookie并替换 */
                        char *p = cookie_out;
                        while (*p) {
                            char *kv_start = p;
                            char *kv_end = strchr(p, ';');
                            char *k_eq = strchr(p, '=');
                            if (!k_eq || (kv_end && k_eq > kv_end)) break;
                            size_t kn = (size_t)(k_eq - p);
                            if (kn == nl && memcmp(p, name, nl) == 0) {
                                char *after = kv_end ? kv_end : p + strlen(p);
                                if (*after == ';') after++;
                                memmove(kv_start, after, strlen(after) + 1);
                                break;
                            }
                            if (!kv_end) break;
                            p = kv_end + 1;
                            while (*p == ' ') p++;
                        }
                        /* 追加新值 */
                        size_t cur = strlen(cookie_out);
                        if (cur > 0 && cookie_out[cur-1] != ';' && cur + 1 < cookie_sz) {
                            cookie_out[cur++] = ';';
                            cookie_out[cur] = 0;
                        }
                        if (cur + strlen(sc) + 1 < cookie_sz) {
                            strcpy(cookie_out + cur, sc);
                        }
                    }
                }
            }
            free(wsc);
            if (idx > 64) break;
        }
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

/**
 * http_get_via_curl - 通过系统curl.exe发起GET请求，读取Location头
 *
 * [TODO 临时方案] cas/login 必须用 curl.exe，不能用 WinHTTP。
 * 原因: cas/login 的 URL 含 "?service=https://..."，query 里的 "//" 会触发
 *       WinHTTP 的 URL 规范化，把整条请求路径破坏成 "/cloudB/dy/iam/"，
 *       导致服务端返回登录页而非 302+ticket。curl.exe 不做这种规范化。
 * 长期方案: 改用 libcurl 静态链接(见 TODO.md)。
 *
 * 实现: CreateProcess 启动系统 curl.exe(Win10 1803+/Win11自带)，
 *       curl -s -i -k 输出响应头到 stdout，从输出里解析 Location 行。
 *
 * @param url          完整URL
 * @param hdrs         请求头数组(可NULL，形如 "key: value")
 * @param nhdrs        请求头数量
 * @param cookies_in   请求cookie串(形如 "k1=v1; k2=v2")
 * @param cookie_out   未使用(保留参数兼容旧调用)，传NULL
 * @param cookie_sz    未使用
 * @param resp         响应缓冲区(含头+体)
 * @param rsz          响应缓冲区大小
 * @param status_out   输出HTTP状态码(可NULL)
 * @param location_out 输出Location头值(可NULL)
 * @param loc_sz       location缓冲区大小
 * @return             响应(头+体)长度，失败返回-1
 */
int http_get_via_curl(const char *url, const char **hdrs, int nhdrs,
                              const char *cookies_in,
                              char *cookie_out, size_t cookie_sz,
                              char *resp, size_t rsz, int *status_out,
                              char *location_out, size_t loc_sz) {
    (void)cookie_out; (void)cookie_sz;  /* curl模式下不在此处管理cookie */

    /* 构造命令行: curl -s -i -k --max-time 20 -H "Cookie: ..." -H "..." URL */
    char cmdline[8192];
    int pos = 0;
    pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, "curl.exe -s -i -k --max-time 20");
    if (cookies_in && cookies_in[0]) {
        pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -H \"Cookie: %s\"", cookies_in);
    }
    for (int i = 0; i < nhdrs && hdrs[i]; i++) {
        pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -H \"%s\"", hdrs[i]);
    }
    if (pos + (int)strlen(url) + 4 >= (int)sizeof(cmdline)) return -1;
    pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " \"%s\"", url);

    /* 创建管道捕获 stdout */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return -1;
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;

    char cmdcopy[8192];
    strncpy(cmdcopy, cmdline, sizeof(cmdcopy) - 1);
    cmdcopy[sizeof(cmdcopy) - 1] = 0;
    if (!CreateProcessA(NULL, cmdcopy, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe); CloseHandle(hWritePipe);
        return -1;
    }
    CloseHandle(hWritePipe);  /* 关闭写端，避免ReadFile死等 */

    /* 读取stdout */
    size_t total = 0;
    DWORD n;
    while (total < rsz - 1 &&
           ReadFile(hReadPipe, resp + total, (DWORD)(rsz - 1 - total), &n, NULL) && n > 0) {
        total += n;
    }
    resp[total] = 0;

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    /* 解析状态码和Location(从响应头文本) */
    if (status_out) {
        const char *sp = strstr(resp, "HTTP/");
        if (sp) {
            const char *p = sp;
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            *status_out = atoi(p);
        }
    }
    if (location_out && loc_sz > 0) {
        location_out[0] = 0;
        const char *lp = resp;
        while (lp && *lp) {
            const char *line_end = strstr(lp, "\r\n");
            if (!line_end) break;
            if (lp + 9 <= line_end && _strnicmp(lp, "Location:", 9) == 0) {
                const char *vp = lp + 9;
                while (vp < line_end && (*vp == ' ' || *vp == '\t')) vp++;
                size_t vl = (size_t)(line_end - vp);
                if (vl >= loc_sz) vl = loc_sz - 1;
                memcpy(location_out, vp, vl);
                location_out[vl] = 0;
                break;
            }
            lp = line_end + 2;
            if (line_end + 2 >= resp + total) break;
        }
    }
    return (int)total;
}

/**
 * http_get_with_winhttp - 用 WinHTTP 发起 GET 并提取 Location 头
 *
 * 用于 cas/login 方案 2：把 query 里的 service 值改成不含 "//" 的形式，
 * 绕过 WinHTTP 对 URL 中连续双斜杠的规范化（它会把 query 里的 // 当成路径分隔）。
 *
 * @param url          完整URL（调用方需保证 scheme/host/path/query 合法）
 * @param hdrs         请求头数组
 * @param nhdrs        请求头数量
 * @param cookies_in   请求Cookie串
 * @param resp         响应缓冲（头+体）
 * @param rsz          响应缓冲大小
 * @param status_out   输出HTTP状态码
 * @param location_out 输出Location头
 * @param loc_sz       location缓冲大小
 * @return             响应（头+体）长度，失败返回-1
 */
int http_get_with_winhttp(const char *url, const char **hdrs, int nhdrs,
                                  const char *cookies_in,
                                  char *resp, size_t rsz,
                                  int *status_out,
                                  char *location_out, size_t loc_sz) {
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
    DWORD flags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_ESCAPE_DISABLE_QUERY;
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
        WCHAR whdr[512];
        MultiByteToWideChar(CP_ACP, 0, hdrs[i], -1, whdr, 512);
        WinHttpAddRequestHeaders(hreq, whdr, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    if (cookies_in && cookies_in[0]) {
        char h[2048]; snprintf(h, sizeof(h), "Cookie: %s", cookies_in);
        WCHAR wh[2048]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 2048);
        WinHttpAddRequestHeaders(hreq, wh, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }

    /* 状态码 */
    DWORD status_code = 0, sc_len = sizeof(status_code);
    WinHttpQueryHeaders(hreq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status_code, &sc_len, NULL);
    if (status_out) *status_out = (int)status_code;

    /* Location 头 */
    if (location_out && loc_sz > 0) {
        location_out[0] = 0;
        WCHAR wloc[1024];
        DWORD loc_len = sizeof(wloc);
        if (WinHttpQueryHeaders(hreq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                wloc, &loc_len, WINHTTP_NO_HEADER_INDEX)) {
            WideCharToMultiByte(CP_ACP, 0, wloc, -1, location_out, (int)loc_sz, NULL, NULL);
        }
    }

    DWORD total = 0, n;
    while (total < rsz - 1 && WinHttpReadData(hreq, resp + total, (DWORD)(rsz - 1 - total), &n) && n > 0) {
        total += n;
    }
    resp[total] = 0;

    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    return (int)total;
}

/**
 * http_read_sse - 读取SSE流式响应直至结束
 *
 * eaichat chat/completions 返回 text/event-stream，数据以 "data: ...\n\n" 分块。
 * 本函数逐块读取，对每个完整 event 调用回调。回调返回0则继续，非0则提前终止。
 *
 * @param url         完整URL
 * @param body        请求体
 * @param blen        请求体长度
 * @param hdrs        请求头数组
 * @param nhdrs       请求头数量
 * @param cookies     cookie串
 * @param callback    每个event的回调(data字段内容, 长度, userdata)
 * @param userdata    传给回调的用户数据
 * @return            读取的总字节数, 失败返回-1
 */

int http_read_sse(const char *url, const char *body, size_t blen,
                          const char **hdrs, int nhdrs, const char *cookies,
                          SseEventCallback callback, void *userdata) {
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
    HINTERNET hreq = WinHttpOpenRequest(hconn, L"POST", wurl_path, NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) { WinHttpCloseHandle(hconn); return -1; }
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
    if (cookies && cookies[0]) {
        char h[2048]; snprintf(h, sizeof(h), "Cookie: %s", cookies);
        WCHAR wh[2048]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 2048);
        WinHttpAddRequestHeaders(hreq, wh, (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (void *)body, (DWORD)blen, (DWORD)blen, 0)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }
    if (!WinHttpReceiveResponse(hreq, NULL)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1;
    }

    /* SSE: 设置较长接收超时 */
    DWORD recv_timeout = 120000;
    WinHttpSetOption(hreq, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_timeout, sizeof(recv_timeout));

    /* 逐块读取，按 "\n\n" 切分event */
    char *acc = (char *)malloc(16384);   /* 累积缓冲 */
    char *chunk = (char *)malloc(8192);
    if (!acc || !chunk) { free(acc); free(chunk); WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); return -1; }
    size_t acc_len = 0;
    long total = 0;
    DWORD n;
    int abort = 0;
    while (!abort && WinHttpReadData(hreq, chunk, 8191, &n) && n > 0) {
        total += (long)n;
        /* 追加到acc */
        if (acc_len + n >= 16384) {
            /* 处理已积累的完整event后腾空 */
            /* 先处理所有完整event */
        }
        size_t copy = n;
        if (acc_len + copy >= 16384) copy = 16384 - 1 - acc_len;
        memcpy(acc + acc_len, chunk, copy);
        acc_len += copy;
        acc[acc_len] = 0;

        /* 按双换行切分 */
        char *p = acc;
        for (;;) {
            char *eend = strstr(p, "\n\n");
            if (!eend) break;
            /* event内容 p..eend。提取 data: 行 */
            char *line = p;
            while (line < eend) {
                char *nl = memchr(line, '\n', (size_t)(eend - line));
                if (!nl) nl = eend;
                if (nl - line >= 5 && strncmp(line, "data:", 5) == 0) {
                    char *data_start = line + 5;
                    while (data_start < nl && (*data_start == ' ' || *data_start == '\t')) data_start++;
                    size_t dl = (size_t)(nl - data_start);
                    /* 去除尾部\r(不计入dl) */
                    while (dl > 0 && (data_start[dl-1] == '\r')) dl--;
                    if (callback && dl > 0) {
                        /* 把data复制到独立缓冲再回调，避免在acc上就地改写越界 */
                        char databuf[1024];
                        size_t cpy = dl < sizeof(databuf) - 1 ? dl : sizeof(databuf) - 1;
                        memcpy(databuf, data_start, cpy);
                        databuf[cpy] = 0;
                        int r = callback(databuf, cpy, userdata);
                        if (r != 0) { abort = 1; break; }
                    }
                    break;
                }
                line = (*nl == '\n') ? nl + 1 : nl;
            }
            p = eend + 2;
            if (abort) break;
        }
        /* 把剩余未处理内容移到acc开头 */
        if (p > acc && p < acc + acc_len) {
            size_t remain = (size_t)((acc + acc_len) - p);
            memmove(acc, p, remain);
            acc_len = remain;
            acc[acc_len] = 0;
        } else if (p >= acc + acc_len) {
            acc_len = 0;
            acc[0] = 0;
        }
    }

    free(acc);
    free(chunk);
    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    return (int)total;
}

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
void make_base_headers(const Session *s, const char **hdrs, int *nhdrs) {
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
void make_sig_headers(const Session *s, const char **hdrs, int *nhdrs) {
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
int api_post_noauth(const Session *s, const char *url, const char *body, size_t blen,
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
int api_post(const Session *s, const char *url, const char *body, size_t blen,
                    const char *ct, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("POST", url, body, blen, ct, hdrs, nhdrs, resp, rsz);
}

int api_get(const Session *s, const char *url, char *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_req("GET", url, NULL, 0, NULL, hdrs, nhdrs, resp, rsz);
}

int api_get_binary(const Session *s, const char *url, uint8_t *resp, size_t rsz) {
    const char *hdrs[16];
    int nhdrs = 0;
    make_sig_headers(s, hdrs, &nhdrs);
    return http_get_binary(url, hdrs, nhdrs, resp, rsz);
}
/* ===== common section 4 ===== */
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
int try_captcha_ocr(const Session *s, const char *user,
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
        ct_log("验证码图片下载失败");
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
        ct_log("OCR接口连接失败");
        return 1;
    }
    if (rlen >= (int)sizeof(orc_resp)) {
        ct_log("OCR响应过长，可能被截断");
        rlen = (int)sizeof(orc_resp) - 1;
    }
    orc_resp[rlen] = 0;

    jstr(orc_resp, "data", captcha_out, co_sz);
    if (!captcha_out[0]) {
        ct_log("OCR识别结果为空");
        return 1;
    }
    ct_log("OCR识别成功，长度=%d", (int)strlen(captcha_out));
    return 2;
}
/* ===== common section 5 ===== */
/* ======================== 登录流程 ======================== */

/**
 * do_login_send - 发送登录请求并解析响应
 *
 * 封装登录请求的发送与响应解析，供自动/手工两个阶段共用。
 * 使用 json_find_key 单次扫描解析登录响应，避免多次从头遍历。
 *
 * @param s         会话信息(输出 secretKey/userId/tenantId 等)
 * @param user      用户名
 * @param final_sha SHA256(密码+challengeCode)
 * @param sha2_pwd  SHA256(SHA256(密码)+challengeCode)
 * @param cid       挑战码ID (challengeId)
 * @param captcha   验证码文本
 * @param resp      响应缓冲区
 * @param resp_sz   缓冲区大小
 * @return          1=登录成功, 0=验证码错误, -1=用户名或密码错误, -2=请求发送失败
 */
int do_login_send(Session *s, const char *user, const char *final_sha, const char *sha2_pwd,
                         const char *cid, const char *captcha, char *resp, size_t resp_sz) {
    /* URL编码challengeId和deviceCode，避免特殊字符破坏请求体 */
    char enc_cid[512], enc_dc[512];
    url_encode(cid, enc_cid, sizeof(enc_cid));
    url_encode(s->device_code, enc_dc, sizeof(enc_dc));

    /* 构建登录请求体 (application/x-www-form-urlencoded) */
    char post[4096];
    snprintf(post, sizeof(post),
             "userAccount=%s&password=%s&sha256Password=%s&challengeId=%s&captchaCode=%s"
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
             user, final_sha, sha2_pwd, enc_cid, captcha, enc_dc);

    /* 发送登录POST请求 */
    if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/login",
                        post, strlen(post), "application/x-www-form-urlencoded",
                        resp, (int)resp_sz) < 0) {
        return -2;
    }

    /* 检查响应code，非0表示业务错误 */
    int code = jint(resp, "code");
    if (code != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        /* "用户名或密码错误" — 此类错误重试无意义，直接返回 */
        if (strcmp(msg, "\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf") == 0) {
            return -1;
        }
        return 0;
    }

    /* 定位响应中的data对象 */
    const char *data_start = strstr(resp, "\"data\"");
    if (!data_start) return 0;
    data_start = strchr(data_start, '{');
    if (!data_start) return 0;

    /* 使用json_find_key单次扫描提取所有字段 (v1.2.2优化) */
    const char *vstart;
    int vlen;
    char vtype;

    /* 提取secretKey — 登录后的签名密钥，后续API调用必需 */
    if (json_find_key(data_start, "secretKey", &vstart, &vlen, &vtype) && vtype == 's') {
        int copy_len = vlen < (int)sizeof(s->secret_key) - 1 ? vlen : (int)sizeof(s->secret_key) - 1;
        memcpy(s->secret_key, vstart, copy_len);
        s->secret_key[copy_len] = 0;
    }
    /* 提取userName — 用户显示名称 */
    if (json_find_key(data_start, "userName", &vstart, &vlen, &vtype) && vtype == 's') {
        int copy_len = vlen < (int)sizeof(s->user_name) - 1 ? vlen : (int)sizeof(s->user_name) - 1;
        memcpy(s->user_name, vstart, copy_len);
        s->user_name[copy_len] = 0;
    }
    /* 提取userAccount — 用户登录账号 */
    if (json_find_key(data_start, "userAccount", &vstart, &vlen, &vtype) && vtype == 's') {
        int copy_len = vlen < (int)sizeof(s->user_account) - 1 ? vlen : (int)sizeof(s->user_account) - 1;
        memcpy(s->user_account, vstart, copy_len);
        s->user_account[copy_len] = 0;
    }
    /* 提取userId — 用户唯一标识 */
    if (json_find_key(data_start, "userId", &vstart, &vlen, &vtype) && vtype == 'n') {
        char num_buf[32];
        int copy_len = vlen < 31 ? vlen : 31;
        memcpy(num_buf, vstart, copy_len);
        num_buf[copy_len] = 0;
        s->user_id = atoi(num_buf);
    }
    /* 提取tenantId — 租户标识 */
    if (json_find_key(data_start, "tenantId", &vstart, &vlen, &vtype) && vtype == 'n') {
        char num_buf[32];
        int copy_len = vlen < 31 ? vlen : 31;
        memcpy(num_buf, vstart, copy_len);
        num_buf[copy_len] = 0;
        s->tenant_id = atoi(num_buf);
    }
    /* 提取bondedDevice — 设备是否已绑定 (true=4字符, false=5字符) */
    if (json_find_key(data_start, "bondedDevice", &vstart, &vlen, &vtype) && vtype == 'b') {
        s->bonded_device = (vlen == 4);
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
            ct_log("[dumpauth] 已转储登录响应到 %s", full);
        }
    }
    return 1;
}

/**
 * do_login - 执行天翼云电脑登录
 *
 * 登录流程分两个阶段:
 *
 * 阶段1 — 自动OCR识别 (最多3次):
 *   1. 调用 genChallengeData 获取挑战码 (challengeId + challengeCode)
 *   2. 预计算密码哈希: SHA256(密码+challengeCode) 和 SHA256(SHA256(密码)+challengeCode)
 *   3. 下载验证码图片并OCR识别
 *   4. OCR成功则发送登录请求，失败则进入阶段2
 *   5. 登录请求失败(验证码错误)则继续下一次自动尝试
 *
 * 阶段2 — 手工输入 (最多3次):
 *   1. 获取新的挑战码和验证码图片
 *   2. 弹出窗口显示验证码，用户手工输入
 *   3. 发送登录请求，失败则继续下一次手工尝试
 *
 * 特殊处理:
 *   - 用户名或密码错误时直接返回0，不重试
 *   - 手工3次全部失败则输出"验证码识别错误"并退出程序
 *
 * @param s     会话信息(输出 secretKey/userId/tenantId)
 * @param user  用户名
 * @param pwd   原始密码
 * @return      1=登录成功, 0=登录失败
 */
int do_login(Session *s, const char *user, const char *pwd) {
    uint8_t *img_data = NULL;
    int img_len = 0;
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;

    /* ====== 阶段1: 自动OCR识别，最多3次 ====== */
    if (ct_manual_captcha_mode()) goto ct_manual_phase;
    for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {

        /* 获取挑战码 — 每次尝试都需要新的挑战码 */
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData",
                            "{}", 2, "application/json", resp, MAX_RESP) < 0) {
            ct_log("获取挑战码失败 (尝试%d)", attempt);
            continue;
        }
        int code = jint(resp, "code");
        ct_log("挑战码响应: code=%d", code);
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            ct_log("获取挑战码错误: %s", msg);
            continue;
        }
        char cid[128], ccode[128];
        jstr(resp, "challengeId", cid, sizeof(cid));
        jstr(resp, "challengeCode", ccode, sizeof(ccode));
        if (!cid[0]) { ct_log("挑战码为空"); continue; }

        /* 预计算密码哈希 — 两种哈希方式供服务端校验 (v1.2.3优化: 提前计算避免重复) */
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

        /* OCR自动识别验证码 */
        char captcha[64] = "";
        int ocr_result = try_captcha_ocr(s, user, captcha, sizeof(captcha), &img_data, &img_len);

        if (ocr_result >= 2) {
            /* OCR成功，用识别结果发送登录请求 */
            ct_log("正在发送登录请求 (自动, 尝试%d)...", attempt);
            int result = do_login_send(s, user, final_sha, sha2_pwd, cid, captcha, resp, MAX_RESP);
            /* 清理密码相关的敏感数据 */
            SecureZeroMemory(final_sha, sizeof(final_sha));
            SecureZeroMemory(sha2_pwd, sizeof(sha2_pwd));
            if (img_data) { free(img_data); img_data = NULL; }
            if (result == 1) {
                ct_log("登录成功: userId=%d, tenantId=%d, bondedDevice=%d", s->user_id, s->tenant_id, s->bonded_device);
                free(resp);
                return 1;
            }
            if (result == -1) {
                free(resp);
                return 0;
            }
            /* 验证码错误，继续下一次自动尝试 */
            continue;
        }

        /* OCR失败(图片下载失败或识别失败)，释放图片数据，跳出自动阶段 */
        if (img_data) { free(img_data); img_data = NULL; }
        break;
    }

ct_manual_phase:
    /* ====== 阶段2: 手工输入验证码，最多3次 ====== */
    ct_log("验证码自动识别失败，切换手工输入模式");
    for (int attempt = 1; attempt <= MAX_MANUAL_CAPTCHA_ATTEMPTS; attempt++) {

        /* 获取新的挑战码 */
        if (api_post_noauth(s, "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData",
                            "{}", 2, "application/json", resp, MAX_RESP) < 0) {
            ct_log("获取挑战码失败 (手工, 尝试%d)", attempt);
            continue;
        }
        int code = jint(resp, "code");
        if (code != 0) {
            char msg[256];
            jstr(resp, "msg", msg, sizeof(msg));
            ct_log("获取挑战码错误: %s", msg);
            continue;
        }
        char cid[128], ccode[128];
        jstr(resp, "challengeId", cid, sizeof(cid));
        jstr(resp, "challengeCode", ccode, sizeof(ccode));
        if (!cid[0]) { ct_log("挑战码为空"); continue; }

        /* 预计算密码哈希 */
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

        /* 下载验证码图片用于显示 (OCR结果忽略，仅用于获取图片) */
        char captcha[64] = "";
        try_captcha_ocr(s, user, captcha, sizeof(captcha), &img_data, &img_len);

        /* 弹出验证码窗口，等待用户手工输入 */
        if (!ct_manual_captcha(img_data, img_len, captcha, sizeof(captcha))) {
            ct_log("手工输入为空 (尝试%d)", attempt);
            if (img_data) { free(img_data); img_data = NULL; }
            continue;
        }

        /* 发送登录请求 */
        ct_log("正在发送登录请求 (手工, 尝试%d)...", attempt);
        int result = do_login_send(s, user, final_sha, sha2_pwd, cid, captcha, resp, MAX_RESP);
        /* 清理密码相关的敏感数据 */
        SecureZeroMemory(final_sha, sizeof(final_sha));
        SecureZeroMemory(sha2_pwd, sizeof(sha2_pwd));
        if (img_data) { free(img_data); img_data = NULL; }
        if (result == 1) {
            ct_log("登录成功: userId=%d, tenantId=%d, bondedDevice=%d", s->user_id, s->tenant_id, s->bonded_device);
            free(resp);
            return 1;
        }
        if (result == -1) {
            free(resp);
            return 0;
        }
    }

    /* 自动3次 + 手工3次全部失败 */
    ct_log("验证码识别错误");
    InterlockedExchange(&g_running, 0);
    free(resp);
    return 0;
}
/* ===== common section 6 ===== */
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

#define JSON_MAX_DEPTH 16
#define JSON_MAX_STRING_LEN 8192   /* 字符串值最大长度，防止畸形JSON耗尽资源 */
#define JSON_MAX_KEY_LEN 128       /* 键名最大长度 */
#define JSON_MAX_NUMBER_LEN 64     /* 数字值最大长度 */

static int json_find_key_impl(const char *json, const char *key, const char **vstart, int *vlen, char *vtype, int depth) {
    if (!json || !key || !vstart || !vlen || !vtype || depth > JSON_MAX_DEPTH) return 0;
    size_t key_len = strlen(key);
    if (key_len == 0 || key_len >= JSON_MAX_KEY_LEN) return 0;
    const char *p = json;
    size_t chars_since_quote_check = 0;  /* 用于防止超长未闭合字符串 */

    while (*p) {
        /* 跳过空白字符 */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

        /* 检查是否是字符串键 */
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

            /* 检查是否完全匹配 */
            if (match == key_len && *p == '"') {
                p++;  /* 跳过结束引号 */

                /* 跳过冒号和空白 */
                while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;

                /* 解析值 */
                if (*p == '"') {
                    /* 字符串值 - 添加长度限制防止畸形JSON */
                    *vtype = 's';
                    *vstart = ++p;
                    *vlen = 0;
                    chars_since_quote_check = 0;
                    while (*p && *p != '"' && *vlen < JSON_MAX_STRING_LEN) {
                        if (*p == '\\') { p++; chars_since_quote_check++; }
                        p++;
                        (*vlen)++;
                        chars_since_quote_check++;
                        /* 防止未闭合的引号导致无限循环 */
                        if (chars_since_quote_check > JSON_MAX_STRING_LEN * 2) break;
                    }
                    if (*vlen >= JSON_MAX_STRING_LEN) return 0;  /* 字符串过长，视为畸形 */
                    return 1;
                } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
                    /* 数字值 - 添加长度限制 */
                    *vtype = 'n';
                    *vstart = p;
                    *vlen = 0;
                    while ((*p == '-' || (*p >= '0' && *p <= '9')) && *vlen < JSON_MAX_NUMBER_LEN) {
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
                if (json_find_key_impl(p + 1, key, vstart, vlen, vtype, depth + 1)) {
                    return 1;
                }
                p = end + 1;
            } else {
                break;
            }
        } else if (*p == '[') {
            /* 跳过数组内容 */
            p++;
            int bracket_depth = 1;
            while (*p && bracket_depth > 0) {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') {
                        if (*p == '\\') p++;
                        p++;
                    }
                } else if (*p == '[') {
                    bracket_depth++;
                } else if (*p == ']') {
                    bracket_depth--;
                }
                p++;
            }
        } else {
            p++;
        }
    }
    return 0;
}

int json_find_key(const char *json, const char *key, const char **vstart, int *vlen, char *vtype) {
    return json_find_key_impl(json, key, vstart, vlen, vtype, 0);
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
 * fetch_desktop_list_api - 调用pageDesktop API获取响应
 *
 * 提取公共API调用逻辑，供get_desktop_list和get_desktop_list_light共用。
 *
 * @param s     会话信息
 * @param resp  响应缓冲区
 * @param rsz   缓冲区大小
 * @return      1=成功, 0=失败
 */
int fetch_desktop_list_api(Session *s, char *resp, size_t rsz) {
    char body[] = "{\"getCnt\":20,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}";
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
                 body, strlen(body), "application/json", resp, (int)rsz) < 0) {
        ct_log("获取桌面列表请求失败");
        return 0;
    }
    if (jint(resp, "code") != 0) {
        ct_log("获取桌面列表错误: code=%d", jint(resp, "code"));
        return 0;
    }
    return 1;
}

/**
 * parse_desktop_array - 解析desktopList数组中的桌面对象
 *
 * 提取公共JSON解析逻辑，通过回调函数填充不同类型的结构体。
 * Desktop和DesktopLight结构体布局不同，无法直接共用填充代码，
 * 因此通过回调让调用者自行处理字段赋值。
 *
 * @param resp      API响应JSON
 * @param callback  每解析一个桌面对象时调用的回调函数
 * @param ctx       传递给回调的上下文指针
 * @param max       最大桌面数量
 * @return          实际解析的桌面数量
 */
int parse_desktop_array(const char *resp, ParseDesktopCallback callback, void *ctx, int max) {
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
        callback(obj, end + 1, count, ctx);
        count++;
        p = end + 1;
    }
    return count;
}

void fill_desktop_cb(const char *obj, const char *end, int index, void *ctx) {
    Desktop *desktops = (Desktop *)ctx;
    jstr_range(obj, end, "desktopId", desktops[index].desktop_id, sizeof(desktops[index].desktop_id));
    if (!desktops[index].desktop_id[0])
        jstr_range(obj, end, "objId", desktops[index].desktop_id, sizeof(desktops[index].desktop_id));
    desktops[index].id_hash = fnv1a_hash(desktops[index].desktop_id);
    jstr_range(obj, end, "desktopCode", desktops[index].desktop_code, sizeof(desktops[index].desktop_code));
    char status[64];
    jstr_range(obj, end, "useStatusText", status, sizeof(status));
    desktops[index].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
    ct_log("桌面[%d]: id=%s code=%s 状态=%s 运行中=%d",
             index, desktops[index].desktop_id, desktops[index].desktop_code,
             status, desktops[index].is_active);
}

void fill_desktop_light_cb(const char *obj, const char *end, int index, void *ctx) {
    DesktopLight *desktops = (DesktopLight *)ctx;
    jstr_range(obj, end, "desktopId", desktops[index].desktop_id, sizeof(desktops[index].desktop_id));
    if (!desktops[index].desktop_id[0])
        jstr_range(obj, end, "objId", desktops[index].desktop_id, sizeof(desktops[index].desktop_id));
    desktops[index].id_hash = fnv1a_hash(desktops[index].desktop_id);
    jstr_range(obj, end, "desktopCode", desktops[index].desktop_code, sizeof(desktops[index].desktop_code));
    char status[64];
    jstr_range(obj, end, "useStatusText", status, sizeof(status));
    desktops[index].is_active = (strcmp(status, "\xe8\xbf\x90\xe8\xa1\x8c\xe4\xb8\xad") == 0);
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
int get_desktop_list(Session *s, Desktop *desktops, int max) {
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    if (!fetch_desktop_list_api(s, resp, MAX_RESP)) { free(resp); return 0; }
    ct_log("获取桌面列表成功，正在解析桌面信息");
    int result = parse_desktop_array(resp, fill_desktop_cb, desktops, max);
    free(resp);
    return result;
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
int get_desktop_list_light(Session *s, DesktopLight *desktops, int max) {
    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    if (!fetch_desktop_list_api(s, resp, MAX_RESP)) { free(resp); return 0; }
    int result = parse_desktop_array(resp, fill_desktop_light_cb, desktops, max);
    free(resp);
    return result;
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
int connect_desktop(Session *s, Desktop *d) {
    /* 构建连接请求体 */
    char post[4096];
    snprintf(post, sizeof(post),
             "objId=%s&objType=0&osType=15&deviceId=60&vdCommand=&ipAddress=&macAddress="
             "&deviceCode=%s&deviceName=Chrome%%E6%%B5%%8F%%E8%%A7%%88%%E5%%99%%A8&deviceType=60"
             "&deviceModel=Windows+NT+10.0%%3B+Win64%%3B+x64&appVersion=3.2.0"
             "&sysVersion=Windows+NT+10.0%%3B+Win64%%3B+x64&clientVersion=103020001",
             d->desktop_id, s->device_code);

    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) {
        ct_log("连接桌面请求失败: %s", d->desktop_id);
        return 0;
    }
    if (api_post(s, "https://desk.ctyun.cn:8810/api/desktop/client/connect",
                 post, strlen(post), "application/x-www-form-urlencoded",
                 resp, MAX_RESP) < 0) {
        ct_log("连接桌面请求失败: %s", d->desktop_id);
        free(resp);
        return 0;
    }
    /* [DEBUG] 打印connect API完整响应 */
    ct_log("[%s] [DEBUG] connect API 原始响应(%dB): %.512s", d->desktop_id, (int)strlen(resp), resp);

    if (jint(resp, "code") != 0) {
        char msg[256];
        jstr(resp, "msg", msg, sizeof(msg));
        ct_log("连接桌面错误 [%s]: %s", d->desktop_id, msg);
        free(resp);
        return 0;
    }

    /*
     * 提取连接参数: 按优先级尝试 desktopInfo → shadowDesktopInfo → desktopAnywhereInfo
     *
     * 后启动的桌面(如HA模式/漫游模式)可能 desktopInfo 为 null，
     * 实际连接参数在 shadowDesktopInfo 或 desktopAnywhereInfo 中。
     */
    static const char *info_keys[] = {
        "desktopInfo",
        "shadowDesktopInfo",
        "desktopAnywhereInfo"
    };
    const int info_key_count = 3;

    /* 使用临时缓冲区提取字段，再str_dup到堆上 */
    char *tmp = NULL;
    int tmp_cap = 0;
    for (int ki = 0; ki < info_key_count; ki++) {
        /* 构造搜索模式: "keyname" */
        char key_pattern[64];
        snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", info_keys[ki]);
        const char *di = strstr(resp, key_pattern);
        if (!di) continue;
        di = strchr(di, '{');
        if (!di) continue;
        const char *di_end = find_matching_brace(di);
        if (!di_end) continue;

        int len = (int)(di_end - di + 1);
        /* 复用缓冲区，避免每轮 malloc 造成内存泄漏 */
        if (len + 1 > tmp_cap) {
            free(tmp);
            tmp = (char *)malloc(len + 1);
            if (!tmp) { tmp_cap = 0; free(resp); return 0; }
            tmp_cap = len + 1;
        }

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

        ct_log("[%s] 连接桌面成功: host=%s port=%s clink=%s [来源:%s]",
                 d->desktop_code,
                 d->host ? d->host : "", d->port ? d->port : "",
                 d->clink_host ? d->clink_host : "", info_keys[ki]);

        /* 找到有效host就停止尝试下一个源 */
        if (d->host && d->host[0]) break;

        /* 当前源没有host，释放后尝试下一个 */
        free(d->host); d->host = NULL;
        free(d->port); d->port = NULL;
        free(d->clink_host); d->clink_host = NULL;
        free(d->ca_cert); d->ca_cert = NULL;
        free(d->client_cert); d->client_cert = NULL;
        free(d->client_key); d->client_key = NULL;
        free(d->token); d->token = NULL;
        free(d->tenant_account); d->tenant_account = NULL;
    }
    free(tmp);
    tmp = NULL;
    if (!d->host || !d->host[0]) {
        ct_log("[%s] 错误: 连接响应缺少host字段", d->desktop_code);
        free(d->host); d->host = NULL;
        free(d->port); d->port = NULL;
        free(d->clink_host); d->clink_host = NULL;
        free(d->ca_cert); d->ca_cert = NULL;
        free(d->client_cert); d->client_cert = NULL;
        free(d->client_key); d->client_key = NULL;
        free(d->token); d->token = NULL;
        free(d->tenant_account); d->tenant_account = NULL;
        free(resp);
        return 0;
    }
    if (!d->ca_cert || !d->client_cert || !d->client_key) {
        ct_log("[%s] 错误: 连接响应缺少证书字段", d->desktop_code);
        free(d->host); d->host = NULL;
        free(d->port); d->port = NULL;
        free(d->clink_host); d->clink_host = NULL;
        free(d->ca_cert); d->ca_cert = NULL;
        free(d->client_cert); d->client_cert = NULL;
        free(d->client_key); d->client_key = NULL;
        free(d->token); d->token = NULL;
        free(d->tenant_account); d->tenant_account = NULL;
        free(resp);
        return 0;
    }
    free(resp);
    return 1;
}
/* ===== common section 7 ===== */
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
uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

/**
 * qr - ChaCha20四分之一轮函数
 *
 * ChaCha20的核心运算单元，对4个32位字执行混合运算。
 */
void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
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
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
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
void chacha20_xor(const uint8_t *src, size_t n, const uint8_t key[32],
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
void poly1305(const uint8_t *msg, size_t mlen, const uint8_t key[32], uint8_t tag[16]) {
    /* r值提取: 按RFC 8439 Section 2.5.1，将16字节密钥解码为5个26位limb */
    /* 从密钥中提取r值(前16字节)，进行clamping(固定位清零) */
    /* limb解码方式: 每个limb由4个连续字节的部分位拼接而成， */
    /* 每个limb起始在字节边界上偏移3字节(24位)，实现26位对齐 */
    uint32_t r0 = key[0]|((uint32_t)key[1]<<8)|((uint32_t)key[2]<<16)|((uint32_t)key[3]<<24);
    uint32_t r1 = ((uint32_t)key[3]>>2)|((uint32_t)key[4]<<6)|((uint32_t)key[5]<<14)|((uint32_t)key[6]<<22);
    uint32_t r2 = ((uint32_t)key[6]>>4)|((uint32_t)key[7]<<4)|((uint32_t)key[8]<<12)|((uint32_t)key[9]<<20);
    uint32_t r3 = ((uint32_t)key[9]>>6)|((uint32_t)key[10]<<2)|((uint32_t)key[11]<<10)|((uint32_t)key[12]<<18);
    uint32_t r4 = ((uint32_t)key[12]>>8)|((uint32_t)key[13]<<0)|((uint32_t)key[14]<<8)|((uint32_t)key[15]<<16);
    /* Clamping (RFC 8439 Section 2.5.1): r4[4:0] r3[6:0] r2[6:0] r1[6:2] r0[25:0] */
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
        /* hibit (RFC 8439 Section 2.5.1): 完整块第25位设1，不完整块末尾追加1字节 */
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
void build_poly1305_data(const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t off = 0;
    size_t need = aad_len + 16 + ct_len + 16 + 16;
    if (need > out_cap) { *out_len = 0; return; }
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
#define AEAD_STACK_BUF_SIZE 256

int aead_seal(const uint8_t *pt, size_t ptlen, const uint8_t key[32],
                     const uint8_t nonce[12], uint8_t *ct, uint8_t tag[16]) {
    chacha20_xor(pt, ptlen, key, nonce, 1, ct);
    uint8_t blk0[64];
    chacha20_block(key, 0, nonce, blk0);
    size_t mac_buf_sz = ptlen + 64 + 16;
    uint8_t stack_buf[AEAD_STACK_BUF_SIZE];
    uint8_t *mac_data = (mac_buf_sz <= AEAD_STACK_BUF_SIZE) ? stack_buf : (uint8_t *)malloc(mac_buf_sz);
    if (!mac_data) return 0;
    size_t mac_len = 0;
    build_poly1305_data(NULL, 0, ct, ptlen, mac_data, mac_buf_sz, &mac_len);
    poly1305(mac_data, mac_len, blk0, tag);
    if (mac_data != stack_buf) free(mac_data);
    return 1;
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
void encrypt_data(const char *plaintext, const uint8_t key[32], char *out_b64) {
    size_t plen = strlen(plaintext);
    uint8_t nonce[12], tag[16];
    if (!CryptGenRandom(g_crypt, 12, nonce)) { out_b64[0] = 0; return; }
    size_t total = 12 + plen + 16;
    uint8_t *combined = (uint8_t *)malloc(total);
    if (!combined) { out_b64[0] = 0; return; }
    memcpy(combined, nonce, 12);
    if (!aead_seal((const uint8_t *)plaintext, plen, key, nonce, combined + 12, tag)) {
        free(combined);
        out_b64[0] = 0;
        return;
    }
    memcpy(combined + 12 + plen, tag, 16);
    b64enc(combined, total, out_b64);
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
int aead_open(const uint8_t *ct, size_t ctlen, const uint8_t key[32],
                     const uint8_t nonce[12], uint8_t *pt) {
    if (ctlen < 16) return 0;
    size_t dlen = ctlen - 16;  /* 去除tag后的密文长度 */
    const uint8_t *tag = ct + dlen;

    /* 生成Poly1305密钥并验证认证标签 */
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
int decrypt_data(const char *b64, const uint8_t key[32], char *out, size_t out_sz) {
    size_t b64len = strlen(b64);
    size_t data_cap = b64len / 4 * 3 + 4;
    uint8_t *data = (uint8_t *)malloc(data_cap);
    size_t dlen = b64dec(b64, b64len, data);
    if (dlen == 0) { free(data); ct_log("Base64解码失败"); return 0; }
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
/* ===== common section 8 ===== */

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
void mac_to_fingerprint(const char *mac, char *fp_hex) {
    uint8_t d[32];
    sha256((const uint8_t *)mac, strlen(mac), d);
    static const char hex_lut[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        fp_hex[i * 2]     = hex_lut[d[i] >> 4];
        fp_hex[i * 2 + 1] = hex_lut[d[i] & 0x0f];
    }
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
void get_fingerprint(char *fp_hex) {
    char mac[32] = "";
    DWORD sz = 0;
    if (GetAdaptersInfo(NULL, &sz) != ERROR_BUFFER_OVERFLOW) {
        mac_to_fingerprint("", fp_hex);
        return;
    }
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) {
        mac_to_fingerprint("", fp_hex);
        return;
    }
    PIP_ADAPTER_INFO pinfo = (PIP_ADAPTER_INFO)buf;
    if (GetAdaptersInfo(pinfo, &sz) != ERROR_SUCCESS) {
        free(buf);
        mac_to_fingerprint("", fp_hex);
        return;
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
    ct_log("MAC地址: %s -> 指纹: %s", mac, fp_hex);
}

/**
 * generate_device_code - 根据指纹生成设备码
 *
 * 对指纹做SHA-256哈希，取前16字节格式化为"web_"前缀的设备码。
 * 设备码用于API请求的身份标识，与机器硬件绑定。
 *
 * @param fp_hex  本机指纹(64字符十六进制)
 * @param out     输出设备码缓冲区
 * @param out_sz  输出缓冲区大小
 */
void generate_device_code(const char *fp_hex, char *out, size_t out_sz) {
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
int get_all_macs(char macs[][32], int max_macs) {
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
void derive_key_legacy(const char *fp, const char *salt, uint8_t key[32]) {
    char material[256];
    snprintf(material, sizeof(material), "%s|%s", fp, salt);
    sha256((const uint8_t *)material, strlen(material), key);
}

void derive_key(const char *fp, const char *salt, uint8_t key[32]) {
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
int protect_data_dpapi(const uint8_t *plaintext, DWORD plain_len,
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
int unprotect_data_dpapi(const uint8_t *ciphertext, DWORD cipher_len,
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
/* ===== common section 9 ===== */
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
size_t rsa_oaep_encrypt(const uint8_t *n_bytes, size_t n_len, uint32_t e_val, uint8_t *result) {
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
        ct_log("RSA公钥导入失败: 0x%08X", status);
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
    /* 无论加密成功或失败，都必须销毁密钥句柄 */
    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        ct_log("RSA加密失败: 0x%08X", status);
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
int handle_redq(const uint8_t *msg, size_t mlen, uint8_t *resp, size_t *rlen) {
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
uint8_t initial_payload[INITIAL_PAYLOAD_LEN] = {
    0x52,0x45,0x44,0x51,0x02,0x00,0x00,  /* "REDQ" + 版本2 */
    0x00,0x02,0x00,0x00,0x00,0x1A,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x12,
    0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x04,
    0x08,0x00,0x00
};
/* ===== common section 10 ===== */
/* ======================== WebSocket通信 ======================== */

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
int ws_connect(const char *uri, WSConn *wsc, const char *desktop_code) {
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

    ct_log("[%s] [DEBUG] ws_connect uri=%s host=%s port=%d ssl=%d", desktop_code, uri, host, port, use_ssl);

    /* 创建WinHTTP会话 */
    wsc->hSession = WinHttpOpen(ct_ws_ua(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!wsc->hSession) {
        ct_log("[%s] HTTP会话创建失败: %lu", desktop_code, GetLastError());
        return 0;
    }

    /* 连接到服务器 */
    WCHAR whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    wsc->hConnect = WinHttpConnect(wsc->hSession, whost, (INTERNET_PORT)port, 0);
    if (!wsc->hConnect) {
        ct_log("[%s] HTTP连接失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    /* 创建HTTP请求(准备升级为WebSocket) */
    WCHAR wpath[2048] = {0};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 2048);
    DWORD flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
    wsc->hRequest = WinHttpOpenRequest(wsc->hConnect, L"GET", wpath, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!wsc->hRequest) {
        ct_log("[%s] HTTP请求创建失败: %lu", desktop_code, GetLastError());
        goto cleanup;
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
        ct_log("[%s] WebSocket升级选项设置失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    /* 发送HTTP升级请求 */
    if (!WinHttpSendRequest(wsc->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        ct_log("[%s] HTTP请求发送失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    /* 接收服务端响应 */
    if (!WinHttpReceiveResponse(wsc->hRequest, NULL)) {
        ct_log("[%s] HTTP响应接收失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    /* 验证HTTP 101 Switching Protocols响应 */
    DWORD status_code = 0;
    DWORD sc_len = sizeof(status_code);
    WinHttpQueryHeaders(wsc->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &status_code, &sc_len, NULL);
    if (status_code != 101) {
        ct_log("[%s] WebSocket升级失败，状态码=%lu", desktop_code, status_code);
        goto cleanup;
    }

    /* 完成WebSocket升级 */
    wsc->hWebSocket = WinHttpWebSocketCompleteUpgrade(wsc->hRequest, (DWORD_PTR)NULL);
    if (!wsc->hWebSocket) {
        ct_log("[%s] WebSocket升级完成失败: %lu", desktop_code, GetLastError());
        goto cleanup;
    }

    /* 升级完成后关闭HTTP请求句柄(不再需要) */
    WinHttpCloseHandle(wsc->hRequest);
    wsc->hRequest = NULL;

    DWORD recv_timeout = WS_RECV_TIMEOUT_MS;
    WinHttpSetOption(wsc->hWebSocket, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_timeout, sizeof(recv_timeout));

    ct_log("[%s] WebSocket握手成功", desktop_code);
    return 1;

cleanup:
    if (wsc->hRequest) { WinHttpCloseHandle(wsc->hRequest); wsc->hRequest = NULL; }
    if (wsc->hConnect) { WinHttpCloseHandle(wsc->hConnect); wsc->hConnect = NULL; }
    if (wsc->hSession) { WinHttpCloseHandle(wsc->hSession); wsc->hSession = NULL; }
    return 0;
}

/**
 * ws_send_text - 发送WebSocket文本消息
 *
 * @param wsc   WebSocket连接
 * @param text  文本消息内容
 * @return      0=成功, -1=发送失败(连接可能已断开)
 */
int ws_send_text(WSConn *wsc, const char *text) {
    size_t len = strlen(text);
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                          (void *)text, (DWORD)len);
    return (err == ERROR_SUCCESS) ? 0 : -1;
}

/**
 * ws_send_bytes - 发送WebSocket二进制消息
 *
 * @param wsc   WebSocket连接
 * @param data  二进制数据
 * @param dlen  数据长度
 * @return      0=成功, -1=发送失败(连接可能已断开)
 */
int ws_send_bytes(WSConn *wsc, const uint8_t *data, size_t dlen) {
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                          (void *)data, (DWORD)dlen);
    return (err == ERROR_SUCCESS) ? 0 : -1;
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
int ws_recv(WSConn *wsc, uint8_t *out, size_t outsz, int *is_text) {
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
void ws_close(WSConn *wsc) {
    if (wsc->hWebSocket) {
        WinHttpWebSocketClose(wsc->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(wsc->hWebSocket);
    }
    if (wsc->hRequest) WinHttpCloseHandle(wsc->hRequest);
    if (wsc->hConnect) WinHttpCloseHandle(wsc->hConnect);
    if (wsc->hSession) WinHttpCloseHandle(wsc->hSession);
}

/**
 * ws_send_ping - 发送RFC 6455协议层WebSocket Ping帧
 *
 * 使用WinHTTP原生Ping控制帧(opcode=0x9)，与浏览器自动处理的行为一致。
 * 服务端收到Ping后会自动回复Pong，证明连接活跃。
 */
int ws_send_ping(WSConn *wsc) {
    /*
     * WinHTTP支持真正的WebSocket协议层Ping帧:
     *   WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE = 3 (opcode 0x9)
     *
     * 根据RFC 6455:
     *   - 服务端收到Ping后必须回复Pong(相同payload)
     *   - 这是浏览器自动处理的机制，我们的C程序需要显式调用
     */
    static const uint8_t ping_payload[4] = { 'A','L','I','V' };
    DWORD err = WinHttpWebSocketSend(wsc->hWebSocket,
                                     WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE,
                                     (void *)ping_payload, sizeof(ping_payload));
    return (err == ERROR_SUCCESS) ? 0 : -1;
}
/* ===== common section 11 ===== */
/**
 * build_mouse_move_msg - 构建CLink鼠标移动事件消息
 *
 * 使用SendInfo协议格式封装鼠标位置更新，模拟真实用户操作。
 * 消息格式: [2B type=201] [4B total_len] [4B x] [4B y] [1B buttons]
 *
 * @param out   输出缓冲区(至少15字节)
 * @param osz   缓冲区大小
 * @return      消息长度，失败返回0
 */
size_t build_mouse_move_msg(uint8_t *out, size_t osz) {
    if (osz < 15) return 0;

    /* 随机小偏移坐标(100-300范围)，模拟轻微鼠标抖动 */
    int mx = 100 + (rand() % 200);
    int my = 100 + (rand() % 200);

    /* SendInfo格式: type=201(CLINK_MSG_MOUSE_MOVE), data=9字节 */
    uint16_t msg_type = 201;
    uint32_t total_len = 6 + 9;  /* 6字节头 + 9字节数据 */

    out[0]  = (uint8_t)(msg_type & 0xFF);
    out[1]  = (uint8_t)((msg_type >> 8) & 0xFF);
    out[2]  = (uint8_t)(total_len & 0xFF);
    out[3]  = (uint8_t)((total_len >> 8) & 0xFF);
    out[4]  = (uint8_t)((total_len >> 16) & 0xFF);
    out[5]  = (uint8_t)((total_len >> 24) & 0xFF);

    /* 鼠标数据: x(4B LE) + y(4B LE) + button_state(1B=0无按键) */
    out[6]  = (uint8_t)(mx & 0xFF);
    out[7]  = (uint8_t)((mx >> 8) & 0xFF);
    out[8]  = (uint8_t)((mx >> 16) & 0xFF);
    out[9]  = (uint8_t)((mx >> 24) & 0xFF);
    out[10] = (uint8_t)(my & 0xFF);
    out[11] = (uint8_t)((my >> 8) & 0xFF);
    out[12] = (uint8_t)((my >> 16) & 0xFF);
    out[13] = (uint8_t)((my >> 24) & 0xFF);
    out[14] = 0;  /* 无按键按下 */

    return 15;
}
/* ===== common section 12 ===== */
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
size_t build_send_info_msg(uint16_t type_val, const uint8_t *data, size_t dlen, int is_build_msg, uint8_t *out) {
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
size_t build_user_payload(const Session *s, uint8_t *out, size_t out_sz) {
    char user_json[512];
    snprintf(user_json, sizeof(user_json),
             "{\"type\":1,\"userName\":\"%s\",\"userInfo\":\"\",\"userId\":%d}",
             s->user_account, s->user_id);
    size_t jlen = strlen(user_json);
    size_t need = 6 + 8 + jlen;
    if (need > out_sz) return 0;
    return build_send_info_msg(118, (const uint8_t *)user_json, jlen, 1, out);
}
/* ===== common section 13 ===== */
/*
 * Read one complete WebSocket message, reassembling continuation fragments.
 * Up to outsz bytes are copied into out; any overflow is drained/discarded.
 * Returns:  0 = full message read (total set; pover=1 if truncated)
 *          -1 = connection closed / error
 *          -2 = receive timeout (partial data may be present if total>0)
 */
int ws_read_frame(WSConn *wsc, uint8_t *out, size_t outsz,
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
