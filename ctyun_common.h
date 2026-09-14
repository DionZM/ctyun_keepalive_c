#ifndef CTYUN_COMMON_H
#define CTYUN_COMMON_H

/* ctyun_common.h - ctyun_keepalive / ctyun_points 共享公共层
 * 由 gen_split.py 从两程序中抽取，禁止手工拼装业务逻辑。 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iphlpapi.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

#ifndef WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE
#define WINHTTP_WEB_SOCKET_PING_BUFFER_TYPE         3
#endif
#ifndef WINHTTP_WEB_SOCKET_PONG_BUFFER_TYPE
#define WINHTTP_WEB_SOCKET_PONG_BUFFER_TYPE         4
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define MAX_RESP                65536
#define CAPTCHA_IMG_BUF         65536
#define OCR_RESP_BUF            4096
#define WS_SEND_DELAY_MS        100
#define WS_PING_INTERVAL_MS     15000
#define WS_MOUSE_INTERVAL_MS    30000
#define WS_RECV_BUF_SIZE        8192
#define DNS_RESOLVE_TIMEOUT_MS  10000
#define WINHTTP_CONNECT_TIMEOUT_MS  15000
#define WINHTTP_SEND_TIMEOUT_MS     30000
#define WINHTTP_RECEIVE_TIMEOUT_MS  30000
#ifndef WS_RECV_TIMEOUT_MS
#define WS_RECV_TIMEOUT_MS      30000   /* points 编译时用 /DWS_RECV_TIMEOUT_MS=60000 覆盖 */
#endif
#define OCR_SERVICE_URL         "https://orc.1999111.xyz/ocr"
#define MAX_LOGIN_ATTEMPTS      3
#define MAX_MANUAL_CAPTCHA_ATTEMPTS 3
#define DESKTOP_CLEANUP_MS      50
#define INITIAL_PAYLOAD_LEN     42      /* REDQ 初始二进制消息固定长度 */

/* ---- 共享数据结构 ---- */
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
    HANDLE start_event;
    volatile LONG keepalive_started;
    volatile LONG missing_logged;
    uint32_t id_hash;
} Desktop;

typedef struct {
    char desktop_id[64];
    char desktop_code[64];
    int is_active;
    uint32_t id_hash;
} DesktopLight;

typedef struct {
    char device_code[128];
    char secret_key[128];
    char user_name[128];
    char user_account[128];
    char phone_number[128];
    int user_id;
    int tenant_id;
    int logged_in;
    int bonded_device;
} Session;

typedef int (*SseEventCallback)(const char *data, size_t dlen, void *userdata);
typedef void (*ParseDesktopCallback)(const char *obj, const char *end, int index, void *ctx);

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    HINTERNET hWebSocket;
} WSConn;

/* ---- 公共全局(定义在 ctyun_common.c) ---- */
extern HCRYPTPROV g_crypt;
extern HINTERNET g_inet;
extern BCRYPT_ALG_HANDLE g_rsa_alg;
extern volatile LONG g_running;
extern const char HEX_LUT[17];
extern uint8_t initial_payload[INITIAL_PAYLOAD_LEN];

/* ---- 由各主程序实现的钩子 ---- */
void ct_log(const char *fmt, ...);
int ct_manual_captcha_mode(void);
int ct_manual_captcha(const uint8_t *img, int len, char *out, size_t sz);
const wchar_t *ct_ws_ua(void);

/* ---- 公共函数原型 ---- */
int crypto_init(void);
void sha256(const uint8_t *d, size_t n, uint8_t *out);
size_t url_encode(const char *in, char *out, size_t out_sz);
void sha256_hex(const char *s, char *out);
void md5_hex(const char *s, char *out);
size_t b64enc(const uint8_t *in, size_t n, char *out);
int b64val(char c);
size_t b64dec(const char *in, size_t n, uint8_t *out);
char *jstr(const char *j, const char *k, char *buf, size_t bsz);
int jint(const char *j, const char *k);
int jbool(const char *j, const char *k);
char *jstr_range(const char *start, const char *end, const char *k, char *buf, size_t bsz);
char *str_dup(const char *s);
int json_find_key(const char *json, const char *key, const char **vstart, int *vlen, char *vtype);
void desktop_free_certs(Desktop *d);
void desktop_cleanup(Desktop *d);
int http_init(void);
int http_req(const char *method, const char *url, const char *body, size_t blen, const char *ct, const char **hdrs, int nhdrs, char *resp, size_t rsz);
int http_get_binary(const char *url, const char **hdrs, int nhdrs, uint8_t *resp, size_t rsz);
int http_req_with_cookies(const char *method, const char *url, const char *body, size_t blen, const char *ct, const char **hdrs, int nhdrs, const char *cookies_in, char *cookie_out, size_t cookie_sz, char *resp, size_t rsz, int *status_out);
int http_get_via_curl(const char *url, const char **hdrs, int nhdrs, const char *cookies_in, char *cookie_out, size_t cookie_sz, char *resp, size_t rsz, int *status_out, char *location_out, size_t loc_sz);
int http_get_with_winhttp(const char *url, const char **hdrs, int nhdrs, const char *cookies_in, char *resp, size_t rsz, int *status_out, char *location_out, size_t loc_sz);
int http_read_sse(const char *url, const char *body, size_t blen, const char **hdrs, int nhdrs, const char *cookies, SseEventCallback callback, void *userdata);
void make_base_headers(const Session *s, const char **hdrs, int *nhdrs);
void make_sig_headers(const Session *s, const char **hdrs, int *nhdrs);
int api_post_noauth(const Session *s, const char *url, const char *body, size_t blen, const char *ct, char *resp, size_t rsz);
int api_post(const Session *s, const char *url, const char *body, size_t blen, const char *ct, char *resp, size_t rsz);
int api_get(const Session *s, const char *url, char *resp, size_t rsz);
int api_get_binary(const Session *s, const char *url, uint8_t *resp, size_t rsz);
int try_captcha_ocr(const Session *s, const char *user, char *captcha_out, size_t co_sz, uint8_t **img_out, int *img_len_out);
int do_login_send(Session *s, const char *user, const char *final_sha, const char *sha2_pwd, const char *cid, const char *captcha, char *resp, size_t resp_sz);
int do_login(Session *s, const char *user, const char *pwd);
int fetch_desktop_list_api(Session *s, char *resp, size_t rsz);
int parse_desktop_array(const char *resp, ParseDesktopCallback callback, void *ctx, int max);
void fill_desktop_cb(const char *obj, const char *end, int index, void *ctx);
void fill_desktop_light_cb(const char *obj, const char *end, int index, void *ctx);
int get_desktop_list(Session *s, Desktop *desktops, int max);
int get_desktop_list_light(Session *s, DesktopLight *desktops, int max);
int connect_desktop(Session *s, Desktop *d);
uint32_t rotl32(uint32_t v, int n);
void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]);
void chacha20_xor(const uint8_t *src, size_t n, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *out);
void poly1305(const uint8_t *msg, size_t mlen, const uint8_t key[32], uint8_t tag[16]);
void build_poly1305_data(const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, uint8_t *out, size_t out_cap, size_t *out_len);
int aead_seal(const uint8_t *pt, size_t ptlen, const uint8_t key[32], const uint8_t nonce[12], uint8_t *ct, uint8_t tag[16]);
void encrypt_data(const char *plaintext, const uint8_t key[32], char *out_b64);
int aead_open(const uint8_t *ct, size_t ctlen, const uint8_t key[32], const uint8_t nonce[12], uint8_t *pt);
int decrypt_data(const char *b64, const uint8_t key[32], char *out, size_t out_sz);
void mac_to_fingerprint(const char *mac, char *fp_hex);
void get_fingerprint(char *fp_hex);
void generate_device_code(const char *fp_hex, char *out, size_t out_sz);
int get_all_macs(char macs[][32], int max_macs);
void derive_key_legacy(const char *fp, const char *salt, uint8_t key[32]);
void derive_key(const char *fp, const char *salt, uint8_t key[32]);
int protect_data_dpapi(const uint8_t *plaintext, DWORD plain_len, const char *entropy, uint8_t **out, DWORD *out_len);
int unprotect_data_dpapi(const uint8_t *ciphertext, DWORD cipher_len, const char *entropy, uint8_t **out, DWORD *out_len);
size_t rsa_oaep_encrypt(const uint8_t *n_bytes, size_t n_len, uint32_t e_val, uint8_t *result);
int handle_redq(const uint8_t *msg, size_t mlen, uint8_t *resp, size_t *rlen);
int ws_connect(const char *uri, WSConn *wsc, const char *desktop_code);
int ws_send_text(WSConn *wsc, const char *text);
int ws_send_bytes(WSConn *wsc, const uint8_t *data, size_t dlen);
int ws_recv(WSConn *wsc, uint8_t *out, size_t outsz, int *is_text);
int ws_read_frame(WSConn *wsc, uint8_t *out, size_t outsz, size_t *ptotal, int *pis_text, int *pover);
void ws_close(WSConn *wsc);
int ws_send_ping(WSConn *wsc);
size_t build_mouse_move_msg(uint8_t *out, size_t osz);
size_t build_send_info_msg(uint16_t type_val, const uint8_t *data, size_t dlen, int is_build_msg, uint8_t *out);
size_t build_user_payload(const Session *s, uint8_t *out, size_t out_sz);

#endif /* CTYUN_COMMON_H */
