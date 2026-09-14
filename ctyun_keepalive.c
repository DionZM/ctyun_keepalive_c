/*
 * ctyun_keepalive.c - 天翼云电脑保活客户端 (C语言版) v1.5.0
 *
 * 公共逻辑(HTTP/加密/登录/WebSocket/桌面解析等)见 ctyun_common.c / ctyun_common.h。
 * v1.5.0 起常驻守护内置"积分调度线程"：每日05:00以无窗口子进程方式拉起
 * ctyun_points.exe(登录1002 + eaichat 1004 + 挂机1003)，守护晚启动时当天自动补跑；
 * 不再依赖 Windows 计划任务，直接运行本程序即完成全部部署。
 *
 * 编译 (MSVC x64):
 *   cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ^
 *      ctyun_common.c ctyun_keepalive.c /Fe:ctyun_keepalive.exe ^
 *      /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG ^
 *      winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ^
 *      ole32.lib windowscodecs.lib user32.lib gdi32.lib shell32.lib psapi.lib
 */

#include "ctyun_common.h"
#include <psapi.h>          /* Process Status API (内存信息) */
#include <ole2.h>           /* COM (CreateStreamOnHGlobal) */
#include <wincodec.h>       /* WIC (图像解码) */

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")

#define APP_VERSION   "1.5.0"

#define MAX_DESKTOPS  10
#define MAX_THREADS   (MAX_DESKTOPS + 3)
#define CHECK_INTERVAL 180
#define THREAD_STACK  131072
#define MAX_SMS_ATTEMPTS 3
#define MAX_AUTO_CAPTCHA_FAILS 3
#define WS_KEEPALIVE_MS     45000
#define WS_RECONNECT_MS     5000
#define CAPTCHA_CLOSE_MS    100

/* ======================== 全局变量 ======================== */



/* 全局trim计数器，用于多线程间协调trim_working_set调用频率 */
static volatile LONG g_trim_counter = 0;

/* 全局认证失效标志，当API返回token无效时设置，通知所有线程优雅退出 */
static volatile LONG g_auth_expired = 0;




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

/* /testsched 自测钩子: 只跑积分调度线程一轮(不登录/不保活)，验证完即退出 */
static int g_test_sched = 0;



/* ================ 优化1.2.4新增: 内存跟踪和WinHTTP参数 ================ */
/* 上次trim_working_set调用时的内存使用量(KB) */
static SIZE_T g_last_trim_memory_kb = 0;
/* 内存增长阈值(KB) - 超过此值才触发trim */
#define TRIM_MEMORY_THRESHOLD_KB (2*1024)  /* 2MB */
/* WinHTTP超时设置(毫秒) */
/* =============================================================== */

#define WS_RECONNECT_MS    5000    /* WebSocket重连间隔(毫秒) */
#define CAPTCHA_CLOSE_MS   100     /* 验证码窗口关闭等待时间(毫秒) */
#define LOG_FLUSH_MS       1000    /* 日志冲刷间隔(毫秒) */
#define LOG_MAX_SIZE       (2*1024*1024) /* 日志文件最大大小(2MB) */
#define LOG_KEEP_SIZE      (1*1024*1024)  /* 日志截断保留大小(1MB) */
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
        if ((DWORD)(GetTickCount() - g_log_last_flush) >= LOG_FLUSH_MS) {
            fflush(g_log_file);
            g_log_last_flush = GetTickCount();
        }
        /* 检查文件大小，超过LOG_MAX_SIZE时截断保留末尾LOG_KEEP_SIZE */
        if (g_log_size > LOG_MAX_SIZE) {
            fflush(g_log_file);
            fclose(g_log_file);
            g_log_file = NULL;
            /* 读取文件末尾LOG_KEEP_SIZE字节 */
            FILE *rf = fopen(g_log_path, "rb");
            if (rf) {
                fseek(rf, 0, SEEK_END);
                long fsize = ftell(rf);
                long keep = LOG_KEEP_SIZE;
                long skip = fsize - keep;
                if (skip < 0) {
                    /* 文件小于保留大小时，从头开始读整个文件 */
                    skip = 0;
                    keep = fsize;
                }
                fseek(rf, skip, SEEK_SET);
                /* 截转时只保留最新的LOG_KEEP_SIZE，避免在内存中重新处理整个日志文件 */
                char *tail = (char *)malloc(keep);
                size_t nread = tail ? fread(tail, 1, keep, rf) : 0;
                fclose(rf);
                /* 重写文件，只保留末尾部分 */
                g_log_file = open_log_file(g_log_path, "w", &g_log_size);
                if (g_log_file && tail) {
                    /* tail 开头通常落在某条日志行中间，跳过首个不完整行，
                     * 避免写入半行日志造成后续解析/阅读混乱 */
                    size_t start_off = 0;
                    const char *nl = (const char *)memchr(tail, '\n', nread);
                    if (nl && (size_t)(nl - tail) + 1 < nread) {
                        start_off = (size_t)(nl - tail) + 1;
                    }
                    fwrite(tail + start_off, 1, nread - start_off, g_log_file);
                    g_log_size = (long)(nread - start_off);
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
        SIZE_T before_kb = current_memory_kb;
        SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            g_last_trim_memory_kb = pmc.WorkingSetSize / 1024;
            log_line("内存优化: %zuKB -> %zuKB", before_kb, g_last_trim_memory_kb);
        }
    }
}

/* ======================== 验证码图片窗口显示 ======================== */

static HWND g_captcha_hwnd = NULL;
static HBITMAP g_captcha_hbm = NULL;
static volatile LONG g_captcha_wnd_ready = 0;
static CRITICAL_SECTION g_captcha_cs;

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
    /* RPC_E_CHANGED_MODE表示COM已以不同线程模式初始化，此时无需CoUninitialize */
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        InterlockedExchange(&g_captcha_wnd_ready, 2);
        return 0;
    }

    HBITMAP hbm = g_captcha_hbm;

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
    EnterCriticalSection(&g_captcha_cs);
    if (g_captcha_hwnd) { LeaveCriticalSection(&g_captcha_cs); return; }

    g_captcha_hbm = decode_image_to_hbitmap(img_data, img_len);
    if (!g_captcha_hbm) { LeaveCriticalSection(&g_captcha_cs); return; }

    InterlockedExchange(&g_captcha_wnd_ready, 0);
    CreateThread(NULL, THREAD_STACK, captcha_wnd_thread, NULL, 0, NULL);
    LeaveCriticalSection(&g_captcha_cs);

    while (!InterlockedCompareExchange(&g_captcha_wnd_ready, 0, 0)) Sleep(20);
}

static void close_captcha_window(void) {
    EnterCriticalSection(&g_captcha_cs);
    if (g_captcha_hwnd) {
        PostMessageW(g_captcha_hwnd, WM_CLOSE, 0, 0);
        g_captcha_hwnd = NULL;
    }
    LeaveCriticalSection(&g_captcha_cs);
    Sleep(CAPTCHA_CLOSE_MS);
    EnterCriticalSection(&g_captcha_cs);
    if (g_captcha_hbm) {
        DeleteObject(g_captcha_hbm);
        g_captcha_hbm = NULL;
    }
    LeaveCriticalSection(&g_captcha_cs);
}

static int read_manual_captcha(char *out, size_t out_sz) {
    printf("验证码自动识别失败，请手工输入："); fflush(stdout);
    if (!fgets(out, (int)out_sz, stdin)) return 0;
    out[strcspn(out, "\r\n")] = 0;
    return out[0] ? 1 : 0;
}
/**
 * read_captcha_manual - 显示验证码窗口并读取手工输入
 *
 * 封装手工输入验证码的完整流程:
 * 1. 显示验证码图片窗口
 * 2. 提示用户手工输入
 * 3. 读取用户输入
 * 4. 关闭验证码窗口
 *
 * @param img_data  验证码图片数据
 * @param img_len   图片数据长度
 * @param out       输出缓冲区
 * @param out_sz    缓冲区大小
 * @return          1=成功读取非空输入, 0=读取失败或为空
 */
static int read_captcha_manual(const uint8_t *img_data, int img_len, char *out, size_t out_sz) {
    if (img_data && img_len > 0) {
        show_captcha_window(img_data, img_len);
    }
    out[0] = 0;
    int ok = read_manual_captcha(out, out_sz);
    close_captcha_window();
    return ok;
}

/* ======================== 短信验证码与设备绑定 ======================== */

/**
 * send_sms_request - 发送短信验证码请求
 *
 * 封装短信验证码的GET请求，供自动/手工两个阶段共用。
 *
 * @param s       会话信息(需已登录)
 * @param phone   手机号
 * @param captcha 图形验证码文本
 * @return        1=成功发送, 0=验证码错误, -1=请求发送失败
 */
static int send_sms_request(const Session *s, const char *phone, const char *captcha) {
    char url[512];
    snprintf(url, sizeof(url),
             "https://desk.ctyun.cn:8810/api/cdserv/client/device/getSmsCode?mobilePhone=%s&captchaCode=%s",
             phone, captcha);

    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return -1;
    int rlen = api_get(s, url, resp, MAX_RESP);
    if (rlen < 0) {
        free(resp);
        return -1;
    }
    int code = jint(resp, "code");
    free(resp);
    if (code == 0) {
        return 1;
    }
    return 0;
}

/**
 * send_sms_code - 发送短信验证码
 *
 * 流程分两个阶段:
 *
 * 阶段1 — 自动OCR识别 (最多3次):
 *   1. 下载短信验证码图片并OCR识别
 *   2. OCR成功则发送短信验证码请求，失败则进入阶段2
 *   3. 请求失败(验证码错误)则继续下一次自动尝试
 *
 * 阶段2 — 手工输入 (最多3次):
 *   1. 下载新的验证码图片用于显示
 *   2. 弹出窗口显示验证码，用户手工输入
 *   3. 发送短信验证码请求，失败则继续下一次手工尝试
 *
 * 注意: 短信验证码的OCR错误计数独立于登录验证码，从零开始计算。
 *
 * @param s     会话信息(需已登录)
 * @param phone 手机号
 * @return      1=成功发送, 0=发送失败
 */
static int send_sms_code(const Session *s, const char *phone) {
    uint8_t *img_data = NULL;
    int img_len = 0;

    /* ====== 阶段1: 自动OCR识别，最多3次 ====== */
    for (int attempt = 1; attempt <= MAX_SMS_ATTEMPTS; attempt++) {
        char captcha[64] = "";

        /* OCR自动识别短信验证码 (user=NULL表示短信验证码URL) */
        int ocr_result = try_captcha_ocr(s, NULL, captcha, sizeof(captcha), &img_data, &img_len);

        if (ocr_result >= 2) {
            /* OCR成功，用识别结果发送短信验证码请求 */
            log_line("正在发送短信验证码请求 (自动, 尝试%d)...", attempt);
            int result = send_sms_request(s, phone, captcha);
            if (img_data) { free(img_data); img_data = NULL; }
            if (result == 1) {
                log_line("短信验证码已发送至 %s", phone);
                return 1;
            }
            /* 验证码错误，继续下一次自动尝试 */
            continue;
        }

        /* OCR失败(图片下载失败或识别失败)，释放图片数据，跳出自动阶段 */
        if (img_data) { free(img_data); img_data = NULL; }
        break;
    }

    /* ====== 阶段2: 手工输入验证码，最多3次 ====== */
    log_line("短信验证码自动识别失败，切换手工输入模式");
    for (int attempt = 1; attempt <= MAX_MANUAL_CAPTCHA_ATTEMPTS; attempt++) {
        char captcha[64] = "";

        /* 下载验证码图片用于显示 (OCR结果忽略，仅用于获取图片) */
        try_captcha_ocr(s, NULL, captcha, sizeof(captcha), &img_data, &img_len);

        /* 弹出验证码窗口，等待用户手工输入 */
        if (!read_captcha_manual(img_data, img_len, captcha, sizeof(captcha))) {
            log_line("手工输入为空 (尝试%d)", attempt);
            if (img_data) { free(img_data); img_data = NULL; }
            continue;
        }

        /* 发送短信验证码请求 */
        log_line("正在发送短信验证码请求 (手工, 尝试%d)...", attempt);
        int result = send_sms_request(s, phone, captcha);
        if (img_data) { free(img_data); img_data = NULL; }
        if (result == 1) {
            log_line("短信验证码已发送至 %s", phone);
            return 1;
        }
    }

    /* 自动3次 + 手工3次全部失败 */
    log_line("验证码识别错误");
    InterlockedExchange(&g_running, 0);
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

    char *resp = (char *)malloc(MAX_RESP);
    if (!resp) return 0;
    int rlen = api_post(s, url, "", 0, "application/json", resp, MAX_RESP);
    if (rlen < 0) {
        log_line("设备绑定请求失败");
        free(resp);
        return 0;
    }
    int code = jint(resp, "code");
    if (code == 0) {
        log_line("设备绑定成功");
        free(resp);
        return 1;
    }
    char msg[256];
    jstr(resp, "msg", msg, sizeof(msg));
    log_line("设备绑定错误: %s", msg);
    free(resp);
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
    if (!fgets(vcode, sizeof(vcode), stdin)) { vcode[0] = 0; }
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

/**
 * decrypt_and_login - 从加密的accounts数据中解密凭据并尝试登录
 *
 * 公共逻辑: 提取user_account/password/device_code，解密后自动登录。
 * 供try_decrypt_config_legacy和try_decrypt_config_dpapi共用。
 * 登录成功时，顺便把账号明文+密码SHA256输出(供对话线程复用，避免重复输入)。
 *
 * @param s            会话信息(输出)
 * @param json         包含accounts的JSON字符串
 * @param key          ChaCha20-Poly1305解密密钥
 * @param out_user     输出账号(可NULL)
 * @param out_pass_sha 输出SHA256(密码)(可NULL)
 * @return             1=登录成功, 2=解密成功但登录失败, 0=解密失败
 */
static int decrypt_and_login(Session *s, const char *json, const uint8_t key[32],
                              char *out_user, char *out_pass_sha) {
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

    char user[256], pass[256], devc[256];
    int du = decrypt_data(ua, key, user, sizeof(user));
    int dp = decrypt_data(pw, key, pass, sizeof(pass));
    int dd = decrypt_data(dc, key, devc, sizeof(devc));

    int ret = 0;
    if (du && dp && dd) {
        strncpy(s->device_code, devc, sizeof(s->device_code) - 1);
        s->device_code[sizeof(s->device_code) - 1] = '\0';
        strncpy(s->phone_number, user, sizeof(s->phone_number) - 1);
        s->phone_number[sizeof(s->phone_number) - 1] = '\0';
        /* 输出账号+密码SHA256(明文随后清零)。即使登录失败也输出，
         * 这样对话线程可凭哈希自行登录(可能服务端临时故障导致保活登录失败，
         * 但对话登录是独立体系)。 */
        if (out_user) { strncpy(out_user, user, 127); out_user[127] = 0; }
        if (out_pass_sha) { sha256_hex(pass, out_pass_sha); }
        if (do_login(s, user, pass)) {
            ret = 1;
        } else {
            log_line("自动登录失败，尝试手动输入");
            ret = 2;
        }
    }
    SecureZeroMemory(pass, sizeof(pass));
    SecureZeroMemory(user, sizeof(user));
    SecureZeroMemory(devc, sizeof(devc));
    return ret;
}
/**
 * try_decrypt_config_legacy - v1.x 配置解密 (ChaCha20-Poly1305)
 *
 * 从config.json中提取salt和加密的账号信息，
 * 用给定指纹派生密钥，尝试解密并自动登录。
 */
static int try_decrypt_config_legacy(Session *s, const char *content, const char *fp,
                                      char *out_user, char *out_pass_sha) {
    char salt[65];
    jstr(content, "salt", salt, sizeof(salt));
    if (!salt[0]) return 0;

    uint8_t key[32];
    derive_key_legacy(fp, salt, key);
    int r = decrypt_and_login(s, content, key, out_user, out_pass_sha);
    SecureZeroMemory(key, sizeof(key));
    return r;
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
static int try_decrypt_config_dpapi(Session *s, const char *content, const char *fp,
                                     char *out_user, char *out_pass_sha) {
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
    if (dpapi_ct_len == 0) { free(dpapi_ct); log_line("DPAPI Base64解码失败"); return 0; }

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

    uint8_t key[32];
    derive_key(fp, salt, key);

    int result = decrypt_and_login(s, inner_json, key, out_user, out_pass_sha);
    SecureZeroMemory(key, sizeof(key));
    free(inner_json);
    return result;
}

/**
 * try_decrypt_config - 统一配置解密入口
 *
 * 优先尝试v2.0 DPAPI格式，失败时回退到v1.x ChaCha20格式
 */
static int try_decrypt_config(Session *s, const char *content, const char *fp,
                               char *out_user, char *out_pass_sha) {
    /* 先尝试v2.0 DPAPI格式 */
    int result = try_decrypt_config_dpapi(s, content, fp, out_user, out_pass_sha);
    if (result != 0) return result;

    /* 回退到v1.x传统格式 */
    return try_decrypt_config_legacy(s, content, fp, out_user, out_pass_sha);
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
 * @param s             会话信息(输出)
 * @param out_user      输出: 账号(明文)，可NULL。用于对话线程复用账号
 * @param out_pass_sha  输出: SHA256(密码)的64hex，可NULL。对话线程只需哈希登录
 *                      (传非NULL时，明文密码会在本函数内算完SHA后立即清零，
 *                       不长期驻留；隐私模式下也无需对话线程重复输入密码)
 * @return              1=成功, 0=失败
 */
static int resolve_credentials(Session *s, char *out_user, char *out_pass_sha) {
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
    long fsize = 0;
    if (f) {
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        if (fsize <= 0) { fclose(f); f = NULL; }
    }
    if (f) {
        fseek(f, 0, SEEK_SET);
        char *content = (char *)malloc(fsize + 1);
        if (!content) { fclose(f); f = NULL; }
        if (content) {
            size_t clen = fread(content, 1, fsize, f);
            content[clen] = 0;
            fclose(f);

            int dec_result = try_decrypt_config(s, content, fp, out_user, out_pass_sha);
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
                    int r = try_decrypt_config(s, content, alt_fp, out_user, out_pass_sha);
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
        }
    } else {
        log_line("配置文件不存在: %s", config_path);
    }

    char user[128], pass[128];
    printf("账户: "); fflush(stdout);
    if (!fgets(user, sizeof(user), stdin)) { user[0] = 0; }
    user[strcspn(user, "\r\n")] = 0;
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
        if (!CryptGenRandom(g_crypt, 16, rnd)) {
            log_line("警告: 随机数生成失败，使用指纹生成设备码");
            generate_device_code(fp, s->device_code, sizeof(s->device_code));
        } else {
            char dc_hex[33];
            for (int i = 0; i < 16; i++) sprintf(dc_hex + i * 2, "%02x", rnd[i]);
            snprintf(s->device_code, sizeof(s->device_code), "web_%s", dc_hex);
        }
    } else {
        generate_device_code(fp, s->device_code, sizeof(s->device_code));
    }

    strncpy(s->phone_number, user, sizeof(s->phone_number) - 1);
    s->phone_number[sizeof(s->phone_number) - 1] = '\0';
    if (!do_login(s, user, pass)) { SecureZeroMemory(pass, sizeof(pass)); return 0; }

    if (!s->bonded_device && !do_device_binding(s)) {
        log_line("需要设备绑定但绑定失败");
        SecureZeroMemory(pass, sizeof(pass));
        return 0;
    }

    if (!g_privacy) {
        char salt[33];
        BYTE salt_bytes[16];
        if (!CryptGenRandom(g_crypt, 16, salt_bytes)) {
            log_line("警告: salt生成失败");
            SecureZeroMemory(pass, sizeof(pass));
            return 0;
        }
        for (int i = 0; i < 16; i++) sprintf(salt + i * 2, "%02x", salt_bytes[i]);
        salt[32] = 0;

        uint8_t key[32];
        derive_key(fp, salt, key);

        char enc_user[2048], enc_pass[2048], enc_dc[2048];
        encrypt_data(user, key, enc_user);
        encrypt_data(pass, key, enc_pass);
        encrypt_data(s->device_code, key, enc_dc);

        size_t inner_need = 256 + strlen(enc_user) + strlen(enc_pass) + strlen(enc_dc);
        char *inner_json = (char *)malloc(inner_need);
        int dpapi_ok = 0;
        uint8_t *dpapi_ct = NULL;
        DWORD dpapi_len = 0;

        if (inner_json) {
            snprintf(inner_json, inner_need,
                     "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]}",
                     salt, enc_user, enc_pass, enc_dc);

            dpapi_ok = protect_data_dpapi(
                (const uint8_t *)inner_json, (DWORD)strlen(inner_json),
                fp, &dpapi_ct, &dpapi_len
            );
            free(inner_json);
        }

        /* 保留已有的 chat_dpapi 字段(避免覆盖 chat 会话状态) */
        char chat_dpapi_val[32768] = "";
        {
            FILE *rf = fopen(config_path, "rb");
            if (rf) {
                fseek(rf, 0, SEEK_END);
                long rfsz = ftell(rf);
                if (rfsz > 0 && rfsz < 1024 * 1024) {
                    fseek(rf, 0, SEEK_SET);
                    char *rold = (char *)malloc(rfsz + 1);
                    if (rold) {
                        size_t rrd = fread(rold, 1, rfsz, rf);
                        rold[rrd] = 0;
                        const char *cdp = strstr(rold, "\"chat_dpapi\"");
                        if (cdp) {
                            cdp += strlen("\"chat_dpapi\"");
                            while (*cdp == ' ' || *cdp == ':') cdp++;
                            if (*cdp == '"') {
                                cdp++;
                                const char *cdpe = strchr(cdp, '"');
                                if (cdpe) {
                                    size_t vlen = (size_t)(cdpe - cdp);
                                    if (vlen < sizeof(chat_dpapi_val)) {
                                        memcpy(chat_dpapi_val, cdp, vlen);
                                        chat_dpapi_val[vlen] = 0;
                                    }
                                }
                            }
                        }
                        free(rold);
                    }
                }
                fclose(rf);
            }
        }

        f = fopen(config_path, "w");
        if (f) {
            /* 构造 chat_dpapi 片段(若有) */
            char chat_dpapi_field[32800] = "";
            if (chat_dpapi_val[0]) {
                snprintf(chat_dpapi_field, sizeof(chat_dpapi_field),
                         ",\"chat_dpapi\":\"%s\"", chat_dpapi_val);
            }
            if (dpapi_ok && dpapi_ct) {
                size_t b64_need = ((size_t)dpapi_len + 2) / 3 * 4 + 1;  // +1 for '\0'
                char *dpapi_b64 = (char *)malloc(b64_need);
                if (dpapi_b64) {
                    b64enc(dpapi_ct, dpapi_len, dpapi_b64);
                    fprintf(f, "{\"version\":2,\"dpapi\":\"%s\"%s}", dpapi_b64, chat_dpapi_field);
                    free(dpapi_b64);
                    log_line("配置已保存(v2.0 DPAPI加密)");
                } else {
                    fprintf(f, "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]%s}",
                            salt, enc_user, enc_pass, enc_dc, chat_dpapi_field);
                    log_line("内存不足，已保存(v1.x ChaCha20加密)");
                    dpapi_ok = 0;
                }
                LocalFree(dpapi_ct);
            } else {
                fprintf(f, "{\"salt\":\"%s\",\"accounts\":[{\"user_account\":\"%s\",\"password\":\"%s\",\"device_code\":\"%s\"}]%s}",
                        salt, enc_user, enc_pass, enc_dc, chat_dpapi_field);
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

    /* 把账号明文和密码SHA256输出给main，供对话线程复用(隐私模式下也不必重复输入)。
     * 明文密码在此算完SHA后立即清零，不外泄明文。 */
    if (out_user) {
        strncpy(out_user, user, 127);
        out_user[127] = 0;
    }
    if (out_pass_sha) {
        sha256_hex(pass, out_pass_sha);
    }
    SecureZeroMemory(pass, sizeof(pass));
    return 1;
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
 * HeartbeatParam - 心跳线程参数
 *
 * 共享WSConn指针，心跳线程负责定时发送ping/mouse，
 * 主线程负责阻塞接收消息。两者操作同一WebSocket句柄。
 *
 * 生命周期约定: HeartbeatParam 通常位于 keep_alive_thread 的栈帧上，
 * 心跳线程在每次访问字段前都会先检查 stop_flag；主线程在等待心跳线程
 * 退出(Exit)之前绝不释放/复用该栈帧，从而避免 use-after-free。
 */
typedef struct {
    WSConn *wsc;                  /* 共享的WebSocket连接(用于发送/关闭) */
    const char *desktop_code;     /* 桌面编码(用于日志) */
    volatile LONG *stop_flag;     /* 停止标志(由主线程设置) */
    DWORD cycle_start;            /* 本周期开始时间(GetTickCount) */
    HINTERNET hWebSocket;         /* WebSocket句柄(用于关闭) */
    volatile LONG *close_done;    /* 互斥标志，防止重复关闭 */
} HeartbeatParam;

/**
 * heartbeat_thread - 定时发送协议层Ping，并在周期结束前主动关闭连接
 *
 * 核心策略:
 *   - 每15秒发送RFC 6455 Ping帧(检测WebSocket层活性)
 *   - 在WS_KEEPALIVE_MS到期时WinHttpWebSocketClose主动断连
 *   - 抢在服务端zombie检测(60s)之前完成一次"优雅重连"
 *   - 本质: 通过高频率连接/断开模拟真实客户端的活跃行为
 *
 * @param param  HeartbeatParam指针
 * @return       线程退出码(0)
 */
static DWORD WINAPI heartbeat_thread(LPVOID param) {
    HeartbeatParam *hp = (HeartbeatParam *)param;
    DWORD last_ping = GetTickCount();
    int should_close = 0;

    while (!InterlockedCompareExchange(hp->stop_flag, 0, 0)) {
        /* 以200ms粒度轮询，保证主线程设置stop_flag后能在3000ms等待内退出，
         * 避免心跳线程访问已被主线程复用/释放的栈帧(HeartbeatParam)。 */
        for (int si = 0; si < 25; si++) {
            if (InterlockedCompareExchange(hp->stop_flag, 0, 0)) break;
            Sleep(200);
        }
        if (InterlockedCompareExchange(hp->stop_flag, 0, 0)) break;

        DWORD now = GetTickCount();
        DWORD elapsed = now - hp->cycle_start;

        /* 在WS_KEEPALIVE_MS到期时主动关闭连接，抢在zombie之前重连 */
        if (elapsed >= WS_KEEPALIVE_MS && !InterlockedCompareExchange(hp->close_done, 0, 0)) {
            InterlockedExchange(hp->close_done, 1);
            should_close = 1;
            log_line("[%s] [CYCLE] 周期%ds到期，主动关闭连接(避免zombie)", hp->desktop_code, elapsed / 1000);
            break;
        }

        /* 发送RFC 6455协议层Ping帧(opcode=0x9) */
        if ((now - last_ping) >= WS_PING_INTERVAL_MS) {
            if (ws_send_ping(hp->wsc) == 0)
                log_line("[%s] [PING] RFC6455-Ping已发送 (+%ds)", hp->desktop_code, elapsed / 1000);
            else {
                log_line("[%s] [PING] RFC6455-Ping发送失败 (+%ds)", hp->desktop_code, elapsed / 1000);
                should_close = 1;
                break;
            }
            last_ping = now;
        }
    }

    /* 主动关闭WebSocket，解除主线程ws_recv的阻塞 */
    if (should_close && hp->hWebSocket) {
        log_line("[%s] [CYCLE] 正在关闭WebSocket连接...", hp->desktop_code);
        WinHttpWebSocketClose(hp->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    }
    return 0;
}

/**
 * keep_alive_thread - 保活工作线程
 *
 * 对运行中的桌面执行WebSocket保活:
 * 1. 建立WebSocket连接(使用预构建的ws_uri)
 * 2. 发送连接消息(使用预构建的connect_msg)
 * 3. 发送初始二进制载荷
 * 4. 维持连接45秒，期间处理REDQ认证请求
 * 5. 45秒后断开重连(抢在服务端zombie检测之前)
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

    uint8_t *ws_buf = (uint8_t *)malloc(WS_RECV_BUF_SIZE);
    if (!ws_buf) return 0;

    uint8_t user_payload_buf[1024];
    size_t user_payload_len = build_user_payload(s, user_payload_buf, sizeof(user_payload_buf));
    if (user_payload_len == 0) {
        log_line("[%s] 警告: 用户身份消息构建失败(缓冲区不足)", d->desktop_code);
    }
    int user_payload_sent = 0;

    /*
     * 1.2.1 的线程模型改为：保活线程在创建后先等待 start_event。
     * 这样可以把后续是否开始保活的决定权交给统一轮询线程，
     * 从而免去非运行桌面各自拉取一次完整列表的重开销。
     *
     * 修复(v1.3.5): 修复事件同步竞争问题，先检查退出标志再等待事件，
     * 避免在检查和等待之间收到信号导致永久阻塞。
     */
    while (!InterlockedCompareExchange(&g_auth_expired, 0, 0)) {
        if (!g_running) break;
        DWORD wait = WaitForSingleObject(d->start_event, 1000);
        if (wait == WAIT_OBJECT_0) break;
    }
    if (!g_running || InterlockedCompareExchange(&g_auth_expired, 0, 0)) {
        free(ws_buf);
        return 0;
    }

    /* WebSocket重连指数退避计数器，每个线程独立(必须是栈变量，不能是static，
     * 否则所有桌面线程会共享同一个计数器并互相干扰退避节奏) */
    volatile LONG s_retry_count = 0;

    while (g_running && !InterlockedCompareExchange(&g_auth_expired, 0, 0)) {
        log_line("[%s] 正在连接...", d->desktop_code);
        WSConn wsc;
        if (!ws_connect(d->ws_uri, &wsc, d->desktop_code)) {
            /*
             * 修复(v1.3.5): 添加指数退避重连策略
             * 初始等待5秒，每次失败后等待时间翻倍，最多2分钟
             * 避免被服务端识别为恶意行为
             */
            int retry = (int)InterlockedIncrement(&s_retry_count);
            int delay_ms = WS_RECONNECT_MS;
            if (retry > 1) {
                /* 指数退避: 5s, 10s, 20s, 40s, 80s, 最多120s */
                int shift = retry - 1;
                if (shift > 4) shift = 4;
                delay_ms = WS_RECONNECT_MS << shift;
                if (delay_ms > 120000) delay_ms = 120000;
            }
            log_line("[%s] WebSocket连接失败，%d秒后重试 (第%d次)", d->desktop_code, delay_ms / 1000, retry);
            for (int wi = 0; wi < delay_ms / 200 && g_running && !InterlockedCompareExchange(&g_auth_expired, 0, 0); wi++)
                Sleep(200);
            continue;
        }
        /* 连接成功后重置重试计数 */
        InterlockedExchange(&s_retry_count, 0);

        if (ws_send_text(&wsc, d->connect_msg) != 0) {
            log_line("[%s] [DEBUG] connect_msg发送失败，断开重连", d->desktop_code);
            /* 此处心跳线程尚未创建，直接关闭连接进入重连 */
            ws_close(&wsc);
            continue;
        }
        log_line("[%s] [DEBUG] connect_msg已发送(%dB)", d->desktop_code, (int)strlen(d->connect_msg));
        Sleep(WS_SEND_DELAY_MS);
        if (ws_send_bytes(&wsc, initial_payload, sizeof(initial_payload)) != 0) {
            log_line("[%s] [DEBUG] REDQ initial_payload发送失败，断开重连", d->desktop_code);
            /* 此处心跳线程尚未创建，直接关闭连接进入重连 */
            ws_close(&wsc);
            continue;
        }
        log_line("[%s] [DEBUG] REDQ initial_payload已发送(%zuB)", d->desktop_code, sizeof(initial_payload));
        user_payload_sent = 0;

        log_line("[%s] 已连接，保持%d秒", d->desktop_code, WS_KEEPALIVE_MS / 1000);

        /* [修复] 启动协议层Ping心跳线程(RFC 6455 opcode 0x9) + 周期结束主动关闭 */
        volatile LONG hb_stop = 0;
        volatile LONG hb_close_done = 0;
        HeartbeatParam hb_param = { &wsc, d->desktop_code, &hb_stop, GetTickCount(), wsc.hWebSocket, &hb_close_done };
        HANDLE hHeartbeat = CreateThread(NULL, 0, heartbeat_thread, &hb_param, 0, NULL);
        if (!hHeartbeat) {
            log_line("[%s] 警告: 心跳线程创建失败，将使用单线程模式", d->desktop_code);
        }

        /* 主线程: 阻塞接收消息，处理REDQ认证/用户身份等协议交互 */
        DWORD start = GetTickCount();

        /* [协议分析] 记录本周期内见过的所有SendInfo类型(只记录首次) */
        uint16_t seen_types[64] = {0};
        int seen_type_count = 0;

        /*
         * 回复缓冲: 只收集必须回复的协议消息(type=103用户身份)。
         * type=4心跳暂不回显，观察纯被动模式的存活时间。
         */
        uint8_t reply_buf[4096];
        size_t  reply_len = 0;

        while (g_running && !InterlockedCompareExchange(&g_auth_expired, 0, 0) &&
               (GetTickCount() - start) < WS_KEEPALIVE_MS) {
            int is_text;
            int n = ws_recv(&wsc, ws_buf, WS_RECV_BUF_SIZE, &is_text);
            if (n < 0) {
                DWORD err = GetLastError();
                log_line("[%s] [DEBUG] 接收错误/连接关闭 (err=%lu), 断开重连", d->desktop_code, err);
                break;
            }
            if (n == 0) continue;

            /* 重置本批次的回复缓冲 */
            reply_len = 0;

            if (!is_text && n >= 4 && memcmp(ws_buf, "REDQ", 4) == 0) {
                /* REDQ认证请求 */
                log_line("[%s] 收到REDQ认证请求(%dB)", d->desktop_code, n);
                uint8_t resp[512]; size_t rlen = 0;
                if (handle_redq(ws_buf, n, resp, &rlen)) {
                    ws_send_bytes(&wsc, resp, rlen);
                    log_line("[%s] [DEBUG] REDQ认证响应成功, rlen=%zu", d->desktop_code, rlen);
                } else {
                    log_line("[%s] [ERROR] REDQ handle_redq处理失败!", d->desktop_code);
                }
            } else if (!is_text && n >= 6) {
                /*
                 * [协议处理] 解析所有SendInfo二进制消息
                 * 关键发现: type=4 是服务端心跳包(12B)，必须回显才能避免zombie
                 */
                size_t off = 0;
                while (off + 6 <= (size_t)n) {
                    uint16_t msg_type = (uint16_t)(ws_buf[off] | (ws_buf[off+1] << 8));
                    int32_t msg_dlen = (int32_t)(ws_buf[off+2] | (ws_buf[off+3]<<8) |
                                                (ws_buf[off+4]<<16) | (ws_buf[off+5]<<24));
                    if (msg_dlen < 0 || off + 6 + (size_t)msg_dlen > (size_t)n) break;

                    /* 检查是否已记录过此类型 */
                    int already_seen = 0;
                    for (int si = 0; si < seen_type_count; si++) {
                        if (seen_types[si] == msg_type) { already_seen = 1; break; }
                    }

                    /* [测试] 纯被动模式: 不回复任何消息，观察最长存活时间 */
                    if (msg_type == 4 && msg_dlen >= 12) {
                        if (!already_seen) {
                            char hex[64] = {0};
                            int hmax = msg_dlen < 16 ? msg_dlen : 16;
                            for (int hi = 0; hi < hmax; hi++)
                                snprintf(hex + hi*3, 4, "%02x", ws_buf[off+6+hi]);
                            log_line("[%s] [HEARTBEAT] type=%u len=%d hex=[%s] [纯被动]",
                                     d->desktop_code, msg_type, msg_dlen, hex);
                            if (seen_type_count < 64) seen_types[seen_type_count++] = msg_type;
                        }
                    }
                    /* type=103: 用户身份请求 → 需要回复用户信息 */
                    else if (msg_type == 103 && user_payload_len > 0 && !user_payload_sent) {
                        if (reply_len + user_payload_len <= sizeof(reply_buf)) {
                            memcpy(reply_buf + reply_len, user_payload_buf, user_payload_len);
                            reply_len += user_payload_len;
                        }
                        log_line("[%s] 发送用户身份响应(type=103)", d->desktop_code);
                        user_payload_sent = 1;
                        if (!already_seen && seen_type_count < 64)
                            seen_types[seen_type_count++] = msg_type;
                    }
                    /* type=0: 空消息 → 不回复(服务端→客户端单向) */
                    else if (msg_type == 0) {
                        if (!already_seen) {
                            log_line("[%s] [PROTO] type=0 空消息(不回复)", d->desktop_code);
                            if (seen_type_count < 64) seen_types[seen_type_count++] = msg_type;
                        }
                    }
                    /* type=127: 屏幕帧数据 → 不回复(服务端→客户端单向，回显会导致连接断开!) */
                    else if (msg_type == 127) {
                        if (!already_seen) {
                            log_line("[%s] [PROTO] type=127 屏幕数据 %dB(不回复)", d->desktop_code, msg_dlen);
                            if (seen_type_count < 64) seen_types[seen_type_count++] = msg_type;
                        }
                    }
                    /* 其他未知类型: 首次记录 */
                    else {
                        if (!already_seen && seen_type_count < 64) {
                            seen_types[seen_type_count++] = msg_type;
                            log_line("[%s] [PROTO] 新类型 type=%u data_len=%d", d->desktop_code, msg_type, msg_dlen);
                        }
                    }

                    off += 6 + (size_t)msg_dlen;
                }

                /* ★ 批量发送本批次收集的所有回复(在recv循环外发送，避免状态机冲突) ★ */
                if (reply_len > 0) {
                    if (ws_send_bytes(&wsc, reply_buf, reply_len) != 0) {
                        log_line("[%s] [DEBUG] 批量回复发送失败，断开重连", d->desktop_code);
                        goto recv_loop_done;
                    }
                    log_line("[%s] [BATCH] 批量回复 %zuB", d->desktop_code, reply_len);
                }
            } else if (is_text) {
                log_line("[%s] [DEBUG] 收到文本消息(%dB): %.256s", d->desktop_code, n, ws_buf);
            } else if (n > 0) {
                log_line("[%s] [DEBUG] 其他小包 is_text=%d n=%d", d->desktop_code, is_text, n);
            }
        }
    recv_loop_done: ;

        /* 本周期结束: 打印汇总的所有协议类型 */
        if (seen_type_count > 0) {
            char type_list[512] = {0};
            int pos = 0;
            for (int ti = 0; ti < seen_type_count && pos < 500; ti++) {
                pos += snprintf(type_list + pos, 500 - pos, "%u ", seen_types[ti]);
            }
            log_line("[%s] [PROTO-SUMMARY] 本周期共发现 %d 种SendInfo类型: %s",
                     d->desktop_code, seen_type_count, type_list);
        }

        /* 停止心跳线程并等待退出 */
        InterlockedExchange(&hb_stop, 1);
        if (hHeartbeat) {
            /* 心跳线程内部以200ms粒度轮询hb_stop，最长 ~5s 必然退出 */
            DWORD wait_result = WaitForSingleObject(hHeartbeat, 6000);
            CloseHandle(hHeartbeat);
            if (wait_result != WAIT_OBJECT_0) {
                /* 极端情况下仍超时：不再访问可能被复用的栈帧，
                 * 直接放弃该心跳线程(被托管)，避免 use-after-free */
                log_line("[%s] 警告: 心跳线程未及时退出", d->desktop_code);
            }
        }

        ws_close(&wsc);
        log_line("[%s] %d秒完成，重新连接", d->desktop_code, WS_KEEPALIVE_MS / 1000);

        /* 全局原子计数器每15次递增时执行一次trim，释放物理内存 */
        if (InterlockedIncrement(&g_trim_counter) % 15 == 0) trim_working_set(0);
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
    int empty_count = 0;

    while (g_running) {
        Sleep(CHECK_INTERVAL * 1000);
        if (!g_running) break;
        log_line("正在统一检查桌面状态...");

        ZeroMemory(tmp, sizeof(tmp));
        int n = get_desktop_list_light(s, tmp, MAX_DESKTOPS);
        if (n == 0 && !InterlockedCompareExchange(&g_auth_expired, 0, 0)) {
            empty_count++;
            if (empty_count >= 3) {
                log_line("警告: 连续%d次桌面列表为空，认证可能已过期", empty_count);
                InterlockedExchange(&g_auth_expired, 1);
                break;
            }
            log_line("警告: 桌面列表为空(连续%d次)，可能认证已过期或无可用桌面", empty_count);
        } else {
            empty_count = 0;
        }
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
        if (InterlockedIncrement(&g_trim_counter) % 15 == 0) trim_working_set(0);
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

/* ======================== 公共层钩子实现 ======================== */

int ct_manual_captcha_mode(void) {
    /* 保活客户端: OCR 失败后固定进入手工弹窗流程，无环境变量开关 */
    return 0;
}

int ct_manual_captcha(const uint8_t *img_data, int img_len, char *out, size_t out_sz) {
    return read_captcha_manual(img_data, img_len, out, out_sz);
}

const wchar_t *ct_ws_ua(void) {
    return L"CtYunKeepAlive/" APP_VERSION;
}

void ct_log(const char *fmt, ...) {
    char b[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    log_line("%s", b);
}

/* ======================== 积分程序每日调度 (v1.5.0) ========================
 *
 * 取代 v1.4.0 的计划任务方案：常驻守护自身负责每日 05:00 拉起 ctyun_points.exe。
 *
 * 行为:
 *  - 每天 05:00(本地时间)以 CREATE_NO_WINDOW 子进程启动一次 points，工作目录=
 *    本 exe 所在目录(points 依赖 cwd 读取 config.json)；
 *  - 守护在 05:00 之后才启动(开机晚/重启)且今天没拉起过 → 立即补跑(StartWhenAvailable)；
 *  - points_launch.dat 记录最后拉起日期；points 另带单实例命名互斥，双重防同账号顶号；
 *  - 调度线程同步等待 points 结束(拿满即止/6h硬上限)，期间不再发起第二次；
 *  - 首次运行幂等删除 v1.4.0 时代的旧计划任务 ctyun_points(退出码非0即"本不存在"，忽略)。
 *
 * 调试/排障钩子(环境变量):
 *  CTYUN_POINTS_EXE       覆盖被拉起的 exe 全路径(默认 <本目录>\ctyun_points.exe)
 *  CTYUN_POINTS_ARGS      覆盖命令行参数(默认无参)
 *  CTYUN_POINTS_KEEP_TASK 非空则不清理旧计划任务
 *  CLI: /testsched        只跑一轮调度逻辑(不登录/不保活)，用于验证
 */
#define POINTS_SCHED_HOUR     5
#define POINTS_LEGACY_TASK    "ctyun_points"
#define POINTS_MARK_FILE      "points_launch.dat"
#define POINTS_DEFAULT_EXE    "ctyun_points.exe"

/* 本 exe 所在目录(以反斜杠结尾) */
static void points_module_dir(char *dir, size_t n) {
    char exe[MAX_PATH];
    DWORD got = GetModuleFileNameA(NULL, exe, MAX_PATH);
    dir[0] = 0;
    if (got > 0 && got < MAX_PATH) {
        strncpy(dir, exe, n - 1);
        dir[n - 1] = 0;
        char *sl = strrchr(dir, '\\');
        if (sl) sl[1] = 0;
    }
    if (!dir[0]) { strcpy(dir, ".\\"); }
}

static void points_today_str(char *buf, size_t n) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, n, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
}

/* 决定被拉起的 exe 路径与参数(支持环境变量覆盖) */
static void points_resolve_target(char *exe, size_t exe_n,
                                  char *args, size_t args_n,
                                  const char *dir) {
    const char *env_exe = getenv("CTYUN_POINTS_EXE");
    if (env_exe && env_exe[0]) {
        strncpy(exe, env_exe, exe_n - 1);
        exe[exe_n - 1] = 0;
    } else {
        snprintf(exe, exe_n, "%s%s", dir, POINTS_DEFAULT_EXE);
    }
    const char *env_args = getenv("CTYUN_POINTS_ARGS");
    if (env_args) {
        strncpy(args, env_args, args_n - 1);
        args[args_n - 1] = 0;
    } else {
        args[0] = 0;
    }
}

static int points_was_launched(const char *mark_path, const char *today) {
    FILE *f = fopen(mark_path, "r");
    if (!f) return 0;
    char buf[32];
    int hit = 0;
    if (fgets(buf, sizeof(buf), f)) {
        buf[strcspn(buf, "\r\n")] = 0;
        hit = (strcmp(buf, today) == 0);
    }
    fclose(f);
    return hit;
}

static void points_record_launched(const char *mark_path, const char *today) {
    FILE *f = fopen(mark_path, "w");
    if (!f) { log_line("积分调度: 警告，无法写启动标记 %s", mark_path); return; }
    fprintf(f, "%s\n", today);
    fclose(f);
}

/* 幂等清理 v1.4.0 时代的旧计划任务；任何失败均不影响守护 */
static void points_cleanup_legacy_task(void) {
    const char *keep = getenv("CTYUN_POINTS_KEEP_TASK");
    if (keep && keep[0]) {
        log_line("积分调度: CTYUN_POINTS_KEEP_TASK 已设置，保留旧计划任务");
        return;
    }
    wchar_t cmdline[160];
    _snwprintf(cmdline, 159, L"schtasks.exe /Delete /TN %hs /F", POINTS_LEGACY_TASK);
    cmdline[159] = 0;
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        log_line("积分调度: schtasks 调用失败(%lu，忽略)", (unsigned long)GetLastError());
        return;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD rc = 1;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (rc == 0)
        log_line("积分调度: 已清理旧计划任务 \"%s\"(此后由本守护直接拉起积分程序)",
                 POINTS_LEGACY_TASK);
    /* rc!=0: 任务本就不存在(0x80070002 等)，属于常态，不刷日志 */
}

/* 无窗口拉起积分程序并等待其结束；成功返回1，exit_code 输出子进程退出码 */
static int points_launch_and_wait(const char *dir, const char *exe,
                                  const char *args, DWORD *exit_code) {
    char cmdline[2100];
    snprintf(cmdline, sizeof(cmdline), "\"%s\"%s%s",
             exe, (args[0] ? " " : ""), args);
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    /* NEW_PROCESS_GROUP: 守护 Ctrl+C 时不把子进程一起带走(points 自行拿满/6h退出) */
    log_line("积分调度: 拉起 %s%s%s (工作目录 %s)",
             exe, args[0] ? " " : "", args, dir);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                        NULL, dir, &si, &pi)) {
        log_line("积分调度: 启动失败(%lu)", (unsigned long)GetLastError());
        return 0;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD rc = 1;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hProcess);
    if (exit_code) *exit_code = rc;
    return 1;
}

static DWORD WINAPI points_scheduler_thread(LPVOID param) {
    HANDLE h_first_round = (HANDLE)param;  /* 仅 /testsched 时非空 */

    char dir[MAX_PATH];
    points_module_dir(dir, sizeof(dir));
    char exe[MAX_PATH], args[1024];
    points_resolve_target(exe, sizeof(exe), args, sizeof(args), dir);
    char mark_path[MAX_PATH];
    snprintf(mark_path, sizeof(mark_path), "%s%s", dir, POINTS_MARK_FILE);

    log_line("积分调度: 线程已启动，每日%02d:00拉起积分程序(目标: %s)",
             POINTS_SCHED_HOUR, exe);

    if (!g_test_sched)
        points_cleanup_legacy_task();

    for (;;) {
        char today[16];
        points_today_str(today, sizeof(today));
        int launched = points_was_launched(mark_path, today);

        time_t now_t = time(NULL);
        struct tm lt;
        localtime_s(&lt, &now_t);
        struct tm fire = lt;
        fire.tm_hour = POINTS_SCHED_HOUR;
        fire.tm_min = 0;
        fire.tm_sec = 0;
        time_t fire_t = mktime(&fire);

        long wait_sec;
        const char *decision;
        if (launched) {
            wait_sec = (long)(fire_t + 86400 - now_t);   /* 今天已跑: 明天05:00 */
            decision = "今日已拉起过，等待次日";
        } else if (fire_t > now_t) {
            wait_sec = (long)(fire_t - now_t);           /* 今天05:00还没到 */
            decision = "等待今日定点";
        } else {
            wait_sec = 0;                                /* 05:00已过且未跑: 立即补跑 */
            decision = "定点已过且今日未拉起，立即补跑";
        }
        if (wait_sec < 0) wait_sec = 0;
        log_line("积分调度: %s (今天=%s, 标记文件=%s, 距下次%ld秒)",
                 decision, today, POINTS_MARK_FILE, wait_sec);

        if (h_first_round) SetEvent(h_first_round);

        if (g_test_sched) {
            /* 自测: 等待分支到点即结束；补跑分支等子进程跑完后结束 */
            if (wait_sec > 0) { log_line("积分调度[/testsched]: 首轮判定为等待，验证完成"); return 0; }
        } else {
            /* 分段睡眠，60秒一醒以响应 g_running 退出 */
            while (wait_sec > 0 && g_running) {
                DWORD chunk = (wait_sec > 60) ? 60 : (DWORD)wait_sec;
                Sleep(chunk * 1000);
                wait_sec -= (long)chunk;
            }
            if (!g_running) { log_line("积分调度: 收到停止信号，线程退出"); return 0; }
            /* 触发前复核: 睡眠跨午夜后 today 已变化，旧标记比较无意义但补跑判据仍成立；
             * 若等待期间已有其它实例(如前台过渡实例)完成拉起，则跳过本轮 */
            char now_today[16];
            points_today_str(now_today, sizeof(now_today));
            if (points_was_launched(mark_path, now_today)) {
                log_line("积分调度: 复核发现今日已被其它实例拉起，跳过本轮");
                continue;
            }
        }

        /* wait_sec == 0: 拉起积分程序 */
        char fire_today[16];
        points_today_str(fire_today, sizeof(fire_today));
        DWORD rc = 0;
        if (points_launch_and_wait(dir, exe, args, &rc)) {
            points_record_launched(mark_path, fire_today);
            log_line("积分调度: 积分程序已退出(退出码=%lu)，今日标记已写入", rc);
        } else if (!g_test_sched) {
            log_line("积分调度: 60秒后重试拉起");
            Sleep(60000);
        }

        if (g_test_sched) { log_line("积分调度[/testsched]: 拉起-等待-标记流程验证完成"); return 0; }
    }
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
    printf("  /help,       /h  显示此帮助信息\n\n");
    printf("常驻运行期间每日05:00自动无窗口调用 ctyun_points.exe 完成积分任务\n");
    printf("(登录1002 + AI对话1004 + 挂机1003)，无需安装计划任务。\n");
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
    /* 设置控制台为UTF-8编码，解决中文乱码（必须在 printf/usage 之前） */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/background") == 0 || strcmp(argv[i], "/b") == 0) {
            g_bg_switch = 1;
        } else if (strcmp(argv[i], "/__bg") == 0) {
            g_background = 1;
        } else if (strcmp(argv[i], "/privacy") == 0 || strcmp(argv[i], "/p") == 0) {
            g_privacy = 1;
        } else if (strcmp(argv[i], "/random") == 0 || strcmp(argv[i], "/r") == 0) {
            g_random = 1;
        } else if (strcmp(argv[i], "/version") == 0 || strcmp(argv[i], "/v") == 0) {
            printf("版本 " APP_VERSION "\n");
            return 0;
        } else if (strcmp(argv[i], "/testsched") == 0) {
            g_test_sched = 1;
        } else if (strcmp(argv[i], "/help") == 0 || strcmp(argv[i], "/h") == 0 || strcmp(argv[i], "/?") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* /testsched: 积分调度自测——只跑调度线程一轮，不登录/不连接桌面/不清理计划任务。
     * 配合 CTYUN_POINTS_EXE / CTYUN_POINTS_ARGS 可用替身程序验证拉起与标记文件行为。 */
    if (g_test_sched) {
        log_line("=== /testsched 积分调度自测开始(不登录/不保活) ===");
        HANDLE h_evt = CreateEvent(NULL, TRUE, FALSE, NULL);
        HANDLE h_thr = CreateThread(NULL, THREAD_STACK, points_scheduler_thread, h_evt, 0, NULL);
        if (h_thr) {
            WaitForSingleObject(h_evt, 10000);
            /* 补跑分支会等待子进程结束(替身程序通常几秒)，最多等90秒 */
            WaitForSingleObject(h_thr, 90000);
            CloseHandle(h_thr);
        } else {
            log_line("调度线程创建失败: %lu", (unsigned long)GetLastError());
        }
        if (h_evt) CloseHandle(h_evt);
        log_line("=== /testsched 结束 ===");
        if (g_log_file) fclose(g_log_file);
        return 0;
    }

    /* 设置控制台字体为Consolas，确保中文正常显示 */
    CONSOLE_FONT_INFOEX cfi = {0};
    cfi.cbSize = sizeof(cfi);
    cfi.dwFontSize.Y = 16;
    cfi.FontWeight = FW_NORMAL;
    wcscpy(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);

    /* 注册Ctrl+C处理函数 */
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    InitializeCriticalSection(&g_captcha_cs);

    if (!g_background) refresh_banner();

    /* 初始化网络和加密子系统 */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (!crypto_init()) {
        fprintf(stderr, "加密子系统初始化失败\n");
        WSACleanup();
        return 1;
    }
    http_init();

    log_line("天翼云电脑保活 V" APP_VERSION);

    /* 解析用户凭据(尝试自动解密config.json，失败则手动输入)。 */
    Session session = {0};
    if (!resolve_credentials(&session, NULL, NULL)) {
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
    HANDLE threads[MAX_THREADS];
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

        /* 先判断是否还有线程槽位，避免创建后才发现越界。
         * 此前的"先CreateThread再判断越界"会把已创建的线程靠CloseHandle
         * 释放(不会等待其退出)，且对应 start_event 也被关闭，使该线程
         * 在 WaitForSingleObject(已关闭句柄) 上行为未定义。 */
        if (nthreads >= MAX_THREADS - 1) {
            log_line("警告: 线程数已达上限(%d)，跳过桌面[%s]",
                     MAX_THREADS - 1, desktops[i].desktop_code);
            CloseHandle(desktops[i].start_event);
            desktops[i].start_event = NULL;
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

        /* v1.5.0: 启动积分每日调度线程(取代计划任务)。必须在 run.log 打开之后启动，
         * 否则 /__bg 模式下线程首条日志在 g_log_file 就绪前发出而丢失。前台过渡实例与
         * /__bg 常驻实例都会启动它，靠 points_launch.dat 标记 + points 单实例互斥去重。 */
        {
            HANDLE h_sched = CreateThread(NULL, THREAD_STACK, points_scheduler_thread, NULL, 0, NULL);
            if (h_sched) CloseHandle(h_sched);
            else log_line("积分调度线程创建失败: %lu", (unsigned long)GetLastError());
        }

        log_line("保活已启动, Ctrl+C 停止");

        while (g_running) {
            DWORD result = WaitForMultipleObjects(nthreads, threads, TRUE, 500);
            if (result != WAIT_TIMEOUT) break;
            if (g_bg_switch && !g_background) {
                char exe_path[MAX_PATH];
                GetModuleFileNameA(NULL, exe_path, MAX_PATH);
                char *slash = strrchr(exe_path, '\\');
                if (slash) *slash = 0;
                char log_path[MAX_PATH];
                snprintf(log_path, sizeof(log_path), "%s\\run.log", exe_path);

                log_line("已转入后台运行, 日志: %s", log_path);
                log_line("本窗口将在5秒后自动关闭...");
                Sleep(5000);

                GetModuleFileNameA(NULL, exe_path, MAX_PATH);

                char cmd_line[1024];
                snprintf(cmd_line, sizeof(cmd_line), "\"%s\" /__bg", exe_path);
                if (g_privacy) strcat(cmd_line, " /p");
                if (g_random) strcat(cmd_line, " /r");

                STARTUPINFOA si = { sizeof(si) };
                PROCESS_INFORMATION pi = {0};
                if (CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                                   DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }

                HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                    COORD pos = {0, csbi.srWindow.Bottom};
                    DWORD written;
                    FillConsoleOutputCharacterW(hOut, L' ', csbi.dwSize.X, pos, &written);
                    FillConsoleOutputAttribute(hOut, csbi.wAttributes, csbi.dwSize.X, pos, &written);
                }

                ExitProcess(0);
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
    DeleteCriticalSection(&g_captcha_cs);
    if (g_inet) WinHttpCloseHandle(g_inet);
    if (g_rsa_alg) BCryptCloseAlgorithmProvider(g_rsa_alg, 0);
    CryptReleaseContext(g_crypt, 0);
    WSACleanup();
    log_line("已停止");
    return 0;
}
