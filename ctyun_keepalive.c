/*
 * ctyun_keepalive.c - 某云电脑保活客户端 (C语言版)
 *
 * 功能概述:
 *   自动登录某云电脑平台，获取桌面列表，对运行中的桌面建立WebSocket保活连接，
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
 * 版本: 1.0.0
 */
