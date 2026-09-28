@echo off
rem Build ctyun_keepalive.exe and ctyun_points.exe (MSVC 2022 BuildTools, x64)
rem /GL  - Whole Program Optimization (cross-module inlining)
rem /LTCG - Link-Time Code Generation, paired with /GL
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1

rem --- ctyun_keepalive.exe ---
cl /nologo /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ctyun_common.c ctyun_keepalive.c /Fe:ctyun_keepalive.exe /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib shell32.lib psapi.lib
if errorlevel 1 exit /b 1

rem --- ctyun_points.exe (WS_RECV_TIMEOUT_MS=60000; common defaults to 30s for keepalive) ---
cl /nologo /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL /DWS_RECV_TIMEOUT_MS=60000 ctyun_common.c ctyun_points.c /Fe:ctyun_points.exe /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib user32.lib shell32.lib
