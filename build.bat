@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
rem 1.2.2 compile optimization: enable Whole Program Optimization (/GL) and Link-Time Code Generation (/LTCG)
rem /GL - Whole Program Optimization, cross-module inlining and optimization
rem /LTCG - Link-Time Code Generation, used with /GL for best performance
cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 /GL ctyun_keepalive.c /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF /LTCG winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib
