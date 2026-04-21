@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /O2 /MD /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /utf-8 ctyun_keepalive.c /link /SUBSYSTEM:CONSOLE /STACK:131072,131072 /OPT:REF /OPT:ICF winhttp.lib ws2_32.lib crypt32.lib advapi32.lib iphlpapi.lib bcrypt.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib
