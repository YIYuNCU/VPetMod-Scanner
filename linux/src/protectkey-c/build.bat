@echo off
rem Build protectkey.exe (x64). Works outside MSVC env: calls vcvars64 automatically.
rem NOTE: keep this file ASCII-only (cmd parses it as ANSI/GBK codepage).
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /utf-8 /DUNICODE /D_UNICODE protectkey.c /link crypt32.lib
