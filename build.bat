@echo off
title Building SecureXP Core (tdm64-gcc)

if not exist "SecureXP.cpp" (
    echo [ERROR] SecureXP.cpp was not found!
    pause
    exit /b
)

echo Compiling Resources...
windres SecureXP.rc -F pe-i386 -o SecureXP_res.o
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile resources.
    pause
    exit /b
)

echo Compiling C++ Code (Generating 32-bit XP Executable)...
:: اضافه شدن -liphlpapi به انتهای دستور کامپایلر
g++ SecureXP.cpp SecureXP_res.o -o SecureXP.exe -mwindows -static -std=c++11 -m32 -lwininet -lcrypt32 -lcomctl32 -lshlwapi -ladvapi32 -lshell32 -lole32 -luuid -luser32 -lkernel32 -lgdi32 -lcomdlg32 -liphlpapi

if %ERRORLEVEL%==0 (
    echo [SUCCESS] SecureXP.exe created!
) else (
    echo [ERROR] Compilation failed.
)
pause