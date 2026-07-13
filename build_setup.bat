@echo off
title Building SecureXP Multi-Step Setup Wizard (TDM-GCC)
set GCC_PATH=C:\TDM-GCC-64\bin

if not exist "SecureXP.exe" (
    echo [ERROR] SecureXP.exe was not found in this folder!
    pause
    exit /b
)

if not exist "SecureXP.ico" (
    echo [ERROR] SecureXP.ico was not found in this folder!
    pause
    exit /b
)

if not exist "eula.txt" (
    echo [ERROR] eula.txt was not found in this folder!
    pause
    exit /b
)

echo ==========================================
echo Step 1: Compiling Setup Resource file [Setup.rc] ...
echo ==========================================
"%GCC_PATH%\windres.exe" Setup.rc -F pe-i386 -o Setup_res.o

IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile Setup.rc!
    pause
    exit /b
)

echo.
echo ==========================================
echo Step 2: Compiling Setup C++ code with g++ ...
echo ==========================================
"%GCC_PATH%\g++.exe" -o SecureXP_Setup.exe Setup.cpp Setup_res.o -mwindows -static -std=c++11 -m32 -lcomctl32 -lshlwapi -ladvapi32 -lshell32 -lole32 -luuid -luser32 -lkernel32 -lgdi32

if %ERRORLEVEL%==0 (
    echo.
    echo ==========================================
    echo [SUCCESS] Multi-Step Setup Bundle created: SecureXP_Setup.exe
    echo ==========================================
) else (
    echo.
    echo [ERROR] Compilation failed.
)

pause