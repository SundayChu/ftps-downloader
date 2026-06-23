@echo off
REM Build FTPS Downloader without console window - Windows + Linux

setlocal
set EXE_NAME=ftps-downloader.exe
set LINUX_EXE=ftps-downloader-linux\ftps-downloader
set LINUX_DIR=ftps-downloader-linux

:: ===== Windows 版 (隱藏模式) =====
echo [1/2] 編譯 Windows 版 %EXE_NAME% (隱藏模式)...

:TRY_BUILD_WIN
go build -ldflags="-H=windowsgui" -o %EXE_NAME% ./cmd/downloader

if %ERRORLEVEL% EQU 0 (
    echo   OK: %EXE_NAME% 建立成功（無主控台）
    goto BUILD_LINUX
)

echo   編譯失敗，嘗試移除舊檔案...
if exist %EXE_NAME% (
    del /F %EXE_NAME% 2>nul
    if exist %EXE_NAME% (
        echo   ERROR: 無法刪除 %EXE_NAME%，程式可能正在執行中
        goto END
    )
    echo   舊檔案已刪除，重試編譯...
    goto TRY_BUILD_WIN
) else (
    echo   編譯失敗（其他原因）
    goto END
)

:: ===== Linux 版 =====
:BUILD_LINUX
echo [2/2] 編譯 Linux amd64 版...

if not exist %LINUX_DIR% mkdir %LINUX_DIR%

set GOOS=linux
set GOARCH=amd64
go build -o %LINUX_EXE% ./cmd/downloader
set GOOS=
set GOARCH=

if %ERRORLEVEL% EQU 0 (
    echo   OK: %LINUX_EXE% 建立成功
) else (
    echo   ERROR: Linux 編譯失敗
    goto END
)

echo.
echo 全部完成！
echo   Windows: %EXE_NAME% (隱藏模式)
echo   Linux:   %LINUX_EXE%

:END
pause
