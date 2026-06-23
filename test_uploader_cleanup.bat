@echo off
REM ================================================================
REM 測試上傳器的自動清理與單一實例功能
REM ================================================================
chcp 65001 >nul
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║  FTPS 上傳器 - 自動清理與單一實例測試                      ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試 1: 建立測試用的舊日誌檔案                             │
echo └───────────────────────────────────────────────────────────┘
echo.

REM 確保 logs 目錄存在
if not exist logs mkdir logs

REM 建立今天的日誌
echo 建立今天的日誌: ftps-uploader-%date:~0,4%%date:~5,2%%date:~8,2%.log
echo This is today's log > logs\ftps-uploader-%date:~0,4%%date:~5,2%%date:~8,2%.log

REM 建立 5 天前的舊日誌
echo 建立 5 天前的舊日誌: ftps-uploader-20260228.log
echo This is an old log from 5 days ago > logs\ftps-uploader-20260228.log

REM 建立 4 天前的舊日誌
echo 建立 4 天前的舊日誌: ftps-uploader-20260301.log
echo This is an old log from 4 days ago > logs\ftps-uploader-20260301.log

REM 建立 2 天前的新日誌（應該保留）
echo 建立 2 天前的新日誌: ftps-uploader-20260303.log
echo This is a recent log from 2 days ago > logs\ftps-uploader-20260303.log

REM 修改檔案時間（使用 PowerShell）
echo.
echo 正在修改檔案時間...
powershell -Command "(Get-Item 'logs\ftps-uploader-20260228.log').LastWriteTime = (Get-Date).AddDays(-5)"
powershell -Command "(Get-Item 'logs\ftps-uploader-20260301.log').LastWriteTime = (Get-Date).AddDays(-4)"
powershell -Command "(Get-Item 'logs\ftps-uploader-20260303.log').LastWriteTime = (Get-Date).AddDays(-2)"

echo.
echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試 2: 顯示目前的日誌檔案                                 │
echo └───────────────────────────────────────────────────────────┘
echo.
echo 目前 logs 目錄的內容:
dir /B logs\*.log
echo.

echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試 3: 執行上傳程式（將清理超過 3 天的日誌）              │
echo └───────────────────────────────────────────────────────────┘
echo.
echo 預期結果:
echo   - ✓ 保留: ftps-uploader-%date:~0,4%%date:~5,2%%date:~8,2%.log （今天）
echo   - ✓ 保留: ftps-uploader-20260303.log （2 天前）
echo   - ✗ 刪除: ftps-uploader-20260228.log （5 天前）
echo   - ✗ 刪除: ftps-uploader-20260301.log （4 天前）
echo.
pause

REM 執行上傳程式（使用範例設定檔）
echo.
echo ════════════════════════════════════════════════════════════
echo 開始執行上傳程式...
echo ════════════════════════════════════════════════════════════
echo.

REM 檢查是否有設定檔
if not exist config.uploader.properties (
    echo ⚠️  警告: 找不到 config.uploader.properties
    echo.
    echo 如果要測試完整功能，請先建立設定檔。
    echo 或者，程式會在測試清理和單一實例功能後因為缺少設定而停止。
    echo.
    pause
)

REM 執行上傳程式
ftps-uploader.exe
if errorlevel 1 (
    echo.
    echo ⚠️  程式執行失敗（可能是缺少設定檔，但清理功能應該已經執行）
) else (
    echo.
    echo ✓ 程式執行完成
)

echo.
echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試 4: 顯示清理後的日誌檔案                               │
echo └───────────────────────────────────────────────────────────┘
echo.
echo 清理後 logs 目錄的內容:
dir /B logs\*.log
echo.

echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試 5: 測試單一實例控制                                   │
echo └───────────────────────────────────────────────────────────┘
echo.
echo 即將在背景啟動第一個上傳程式實例...
echo 然後啟動第二個實例，第二個實例應該會自動終止第一個實例。
echo.
pause

REM 在背景啟動第一個實例（使用 start 命令）
echo 啟動第一個實例...
start "FTPS-Uploader-Instance1" ftps-uploader.exe
echo 等待 3 秒...
timeout /t 3 /nobreak >nul

echo.
echo 檢查目前執行中的上傳程式:
tasklist /FI "IMAGENAME eq ftps-uploader.exe" /FO TABLE
echo.

echo 現在啟動第二個實例，它應該會終止第一個實例...
pause

REM 啟動第二個實例
ftps-uploader.exe

echo.
echo ┌───────────────────────────────────────────────────────────┐
echo │ 測試完成！                                                  │
echo └───────────────────────────────────────────────────────────┘
echo.
echo 測試總結:
echo.
echo 1. 日誌清理功能
echo    - 檢查 logs 目錄，超過 3 天的日誌應該已被刪除
echo    - 最新的日誌應該保留
echo.
echo 2. 單一實例控制
echo    - 舊的執行實例應該被自動終止
echo    - 只有一個程式實例在執行
echo.
echo 請檢查 logs 目錄和程式日誌確認結果。
echo.
pause
