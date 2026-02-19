@echo off
REM 啟動 FTPS Downloader 全天監控模式

echo ================================================
echo FTPS Downloader - 全天監控模式
echo ================================================
echo.
echo 程式將持續運行，定期檢查並下載檔案
echo 按 Ctrl+C 可停止監控
echo.
echo ================================================
echo.

REM 確保使用正確的設定檔
if not exist "config.properties" (
    echo 錯誤：找不到 config.properties 設定檔
    echo.
    echo 請先複製 config.monitor.example.properties 並改名為 config.properties
    echo 然後修改其中的連線設定
    echo.
    pause
    exit /b 1
)

REM 執行下載程式
ftps-downloader.exe

pause
