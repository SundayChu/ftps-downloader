@echo off
REM 測試全天監控模式功能

echo ================================================
echo FTPS Downloader - 監控模式測試
echo ================================================
echo.
echo 此測試將展示監控模式的基本功能
echo 程式會每 1 分鐘檢查一次（僅供測試）
echo.
echo 請確保：
echo 1. 已編譯最新版本的 ftps-downloader.exe
echo 2. 已設定正確的連線參數
echo.
echo 按任意鍵開始測試，或按 Ctrl+C 取消...
pause > nul
echo.

REM 使用命令列參數測試監控模式
REM 注意：這裡使用 1 分鐘間隔僅供測試，實際使用建議至少 15 分鐘
ftps-downloader.exe ^
  -host 127.0.0.1 ^
  -port 21 ^
  -user test ^
  -pass test ^
  -monitor-mode ^
  -check-interval 1 ^
  -local-dir ./downloads ^
  -log-dir ./logs

echo.
echo ================================================
echo 測試結束
echo ================================================
pause
