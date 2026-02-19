@echo off
REM 測試監控模式的詳細日誌輸出

echo ================================================
echo FTPS Downloader - 監控日誌測試
echo ================================================
echo.
echo 此測試將展示監控模式的詳細日誌輸出
echo 程式會每 1 分鐘檢查一次
echo.
echo 日誌內容包括：
echo - 每分鐘的檢查狀態
echo - 時間範圍檢查結果
echo - 停止時間倒數
echo - 下載執行狀態
echo - 待機狀態顯示
echo.
echo 即使不在下載時間內，也會每分鐘顯示狀態
echo 所有信息都會記錄到 log 檔案中
echo.
echo 按任意鍵開始測試，或按 Ctrl+C 取消...
pause > nul
echo.

REM 測試設定：每 1 分鐘檢查，設定一個未來的時間範圍
ftps-downloader.exe ^
  -host 127.0.0.1 ^
  -port 21 ^
  -user test ^
  -pass test ^
  -monitor-mode ^
  -check-interval 1 ^
  -allowed-time-range "23:00-23:59" ^
  -local-dir ./downloads ^
  -log-dir ./logs

echo.
echo ================================================
echo 測試結束
echo 請查看 logs 目錄中的日誌檔案
echo ================================================
pause
