@echo off
REM 測試自動停止功能

echo ================================================
echo FTPS Downloader - 自動停止功能測試
echo ================================================
echo.
echo 此測試將展示自動停止功能
echo 程式會每 1 分鐘檢查一次
echo 並在 2 分鐘後自動停止
echo.
echo 請確保：
echo 1. 已編譯最新版本的 ftps-downloader.exe
echo 2. 當前時間加 2 分鐘後的時間將作為停止時間
echo.

REM 計算 2 分鐘後的時間
powershell -Command "$stopTime = (Get-Date).AddMinutes(2).ToString('HH:mm'); Write-Host '停止時間將設定為：' $stopTime; Write-Host '程式將在該時間自動停止'; Write-Host ''; $stopTime" > temp_stop_time.txt
set /p STOP_TIME=<temp_stop_time.txt
del temp_stop_time.txt

echo 按任意鍵開始測試，或按 Ctrl+C 取消...
pause > nul
echo.

REM 使用命令列參數測試自動停止功能
ftps-downloader.exe ^
  -host 127.0.0.1 ^
  -port 21 ^
  -user test ^
  -pass test ^
  -monitor-mode ^
  -check-interval 1 ^
  -stop-time "%STOP_TIME%" ^
  -local-dir ./downloads ^
  -log-dir ./logs

echo.
echo ================================================
echo 測試結束 - 程式已在指定時間自動停止
echo ================================================
pause
