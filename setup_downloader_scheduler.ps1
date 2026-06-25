# Windows 工作排程設定腳本 - FTPS Downloader (Hidden / Monitor Mode)
# 執行此腳本以建立或更新排程工作
# 注意：必須以系統管理員身分執行

$TaskName = "FTPS_Downloader_Task"
$TaskPath = "\Rayin\"
$WorkingDir = $PSScriptRoot
if (!$WorkingDir) { $WorkingDir = $PWD.Path }
$VbsPath = Join-Path $WorkingDir "run_ftps_downloader_monitor_hidden.vbs"
$ExePath  = Join-Path $WorkingDir "ftps-downloader.exe"

# 確認 VBS 與 exe 存在
if (-not (Test-Path $VbsPath)) {
    Write-Host "ERROR: 找不到 $VbsPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: 找不到 $ExePath，請先編譯" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------
# 如果已存在舊工作，先移除（避免舊的有 stdout/stderr 重導向）
# ---------------------------------------------------------------
$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "發現舊工作，移除中..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Host "舊工作已移除" -ForegroundColor Green
}

# ---------------------------------------------------------------
# 1. 執行動作：透過 VBS 啟動（隱藏視窗，不做任何外部 stdout/stderr 重導向）
#    所有 log 由程式本身寫入 log_dir 指定的資料夾
# ---------------------------------------------------------------
$Action = New-ScheduledTaskAction `
    -Execute "wscript.exe" `
    -Argument "`"$VbsPath`"" `
    -WorkingDirectory $WorkingDir

# ---------------------------------------------------------------
# 2. 觸發器：每天登入後啟動一次（monitor_mode=true 讓程式自己循環）
#    若需要每 N 分鐘重啟，可改用 RepetitionInterval
# ---------------------------------------------------------------
$Trigger = New-ScheduledTaskTrigger -AtLogOn

# ---------------------------------------------------------------
# 3. 設定
# ---------------------------------------------------------------
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0)   # 0 = 不限制執行時間

# ---------------------------------------------------------------
# 4. 註冊工作排程
# ---------------------------------------------------------------
Register-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath $TaskPath `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -RunLevel Highest `
    -Force

Write-Host ""
Write-Host "工作 '$TaskPath$TaskName' 已建立成功！" -ForegroundColor Green
Write-Host "啟動方式: wscript.exe `"$VbsPath`""
Write-Host "工作目錄: $WorkingDir"
Write-Host ""
Write-Host "所有 log 將由程式本身寫入 log_dir 資料夾（含日期），不再有無日期的 ftps_out.log / ftps_err.log" -ForegroundColor Cyan
