# Windows 工作排程設定腳本 - FTPS Uploader (Hidden)

$TaskName = "FTPS_Uploader_Task"
$WorkingDir = $PSScriptRoot
if (!$WorkingDir) { $WorkingDir = $PWD.Path }
$VbsPath = Join-Path $WorkingDir "run_ftps_uploader_hidden.vbs"

# 確保隱藏版執行檔存在
$HiddenExePath = Join-Path $WorkingDir "ftps-uploader-hidden.exe"
if (-not (Test-Path $HiddenExePath)) {
    Write-Host "Building hidden uploader executable..." -ForegroundColor Yellow
    Set-Location $WorkingDir
    go build -ldflags="-H=windowsgui" -o ftps-uploader-hidden.exe ./cmd/uploader
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful!" -ForegroundColor Green
    } else {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
}

# 1. 定義執行動作 (執行 .vbs 檔以隱藏視窗)
$Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$VbsPath`"" -WorkingDirectory $WorkingDir

# 2. 定義觸發器 (例如：每 30 分鐘執行一次，配合程式內的時間範圍檢查)
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30)

# 3. 定義設定 (允許在有電源時執行、如果失敗則重啟等)
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# 4. 註冊工作排程 (如果已存在則更新)
# 將工作建立在 \Rayin 資料夾下
$TaskPath = "\Rayin\"
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Trigger $Trigger -Settings $Settings -Force

Write-Host "Task '$TaskName' has been successfully created in folder '$TaskPath'!" -ForegroundColor Green
Write-Host "Execution Path: $VbsPath (Hidden Mode)"
Write-Host "Executable: ftps-uploader-hidden.exe"
Write-Host "Frequency: Every 30 minutes"
Write-Host "Please remember to set 'allowed_time_range' in config.uploader.properties."
Write-Host ""
Write-Host "Note: The uploader will run in background without showing a window." -ForegroundColor Cyan
