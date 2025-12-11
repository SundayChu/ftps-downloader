# 登入 GitHub (使用瀏覽器驗證)
Write-Host "正在啟動 GitHub 登入程序..."
Write-Host "請注意：GitHub 已不再支援指令列密碼登入，請依照指示使用瀏覽器驗證。"
Write-Host "請在瀏覽器中登入您的帳號: SundayChu535"
& "C:\Program Files\GitHub CLI\gh.exe" auth login --web --git-protocol https

# 檢查是否登入成功
if ($LASTEXITCODE -eq 0) {
    Write-Host "登入成功！正在建立並推送專案..."
    # 建立並推送到 GitHub (預設為私有專案)
    & "C:\Program Files\GitHub CLI\gh.exe" repo create ftps-downloader --private --source=. --push
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "專案已成功推送到 GitHub!"
    } else {
        Write-Host "推送失敗，請檢查錯誤訊息。"
    }
} else {
    Write-Host "登入失敗或已取消。"
}

pause
