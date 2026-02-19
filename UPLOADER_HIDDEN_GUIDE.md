# FTPS Uploader 隱藏執行設定指南

## 概述

上傳程式現在支援隱藏執行模式，執行時不會開啟命令提示字元視窗，適合用於工作排程或背景自動執行。

## 執行檔說明

### 1. ftps-uploader.exe
- **用途**: 一般手動執行版本
- **特性**: 會顯示命令提示字元視窗，可以看到執行過程和日誌
- **適用場景**: 測試、除錯、手動執行

### 2. ftps-uploader-hidden.exe
- **用途**: 隱藏執行版本
- **特性**: 完全在背景執行，不顯示任何視窗
- **適用場景**: 工作排程、自動化任務、背景服務

## 快速使用方式

### 方法 1: 直接執行批次檔（推薦）

直接雙擊執行 `run_ftps_uploader.bat`，批次檔會：
1. 自動檢查 `ftps-uploader-hidden.exe` 是否存在
2. 如不存在則自動編譯
3. 在背景執行上傳程式（無視窗）

### 方法 2: 使用 VBScript（完全隱藏）

雙擊執行 `run_ftps_uploader_hidden.vbs`，會：
1. 完全隱藏執行（連批次檔視窗都不會出現）
2. 適合加入 Windows 工作排程

### 方法 3: 手動執行隱藏版

```powershell
# PowerShell
Start-Process "ftps-uploader-hidden.exe" -ArgumentList "-config=config.uploader.properties" -NoNewWindow
```

```batch
REM 命令提示字元
start "" ftps-uploader-hidden.exe -config=config.uploader.properties
```

## 設定 Windows 工作排程

### 自動設定（推薦）

1. 以系統管理員身分執行 PowerShell
2. 切換到程式目錄
3. 執行設定腳本：
```powershell
.\setup_scheduler.ps1
```

腳本會自動：
- 檢查並編譯隱藏版執行檔
- 建立工作排程任務
- 設定每 30 分鐘執行一次
- 使用 VBScript 完全隱藏執行

### 手動設定

1. 開啟「工作排程器」(Task Scheduler)
2. 建立基本工作
3. **程式**: 選擇 `wscript.exe`
4. **引數**: 填入 VBS 檔案的完整路徑
   ```
   "C:\Sunday\Dropbox\go\ftps-downloader\run_ftps_uploader_hidden.vbs"
   ```
5. **起始位置**: 填入程式目錄路徑
6. 設定觸發條件（建議：每 30 分鐘重複執行）

## 編譯說明

### 編譯隱藏版執行檔

```batch
REM 執行編譯腳本
build_uploader_no_console.bat
```

或手動編譯：
```powershell
go build -ldflags="-H=windowsgui" -o ftps-uploader-hidden.exe uploader.go
```

**重要**: `-H=windowsgui` 參數會將程式編譯為 Windows GUI 應用程式，不會顯示命令提示字元視窗。

## 查看執行狀態

由於隱藏版不顯示視窗，可透過以下方式確認執行狀態：

### 1. 查看日誌檔
在 `logs` 目錄下查看日誌檔：
```
logs/ftps-uploader-YYYY-MM-DD.log
```

### 2. 檢查進程
```powershell
# PowerShell
Get-Process ftps-uploader-hidden -ErrorAction SilentlyContinue
```

### 3. 工作管理員
開啟工作管理員，在「詳細資料」分頁中尋找 `ftps-uploader-hidden.exe`

## 時間範圍控制

配合 `config.uploader.properties` 中的 `allowed_time_range` 設定：

```properties
# 只在凌晨 2:00-5:00 之間執行上傳
allowed_time_range=02:00-05:00
```

建議設定：
- 工作排程：每 30 分鐘或每小時執行一次
- 時間範圍：在配置檔中設定實際要上傳的時間段
- 程式會自動檢查當前時間，不在範圍內會自動跳過

## 疑難排解

### 問題：執行後沒有反應
**檢查**:
1. 查看日誌檔是否有錯誤訊息
2. 確認配置檔路徑正確
3. 檢查 FTP 伺服器連線設定

### 問題：找不到執行檔
**解決**:
執行 `build_uploader_no_console.bat` 重新編譯

### 問題：工作排程沒有執行
**檢查**:
1. 工作排程器中的任務狀態
2. 任務的「上次執行結果」
3. 確認 VBS 檔案路徑正確

### 問題：需要看到執行過程
**解決**:
使用一般版 `ftps-uploader.exe` 進行測試和除錯

## 相關檔案

- `ftps-uploader.exe` - 一般版執行檔（顯示視窗）
- `ftps-uploader-hidden.exe` - 隱藏版執行檔（背景執行）
- `run_ftps_uploader.bat` - 執行批次檔（使用隱藏版）
- `run_ftps_uploader_hidden.vbs` - VBScript 完全隱藏執行
- `build_uploader_no_console.bat` - 編譯隱藏版執行檔
- `setup_scheduler.ps1` - 自動設定工作排程
- `config.uploader.properties` - 主要配置檔
- `config.uploader.example2.properties` - 進階配置範例

## 建議的工作流程

1. **初次設定**:
   - 修改 `config.uploader.properties` 設定
   - 使用 `ftps-uploader.exe` 測試連線和上傳
   - 確認功能正常後，執行 `setup_scheduler.ps1` 設定排程

2. **日常運作**:
   - 由工作排程自動執行 `ftps-uploader-hidden.exe`
   - 定期檢查日誌檔確認執行狀態

3. **問題排查**:
   - 使用 `ftps-uploader.exe` 手動執行
   - 查看視窗輸出找出問題
   - 修正後繼續使用隱藏版

## 安全性注意事項

1. **配置檔保護**: 配置檔包含 FTP 密碼，請妥善保管
2. **日誌權限**: 確保日誌目錄有適當的存取權限
3. **排程權限**: 工作排程建議使用特定的服務帳號執行
