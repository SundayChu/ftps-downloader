# FTPS Downloader 全天監控模式使用指南

## 功能說明

全天監控模式讓下載程式可以持續運行，定期自動檢查並下載檔案。適合需要定時從 FTPS 伺服器下載資料的場景。

## 主要特色

1. **定時檢查**：程式會按照設定的間隔定期檢查是否需要下載
2. **時間範圍控制**：可設定只在特定時間段下載（例如：凌晨 2-5 點）
3. **背景運行**：可配合 VBS 腳本在背景執行，不顯示視窗
4. **日誌記錄**：所有操作都會記錄到日誌檔案

## 設定說明

在 `config.properties` 中添加以下設定：

```properties
# 啟用全天監控模式
monitor_mode=true

# 檢查間隔（分鐘）
check_interval=30

# 允許下載的時間範圍（格式：HH:mm-HH:mm）
allowed_time_range=02:00-05:00

# 自動停止時間（格式：HH:mm）🆕
stop_time=18:00
```

### 設定選項詳解

| 選項 | 說明 | 預設值 | 範例 |
|------|------|--------|------|
| `monitor_mode` | 是否啟用監控模式 | `false` | `true` 或 `false` |
| `check_interval` | 檢查間隔（分鐘） | `30` | `15`、`30`、`60` |
| `allowed_time_range` | 下載時間範圍 | 空（任何時間） | `02:00-05:00`、`22:00-04:00` |
| `stop_time` 🆕 | 自動停止時間 | 空（不自動停止） | `18:00`、`23:30` |

### 時間範圍設定說明

- 格式：`HH:mm-HH:mm`（24 小時制）
- 支援跨午夜時間範圍
  - 例如：`22:00-04:00` 表示晚上 10 點到隔天凌晨 4 點
- 如果不設定，則任何時間都可以下載

### 自動停止時間說明 🆕

- 格式：`HH:mm`（24 小時制）
- 程式會在每次檢查時判斷是否已過該時間
- 到達指定時間後程式會優雅地停止並結束
- 適合需要每天定時關閉再重新啟動的場景
- 搭配 Windows 工作排程器可實現：
  - 每天早上自動啟動程式
  - 每天晚上自動關閉程式
- 如果不設定，則程式會持續運行直到手動停止

## 使用方式

### 方式一：前台運行（顯示視窗）

適合測試和偵錯使用。

```batch
# 直接執行程式
ftps-downloader.exe

# 或使用批次檔
run_ftps_downloader_monitor.bat
```

程式會顯示：
- 監控模式啟動訊息
- 每次檢查的時間
- 是否在允許的時間範圍內
- 下載結果
- 下次檢查時間

按 `Ctrl+C` 可停止監控。

### 方式二：背景運行（隱藏視窗）

適合正式環境使用。

1. 直接執行 VBS 腳本：
   ```
   run_ftps_downloader_monitor_hidden.vbs
   ```

2. 或建立 Windows 工作排程器任務：
   - 觸發程序：系統啟動時
   - 動作：執行 `run_ftps_downloader_monitor_hidden.vbs`
   - 設定：背景執行

## 使用範例

### 範例一：每小時檢查一次，任何時間都下載

```properties
monitor_mode=true
check_interval=60
# 不設定 allowed_time_range
```

### 範例二：每 30 分鐘檢查，只在凌晨 2-5 點下載

```properties
monitor_mode=true
check_interval=30
allowed_time_range=02:00-05:00
```

這個設定下：
- 凌晨 2:00-5:00：每 30 分鐘檢查並下載
- 其他時間：每 30 分鐘檢查，但跳過下載

### 範例三：每 15 分鐘檢查，晚上 10 點到凌晨 4 點下載

```properties
monitor_mode=true
check_interval=15
allowed_time_range=22:00-04:00
```

### 範例四：早上 6 點啟動，晚上 6 點自動關閉 🆕

```properties
monitor_mode=true
check_interval=30
stop_time=18:00
```

這個設定下：
- 程式持續運行
- 每 30 分鐘檢查並下載（任何時間）
- 晚上 6 點自動停止

搭配 Windows 工作排程器：
- 觸發程序：每天早上 6:00 啟動
- 程式會自動在晚上 6:00 停止

### 範例五：只在凌晨 2-5 點下載，早上 8 點自動關閉 🆕

```properties
monitor_mode=true
check_interval=30
allowed_time_range=02:00-05:00
stop_time=08:00
```

這個設定下：
- 凌晨 2:00-5:00：每 30 分鐘檢查並下載
- 5:00-8:00：每 30 分鐘檢查但跳過下載
- 早上 8:00：自動停止程式

### 範例六：搭配命令列參數使用

如果不想修改設定檔，可以直接使用命令列參數：

```batch
# 監控模式，每 30 分鐘檢查，晚上 6 點自動停止
ftps-downloader.exe -monitor-mode -check-interval 30 -stop-time "18:00"

# 監控模式，只在凌晨 2-5 點下載，早上 8 點自動停止
ftps-downloader.exe -monitor-mode -check-interval 30 -allowed-time-range "02:00-05:00" -stop-time "08:00"
```

## 日誌檢視

所有操作都會記錄到 `log_dir` 指定的目錄中：

```properties
log_dir=./logs
```

日誌檔案命名格式：`ftps-downloader-YYYY-MM-DD.log`

例如：`ftps-downloader-2026-01-07.log`

## 停止監控

### 前台運行時
按 `Ctrl+C` 即可停止

### 背景運行時
1. 開啟工作管理員（Ctrl+Shift+Esc）
2. 找到 `ftps-downloader.exe` 程序
3. 結束該程序

## 注意事項

1. **確保設定檔正確**
   - 檢查連線參數是否正確
   - 測試連線是否正常
   - 建議先以前台模式測試

2. **日誌檔案管理**
   - 日誌檔案會持續增長
   - 建議定期清理舊的日誌檔案
   - 或使用日誌輪轉工具

3. **系統資源**
   - 監控模式會持續占用少量系統資源
   - 檢查間隔越短，資源占用越多
   - 建議間隔至少 15 分鐘

4. **時間同步**
   - 確保系統時間正確
   - 時間範圍檢查基於本機系統時間

5. **網路連線**
   - 確保網路連線穩定
   - 如果連線失敗，程式會記錄錯誤並繼續等待下次檢查

## 與排程器比較

| 功能 | 監控模式 | Windows 工作排程器 |
|------|----------|-------------------|
| 設定複雜度 | 簡單，只需設定檔 | 需要設定排程任務 |
| 資源占用 | 持續運行 | 只在執行時占用 |
| 時間精確度 | 每次檢查時判斷 | 排程器控制 |
| 適用場景 | 需要持續監控 | 固定時間執行 |

建議：
- 如果需要在特定時間範圍內頻繁檢查，使用監控模式
- 如果只需要在固定時間執行一次，使用排程器

## 故障排除

### 問題：程式啟動後立即關閉

**解決方法**：
1. 檢查設定檔是否存在且格式正確
2. 以前台模式執行查看錯誤訊息
3. 檢查日誌檔案

### 問題：時間範圍內沒有下載

**解決方法**：
1. 確認時間範圍設定正確
2. 檢查系統時間是否正確
3. 查看日誌檔案確認是否有錯誤

### 問題：背景執行時找不到程序

**解決方法**：
1. 檢查工作管理員中的「詳細資料」頁籤
2. 確認 VBS 腳本執行成功
3. 檢查日誌檔案是否有新記錄

## 進階用法

### 搭配 Windows 服務

可以使用 NSSM (Non-Sucking Service Manager) 將程式註冊為 Windows 服務：

```batch
nssm install FTPSDownloader "C:\path\to\ftps-downloader.exe"
nssm set FTPSDownloader AppDirectory "C:\path\to\ftps-downloader"
nssm start FTPSDownloader
```

### 監控程式狀態

可以建立監控腳本定期檢查程式是否運行：

```powershell
# check_downloader.ps1
$process = Get-Process -Name "ftps-downloader" -ErrorAction SilentlyContinue
if ($null -eq $process) {
    Write-Host "下載程式未運行，正在啟動..."
    Start-Process "run_ftps_downloader_monitor_hidden.vbs"
}
```

## 相關檔案

- `config.monitor.example.properties` - 監控模式設定檔範例
- `run_ftps_downloader_monitor.bat` - 前台執行腳本
- `run_ftps_downloader_monitor_hidden.vbs` - 背景執行腳本
- `config.properties.example` - 完整設定檔範例（含監控模式說明）

## 更新記錄

- 2026-01-07：新增全天監控模式功能
