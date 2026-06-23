# 版本更新記錄

## 2026-03-05 - 下載器與上傳器：自動清理與單一實例功能 🆕

### 新增功能

#### 🗑️ 日誌自動清理（下載器 + 上傳器）
- 每次啟動時自動刪除超過 **3 天**的舊日誌檔案
- 保持日誌目錄整潔，避免佔用過多硬碟空間
- 清理過程會詳細記錄到日誌中（檔案名稱、修改時間、檔案大小）
- 顯示清理統計資訊（刪除檔案數、釋放空間）
- 下載器可透過 `log_retention_days` 參數設定保留天數（預設 3 天）

#### 🔒 單一執行實例控制（下載器 + 上傳器）
- 確保同時只有一個程式實例在執行
- 使用 Windows Mutex 機制偵測已存在的執行實例
- 自動終止舊的執行實例後啟動新程式
- 避免多個實例同時執行造成衝突或資源浪費
- 支援監控模式的重啟需求

### 技術實作

#### 下載器實作
```go
// 單一實例控制
func ensureSingleInstance() error
func killExistingDownloaderProcess() error

// 日誌清理（增強版）
func cleanOldLogs(logDir string, keepDays int) error
func formatFileSize(size int64) string
```

#### 上傳器實作
```go
// 單一實例控制
func ensureSingleInstance() error
func killExistingProcess() error

// 日誌清理
func cleanupOldLogs(logDir string, retentionDays int)
func formatFileSize(size int64) string
```

### 執行流程變更

#### 下載器啟動流程
```
1. 輸出啟動訊息
2. 【單一實例檢查】- 偵測並終止舊實例
3. 解析命令列參數
4. 載入設定檔
5. 建立本地和日誌目錄
6. 設置日誌輸出
7. 【日誌清理】- 刪除超過 N 天的日誌
8. 執行參數驗證
9. 開始下載作業
```

#### 上傳器啟動流程
```
1. 載入設定檔
2. 建立日誌目錄和檔案
3. 【單一實例檢查】- 偵測並終止舊實例
4. 【日誌清理】- 刪除超過 3 天的日誌
5. 執行參數驗證
6. 開始上傳作業
```

### VBS 腳本簡化

- **移除權限依賴**: 不再使用 WMI 檢查和終止程式（需要管理員權限）
- **委託給 Go 程式**: 單一實例控制由 Go 程式自動處理
- **避免權限錯誤**: 解決 800A0046 "沒有使用權限" 錯誤
- **簡化邏輯**: VBS 只負責以隱藏視窗執行主程式

修改檔案：
- `run_ftps_downloader_hidden.vbs` - 下載器 VBS 腳本
- `run_ftps_uploader_hidden.vbs` - 上傳器 VBS 腳本

### 使用場景

#### 1. 手動重啟
不需要手動關閉舊程式：
```bash
ftps-downloader.exe  # 自動終止舊實例
ftps-uploader.exe    # 自動終止舊實例
```

#### 2. 排程重啟
適合 Windows 工作排程器定期重啟：
- 每天自動重啟程式
- 自動清理舊日誌
- 避免多個實例同時執行

#### 3. 監控模式重啟
即使監控模式在執行，也可以直接重啟：
```bash
run_ftps_downloader.bat  # 舊的監控程式會被終止
run_ftps_uploader.bat    # 舊的監控程式會被終止
```

### 日誌範例

#### 單一實例檢查
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【執行實例檢查】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  偵測到已有執行中的程式實例
正在終止舊的執行實例...
🔫 終止程式 PID: 12345
✓ 已終止 PID: 12345
✓ 舊實例已終止，繼續執行新程式
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### 日誌清理
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【日誌清理】檢查日誌目錄: D:\logs
保留天數: 3 天 (刪除 2026-03-02 之前的日誌)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🗑️  已刪除: ftps-downloader-2026-02-28.log (修改時間: 2026-02-28 23:59:58, 大小: 325.8 KB)
🗑️  已刪除: ftps-downloader-2026-03-01.log (修改時間: 2026-03-01 18:30:22, 大小: 189.2 KB)
✓ 清理完成: 刪除 2 個舊日誌檔案，釋放空間 515.0 KB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 相關文件

- [DOWNLOADER_AUTO_CLEANUP_GUIDE.md](DOWNLOADER_AUTO_CLEANUP_GUIDE.md) - 下載器詳細功能說明
- [UPLOADER_AUTO_CLEANUP_GUIDE.md](UPLOADER_AUTO_CLEANUP_GUIDE.md) - 上傳器詳細功能說明

---

## 2026-01-07 v2 - 自動停止時間功能 🆕

### 新增功能

#### 🆕 自動停止時間
- 可設定程式在指定時間自動關閉
- 格式：`HH:mm`（例如：`18:00`）
- 程式會在每次檢查時判斷是否已過該時間
- 到達指定時間後優雅地停止並結束
- 適合搭配 Windows 工作排程器實現每天定時啟動和停止

### 設定參數

新增設定參數：

| 參數 | 說明 | 預設值 |
|------|------|--------|
| `stop_time` | 自動停止時間 | 空（不自動停止） |

### 命令列參數

新增命令列參數：

```bash
-stop-time string  # 自動停止時間（HH:mm）
```

### 使用範例

#### 設定檔方式

```properties
# 每天早上 6 點啟動（由工作排程器），晚上 6 點自動停止
monitor_mode=true
check_interval=30
stop_time=18:00
```

#### 命令列方式

```bash
ftps-downloader.exe -monitor-mode -check-interval 30 -stop-time "18:00"
```

### 典型應用場景

1. **每天定時運行**
   - 工作排程器：每天早上 6:00 啟動
   - 程式設定：`stop_time=18:00`
   - 結果：程式每天運行 12 小時後自動停止

2. **配合下載時間範圍**
   ```properties
   monitor_mode=true
   check_interval=30
   allowed_time_range=02:00-05:00  # 凌晨 2-5 點下載
   stop_time=08:00                  # 早上 8 點停止
   ```
   - 凌晨 2-5 點：執行下載
   - 5-8 點：待機（不下載但持續監控）
   - 早上 8 點：自動停止

### 更新檔案

- **main.go** - 新增自動停止時間檢查功能
- **config.properties.example** - 更新設定說明
- **config.monitor.example.properties** - 新增 stop_time 設定
- **MONITOR_MODE_GUIDE.md** - 新增自動停止時間說明
- **README.md** - 更新使用範例

### 向後相容性

✅ 完全向後相容
- 如果不設定 `stop_time`，程式行為與之前版本完全相同
- 不影響現有設定和使用方式

---

## 2026-01-07 v1 - 全天監控模式更新

### 新增功能

#### 🆕 全天監控模式
- 程式可持續運行，定期自動檢查並下載檔案
- 適合需要定時從 FTPS 伺服器下載資料的場景
- 支援背景執行，不顯示視窗

#### 🆕 時間範圍控制
- 可設定只在特定時間段下載
- 格式：`HH:mm-HH:mm`（例如：`02:00-05:00`）
- 支援跨午夜時間範圍（例如：`22:00-04:00`）
- 非下載時間會跳過下載，但繼續監控

#### 🆕 檢查間隔設定
- 可自訂檢查間隔（單位：分鐘）
- 預設 30 分鐘
- 建議最少 15 分鐘，避免過度占用資源

### 設定參數

新增以下設定參數：

| 參數 | 說明 | 預設值 |
|------|------|--------|
| `monitor_mode` | 啟用監控模式 | `false` |
| `check_interval` | 檢查間隔（分鐘） | `30` |
| `allowed_time_range` | 下載時間範圍 | 空（任何時間） |

### 命令列參數

新增以下命令列參數：

```bash
-monitor-mode              # 啟用監控模式
-check-interval int        # 檢查間隔（分鐘）
-allowed-time-range string # 時間範圍（HH:mm-HH:mm）
```

### 使用範例

#### 設定檔方式

```properties
# 啟用監控模式
monitor_mode=true

# 每 30 分鐘檢查
check_interval=30

# 只在凌晨 2-5 點下載
allowed_time_range=02:00-05:00
```

#### 命令列方式

```bash
ftps-downloader.exe -monitor-mode -check-interval 30 -allowed-time-range "02:00-05:00"
```

### 新增檔案

1. **MONITOR_MODE_GUIDE.md** - 監控模式完整使用指南
2. **config.monitor.example.properties** - 監控模式設定檔範例
3. **run_ftps_downloader_monitor.bat** - 前台執行腳本
4. **run_ftps_downloader_monitor_hidden.vbs** - 背景執行腳本
5. **test_monitor_mode.bat** - 測試腳本

### 更新檔案

1. **main.go** - 新增監控模式核心功能
2. **config.properties.example** - 新增監控模式設定說明
3. **README.md** - 更新文件，新增監控模式說明

### 升級指南

如果您已經在使用舊版本，升級步驟如下：

1. 重新編譯程式：
   ```bash
   go build -o ftps-downloader.exe main.go
   ```

2. 如果需要使用監控模式，在設定檔中添加：
   ```properties
   monitor_mode=true
   check_interval=30
   allowed_time_range=02:00-05:00
   ```

3. 如果不使用監控模式，程式行為與之前完全相同

### 向後相容性

✅ 完全向後相容
- 如果不啟用 `monitor_mode`，程式行為與之前版本完全相同
- 所有舊的設定檔和命令列參數都可以繼續使用
- 預設關閉監控模式，不影響現有使用方式

### 已知限制

1. 監控模式下程式會持續運行，占用系統資源（雖然很少）
2. 時間範圍檢查基於本機系統時間
3. 建議檢查間隔至少 15 分鐘

### 建議使用場景

- ✅ 適合：需要定期從 FTPS 伺服器下載最新資料
- ✅ 適合：需要在特定時間段下載（例如離峰時段）
- ✅ 適合：需要持續監控並自動下載
- ❌ 不適合：只需要執行一次的下載任務（使用預設模式即可）
- ❌ 不適合：需要即時響應的場景（建議使用更短的檢查間隔或其他方案）

### 技術細節

- 使用 Go 的 `time.Sleep` 實現間隔等待
- 時間範圍檢查支援跨午夜
- 循環執行時會捕獲錯誤並繼續運行
- 可使用 Ctrl+C 優雅停止

### 回饋與支援

如有問題或建議，請參考：
- [監控模式使用指南](MONITOR_MODE_GUIDE.md)
- [README.md](README.md)
