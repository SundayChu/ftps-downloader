# 版本更新記錄

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
