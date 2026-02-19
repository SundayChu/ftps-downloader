# 日誌功能指南

## 📋 目錄
- [獨立檔案日誌](#獨立檔案日誌)
- [LIST 輸出控制](#list-輸出控制)
- [日誌檔案結構](#日誌檔案結構)
- [設定範例](#設定範例)

## 獨立檔案日誌

### ✨ 功能說明
為每個下載的檔案建立獨立的日誌檔案，方便追蹤個別檔案的下載歷史和問題診斷。

### 🎯 使用場景
- **批次下載追蹤**：下載多個檔案時，可分別查看各自的下載記錄
- **問題診斷**：當某個檔案下載失敗時，可直接查看該檔案的專屬日誌
- **審計需求**：需要保留每個檔案的完整下載歷史
- **效能分析**：分析不同檔案的下載時間和大小變化

### 📝 設定方式

#### **啟用獨立檔案日誌**
```properties
# config.properties
log_dir=./logs
separate_file_log=true
```

#### **停用獨立檔案日誌（預設）**
```properties
separate_file_log=false
```

### 📁 日誌檔案命名規則

```
logs/
├── ftps_downloader_20260124.log       ← 主日誌
├── download_RYM01_20260124.log        ← RYM01 的下載記錄（當天所有下載）
├── download_RYM02_20260124.log        ← RYM02 的下載記錄（當天所有下載）
└── download_EMPLYE_20260124.log       ← EMPLYE 的下載記錄（當天所有下載）
```

**命名格式**：`download_<檔案名稱>_<日期>.log`
- 日期格式：`YYYYMMDD`（如 `20260124`）
- **同一天的所有下載記錄會追加到同一個檔案**
- 自動建立在 `log_dir` 指定的目錄

**優點**：
- ✅ 同一檔案的每日記錄集中在一個檔案
- ✅ 方便追蹤每日的下載頻率和結果
- ✅ 日誌檔案數量可控，不會爆增

### 📋 日誌內容範例

#### **成功下載的日誌**
```
════════════════════════════════════════════════
📥 檔案下載日誌 - RYM01
════════════════════════════════════════════════
開始時間: 2026-01-24 10:05:23

檔案資訊:
  遠端檔案: \CSTP96.$DATA.SKDATA91\RYM01
  本地檔案: downloads/RYM01
  遠端修改時間: 2026-01-02 15:36:34
  遠端檔案大小: 4.00 KB (4096 bytes)

下載判斷:
  ➜  下載原因: 遠端檔案較新

  📥 開始下載 (檔案大小: 4096 bytes)
  ✅ 下載完成
     遠端大小: 4096 bytes
     下載大小: 4096 bytes
  ✓ 下載驗證通過 (原始資料符合遠端大小)

════════════════════════════════════════════════
結束時間: 2026-01-24 10:05:25
狀態: 下載成功
本地檔案: downloads/RYM01
最終大小: 4096 bytes
════════════════════════════════════════════════


════════════════════════════════════════════════
📥 檔案下載日誌 - RYM01
════════════════════════════════════════════════
開始時間: 2026-01-24 15:30:12

檔案資訊:
  遠端檔案: \CSTP96.$DATA.SKDATA91\RYM01
  本地檔案: downloads/RYM01
  遠端修改時間: 2026-01-02 15:36:34
  遠端檔案大小: 4.00 KB (4096 bytes)
  本地修改時間: 2026-01-24 10:05:25
  本地檔案大小: 4.00 KB (4096 bytes)

下載判斷:
  ⊘  檔案未更新，跳過下載
     原因: 遠端與本地檔案時間相同

════════════════════════════════════════════════
結束時間: 2026-01-24 15:30:13
狀態: 跳過下載
════════════════════════════════════════════════
```

**注意**：上面顯示的是同一個檔案（RYM01）在同一天的兩次檢查記錄，都寫入 `download_RYM01_20260124.log`

**注意**：上面顯示的是同一個檔案（RYM01）在同一天的兩次檢查記錄，都寫入 `download_RYM01_20260124.log`

#### **下載失敗的日誌**
```
════════════════════════════════════════════════
📥 檔案下載日誌 - RYM99
════════════════════════════════════════════════
開始時間: 2026-01-24 10:20:15

檔案資訊:
  遠端檔案: \CSTP96.$DATA.SKDATA91\RYM99
  本地檔案: downloads/RYM99

下載判斷:
  ➜  下載原因: 本地檔案不存在

  📥 開始下載 (無法確認檔案大小)

錯誤: 下載失敗: 550 File not found
════════════════════════════════════════════════
```

---

## LIST 輸出控制

### 🎯 功能說明
控制是否將 FTP LIST 命令的詳細輸出記錄到日誌中。LIST 輸出包含遠端目錄的所有檔案詳情。

### ⚠️ 為什麼預設隱藏？
LIST 命令輸出可能包含敏感資訊：
- 完整的檔案清單
- 檔案大小和修改時間
- 檔案權限和擁有者資訊
- 系統帳號名稱

**預設隱藏可以**：
- 減少日誌檔案大小（特別是頻繁檢查時）
- 避免洩露敏感的檔案結構資訊
- 讓日誌更清晰，專注於下載結果

### 📝 設定方式

#### **隱藏 LIST 輸出（預設）**
```properties
# config.properties
debug_list=false
```

#### **顯示 LIST 輸出（調試用）**
```properties
# 用於調試或排查問題
debug_list=true
```

### 📋 LIST 輸出範例

當 `debug_list=true` 時，日誌會包含類似這樣的內容：

```
---------- LIST 輸出 [開始] ----------
EPSV
229 Entering Extended Passive Mode (|||40123|)
LIST \CSTP96.$DATA.SKDATA91
150 Opening data connection for \CSTP96.$DATA.SKDATA91. (127.0.0.1,1403d) (0 bytes).
File         Code             EOF  Last Modification    Owner  RWEP
EMPLYE          0            53248 23-Jan-26 19:02:49 110, 99 "nnnn"
EMPLYE0         0            16384 23-Jan-26 19:02:49 110, 99 "nnnn"
EMPRELAT        0            12288 30-Nov-25 10:47:56 110, 99 "nnnn"
RYM01           0             4096  2-Jan-26 15:36:34 110, 99 "nnnn"
RYM02           0          5160960  2-Jan-26 16:26:15 110, 99 "nnnn"
RYM07           0         66834432 22-Jan-26 14:04:19 110, 99 "nunu"
226 Transfer complete.
---------- LIST 輸出 [結束] ----------
```

---

## 日誌檔案結構

### 📁 完整日誌目錄結構

```
logs/
├── ftps_downloader_20260124.log           ← 主日誌（包含所有活動）
├── download_RYM01_20260124.log            ← RYM01 當天所有下載記錄
├── download_RYM01_20260125.log            ← RYM01 隔天的下載記錄
├── download_RYM02_20260124.log            ← RYM02 當天所有下載記錄
└── download_EMPLYE_20260124.log           ← EMPLYE 當天所有下載記錄
```

**特點**：
- 每個檔案每天一個日誌檔案
- 當天的多次下載會追加到同一個日誌檔案
- 每次下載都有完整的時間戳記和分隔線

### 📊 主日誌 vs 獨立日誌

| 項目 | 主日誌 | 獨立檔案日誌 |
|------|-------|-------------|
| **檔案名稱** | `ftps_downloader_YYYYMMDD.log` | `download_<檔名>_YYYYMMDD.log` |
| **內容範圍** | 所有活動（連線、下載、監控循環） | 單一檔案在當天的所有下載記錄 |
| **適用場景** | 系統整體運行狀況 | 個別檔案的完整每日記錄 |
| **檔案大小** | 較大（累積所有記錄） | 中等（當天該檔案的所有下載） |
| **查詢速度** | 需要搜尋 | 直接定位到特定檔案和日期 |
| **記錄頻率** | 一天一個檔案 | 每個檔案每天一個檔案 |

### 🔍 查詢特定檔案的下載記錄

**PowerShell 範例**：
```powershell
# 查看 RYM01 的所有歷史記錄（所有日期）
Get-ChildItem logs\download_RYM01_*.log | Sort-Object LastWriteTime

# 查看 RYM01 在 2026-01-24 的記錄
Get-Content logs\download_RYM01_20260124.log

# 查看 RYM01 最近一週的記錄
Get-ChildItem logs\download_RYM01_*.log | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | 
    Sort-Object LastWriteTime
```

---

## 設定範例

### 📋 範例 1：生產環境（建議設定）

```properties
# config.properties

# 啟用日誌
log_dir=./logs

# 為每個檔案建立獨立日誌
separate_file_log=true

# 隱藏 LIST 輸出（保護敏感資訊）
debug_list=false

# 隱藏編碼調試資訊
debug_encoding=false
```

**適合場景**：
- 正式環境運行
- 需要保留完整下載記錄
- 注重安全性和隱私

---

### 📋 範例 2：調試模式

```properties
# config.properties

# 啟用日誌
log_dir=./logs

# 啟用獨立檔案日誌（便於追蹤問題）
separate_file_log=true

# 顯示完整 LIST 輸出（查看檔案清單）
debug_list=true

# 顯示編碼調試資訊
debug_encoding=true
```

**適合場景**：
- 排查下載問題
- 檢查檔案清單
- 編碼轉換問題診斷

---

### 📋 範例 3：簡化模式（最小日誌）

```properties
# config.properties

# 啟用日誌
log_dir=./logs

# 不建立獨立檔案日誌
separate_file_log=false

# 隱藏 LIST 輸出
debug_list=false

# 隱藏編碼調試資訊
debug_encoding=false
```

**適合場景**：
- 測試環境
- 下載檔案數量少
- 不需要保留詳細記錄

---

## 💡 使用建議

### ✅ 建議啟用獨立檔案日誌的情況
- 批次下載多個檔案
- 需要追蹤每個檔案的下載歷史
- 需要分析個別檔案的下載效能
- 有審計或合規要求

### ❌ 可以不啟用的情況
- 只下載少量檔案
- 磁碟空間有限
- 不需要保留詳細記錄

### 🔒 安全性建議
- **生產環境**：設定 `debug_list=false` 避免洩露檔案清單
- **測試環境**：可以設定 `debug_list=true` 方便調試
- **定期清理**：定期清理舊的日誌檔案釋放空間

### 🧹 日誌清理建議

**PowerShell 腳本範例**（保留最近 30 天）：
```powershell
$logDir = ".\logs"
$daysToKeep = 30

Get-ChildItem $logDir -Filter "download_*.log" | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$daysToKeep) } | 
    Remove-Item -Force

Write-Host "✓ 已清理 $daysToKeep 天前的日誌檔案"
```

---

## 🎯 快速設定指南

### 1️⃣ 標準設定（建議）
```properties
log_dir=./logs
separate_file_log=true
debug_list=false
```

### 2️⃣ 調試設定
```properties
log_dir=./logs
separate_file_log=true
debug_list=true
debug_encoding=true
```

### 3️⃣ 最小日誌設定
```properties
log_dir=./logs
separate_file_log=false
debug_list=false
```

---

## 📚 相關文件
- [README.md](README.md) - 程式總覽
- [MONITOR_MODE_GUIDE.md](MONITOR_MODE_GUIDE.md) - 監控模式說明
- [AUTO_STOP_GUIDE.md](AUTO_STOP_GUIDE.md) - 自動停止功能
- [FILE_COMPARISON_GUIDE.md](FILE_COMPARISON_GUIDE.md) - 檔案比對策略
