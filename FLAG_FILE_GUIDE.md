# 結帳檔檢查功能使用指南

## 功能說明

結帳檔（Flag File）檢查功能可以讓下載程式確保資料檔案已經完成寫入。這個功能常用於 Guardian/NonStop 系統，在完成資料更新後會產生一個結帳檔（如 `DATCLOSE`）來表示資料已經就緒。

### 工作機制（2026-02-19 更新）

新版本採用**兩階段檢查機制**：

1. **階段一：下載結帳檔**
   - 程式啟動後，先從指定的專用路徑（`flag_file_path`）下載 DATCLOSE 檔案
   - 如果遠端 DATCLOSE 不存在或下載失敗，會記錄警告但繼續執行

2. **階段二：檢查本地結帳檔**
   - 對於啟用 `check_flag_file=true` 的路徑，檢查本地是否存在**當天的** DATCLOSE
   - 只有本地存在當天的 DATCLOSE 時，才下載該路徑的檔案

3. **階段三：自動清理**
   - 所有下載完成後，自動刪除本地的 DATCLOSE 檔案（如果啟用 `auto_delete_flag_file`）

## 配置方式

### 全局配置（DATCLOSE 下載設定）

在 `config.properties` 中設定：

```properties
# 結帳檔名稱
flag_file_name=DATCLOSE

# 結帳檔專用下載路徑（程式會先從這個路徑下載 DATCLOSE）
flag_file_path=\CSTP96.$DATA.SKWORK

# 下載完成後自動刪除 DATCLOSE（預設 true）
auto_delete_flag_file=true
```

### 針對特定路徑啟用檢查

為需要檢查結帳檔的路徑映射添加配置：

```properties
# 路徑 1：需要檢查本地 DATCLOSE
file_names.1.remote_path=\CSTP96.$DATA.SKINTER1
file_names.1.check_flag_file=true
file_names.1.flag_file_name=DATCLOSE
file_names.1.files.0=BONDW

# 路徑 2：不需要檢查結帳檔，直接下載
file_names.2.remote_path=\CSTP96.$DATA.SKOTC000
file_names.2.files.0=RO60
file_names.2.files.1=RT30
```

## 配置參數

| 參數 | 層級 | 說明 | 範例 | 必填 |
|------|------|------|------|------|
| `flag_file_name` | 全局 | 結帳檔名稱 | `DATCLOSE` | 是 |
| `flag_file_path` | 全局 | DATCLOSE 專用下載路徑 | `\CSTP96.$DATA.SKWORK` | 建議設定 |
| `auto_delete_flag_file` | 全局 | 下載完成後自動刪除 DATCLOSE | `true` / `false` | 否（預設 true）|
| `file_names.N.check_flag_file` | 路徑 | 是否啟用本地結帳檔檢查 | `true` / `false` | 否 |
| `file_names.N.flag_file_name` | 路徑 | 結帳檔名稱（覆蓋全局設定）| `DATCLOSE` | 否 |

## 運作流程

```
1. 連線到 FTPS 伺服器

2. 【階段一】下載結帳檔
   ├─ 檢查是否設定 flag_file_path
   │  ├─ 未設定 → 跳過此階段
   │  └─ 已設定 → 嘗試下載 DATCLOSE
   │     ├─ 成功 → ✓ 下載到本地
   │     └─ 失敗 → ⚠️ 記錄警告，繼續執行
   
3. 【階段二】下載資料檔案
   └─ 對每個 file_names 配置：
      ├─ 檢查此路徑是否啟用 check_flag_file
      │  ├─ 未啟用 → 直接下載檔案
      │  └─ 已啟用 → 檢查本地 DATCLOSE
      │     ├─ 不存在或不是當天 → ⏭️ 跳過此路徑
      │     └─ 存在且是當天 → ✓ 下載檔案
      
4. 【階段三】清理結帳檔
   └─ 檢查 auto_delete_flag_file
      ├─ false → 保留 DATCLOSE
      └─ true → 🗑️ 刪除本地 DATCLOSE
```

## 日誌輸出

### 階段一：下載結帳檔

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【下載結帳檔】開始下載 DATCLOSE...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 遠端路徑: \CSTP96.$DATA.SKWORK.DATCLOSE
✓ 遠端結帳檔存在 (大小: 512 bytes)
✅ 結帳檔下載成功: DATCLOSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 階段二：檢查本地結帳檔並下載

當本地結帳檔存在：
```
🔍 檢查本地結帳檔: DATCLOSE
✓ 本地結帳檔存在，開始下載檔案
⬇  Downloading: BONDW ...
✅ Download successful: BONDW
```

當本地結帳檔不存在或不是當天：
```
🔍 檢查本地結帳檔: DATCLOSE
⏭️  跳過目錄 \CSTP96.$DATA.SKINTER1：本地結帳檔 DATCLOSE 不存在或不是當天的檔案
```

### 階段三：自動清理

```
Download completed. 5 file(s) downloaded.
🗑️  已刪除結帳檔: DATCLOSE
```

## 使用場景

### 場景 1：標準 DATCLOSE 檢查流程

遠端系統在完成資料更新後，會在特定路徑產生 DATCLOSE：

```properties
# 全局設定：DATCLOSE 下載來源
flag_file_name=DATCLOSE
flag_file_path=\CSTP96.$DATA.SKWORK
auto_delete_flag_file=true

# 路徑 1：需要檢查本地 DATCLOSE
file_names.1.remote_path=\CSTP96.$DATA.SKINTER1
file_names.1.check_flag_file=true
file_names.1.files.0=BONDW
file_names.1.files.1=TCD5920

# 路徑 2：需要檢查本地 DATCLOSE
file_names.2.remote_path=\CSTP96.$DATA.SKOTC000
file_names.2.check_flag_file=true
file_names.2.files.0=RO60
```

**工作流程**：
1. 從 `\CSTP96.$DATA.SKWORK` 下載 DATCLOSE
2. 檢查本地是否有今天的 DATCLOSE
3. 如果有，下載路徑 1 和路徑 2 的檔案
4. 下載完成後自動刪除 DATCLOSE

### 場景 2：混合配置（部分路徑需檢查）

```properties
# 全局設定
flag_file_name=DATCLOSE
flag_file_path=\CSTP96.$DATA.SKWORK
auto_delete_flag_file=true

# 路徑 1：需要檢查本地 DATCLOSE
file_names.1.remote_path=\CSTP96.$DATA.SKINTER1
file_names.1.check_flag_file=true
file_names.1.files.0=BONDW

# 路徑 2：不需要檢查，直接下載
file_names.2.remote_path=\CSTP96.$DATA.SKOTC000
file_names.2.files.0=RO60
file_names.2.files.1=RT30
```

**說明**：
- 路徑 1：先檢查本地 DATCLOSE，存在才下載 BONDW
- 路徑 2：直接下載 RO60 和 RT30，不檢查結帳檔

### 場景 3：搭配監控模式（每日自動清理）

```properties
# 監控模式設定
monitor_mode=true
check_interval=30
allowed_time_range=02:00-05:00

# DATCLOSE 設定
flag_file_name=DATCLOSE
flag_file_path=\CSTP96.$DATA.SKWORK
auto_delete_flag_file=true

# 檔案路徑設定
file_names.1.remote_path=\CSTP96.$DATA.SKINTER1
file_names.1.check_flag_file=true
file_names.1.files.0=TCD5920
```

**說明**：
- 每 30 分鐘檢查一次
- 只在凌晨 2-5 點之間執行
- 每次循環都會：下載 DATCLOSE → 檢查本地 → 下載檔案 → 刪除 DATCLOSE
- 確保每次都是使用最新的 DATCLOSE

## 注意事項

1. **權限要求**：確保 FTPS 帳號有權限讀取 DATCLOSE 檔案
2. **路徑正確性**：確認 `flag_file_path` 與遠端系統的命名規則一致
3. **當天檔案判定**：檢查本地 DATCLOSE 時，會判斷檔案修改時間是否為當天
4. **自動清理**：預設會在下載完成後自動刪除 DATCLOSE，確保下次使用最新版本
5. **錯誤處理**：即使 DATCLOSE 下載失敗，程式仍會繼續執行（只會記錄警告）
6. **監控模式**：在監控模式下，每次循環都會重新下載並檢查 DATCLOSE

## 與舊版本的差異

### 舊版邏輯（已棄用）
- 檢查**遠端**路徑的結帳檔是否存在
- 每個路徑獨立檢查遠端檔案

### 新版邏輯（2026-02-19）
- 階段一：先從專用路徑下載 DATCLOSE 到本地
- 階段二：檢查**本地**是否有當天的 DATCLOSE
- 階段三：下載完成後自動清理 DATCLOSE

### 優點
✅ 減少遠端檔案系統存取次數  
✅ 確保所有路徑使用同一份 DATCLOSE  
✅ 自動清理機制避免使用過期的結帳檔  
✅ 更符合實際業務流程（集中管理結帳狀態）

## 疑難排解

### 問題 1：DATCLOSE 下載失敗但程式繼續執行

**現象**：
```
⚠️  遠端結帳檔不存在或無法讀取: ...
ℹ️  繼續執行其他下載作業...
```

**說明**：這是正常行為。DATCLOSE 下載失敗時，程式會：
- 記錄警告訊息
- 繼續執行其他下載作業
- 對於啟用 `check_flag_file` 的路徑，會因本地沒有 DATCLOSE 而跳過

**解決方法**：
1. 檢查 `flag_file_path` 設定是否正確
2. 確認遠端系統是否已產生 DATCLOSE
3. 確認 FTP 帳號權限

### 問題 2：明明下載了 DATCLOSE，為何還是跳過檔案下載

**可能原因**：本地 DATCLOSE 不是當天的檔案

**檢查方法**：
```bash
# 查看 DATCLOSE 的修改時間
Get-Item downloads\DATCLOSE | Select-Object Name, LastWriteTime
```

**解決方法**：
- 手動刪除舊的 DATCLOSE，讓程式重新下載
- 或等待下次循環自動更新

### 問題 3：想要保留 DATCLOSE 不要自動刪除

**解決方法**：
```properties
auto_delete_flag_file=false
```

### 問題 4：如何手動測試

**測試步驟**：
```bash
# 1. 執行一次下載（會下載並刪除 DATCLOSE）
.\ftps-downloader.exe

# 2. 如果想保留 DATCLOSE 進行測試
# 設定 auto_delete_flag_file=false

# 3. 檢查 DATCLOSE 是否存在
Get-Item downloads\DATCLOSE
```

## 相關功能

- [監控模式指南](MONITOR_MODE_GUIDE.md)：了解如何設定自動監控下載
- [時間範圍控制](DOWNLOADER_FILTER_GUIDE.md)：限制下載時間範圍
- [檔案篩選功能](DOWNLOADER_FILTER_GUIDE.md)：使用萬用字元和前後綴篩選

## 更新記錄

- **2026-02-19 v2**：重大更新 - 改為兩階段檢查機制
  - 新增 `flag_file_path` 配置，支援從專用路徑下載 DATCLOSE
  - 新增 `auto_delete_flag_file` 配置，自動清理 DATCLOSE
  - 修改檢查邏輯：從檢查遠端檔案改為檢查本地檔案
  - 支援當天日期判定，確保使用最新的 DATCLOSE
  
- **2026-02-19 v1**：將結帳檔檢查功能從全局配置改為路徑級別配置
  - 支援每個路徑映射獨立設定是否檢查結帳檔
  - 全局配置保留以維持向後兼容性（但已標記為棄用）
