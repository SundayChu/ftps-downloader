# 智慧下載功能指南

## 功能說明

智慧下載功能可以自動比對本地和遠端檔案，只在必要時才下載檔案，避免重複下載相同內容，節省時間和頻寬。

## 主要特性

### 1. 檔案存在檢查
- 自動檢查本地檔案是否已存在
- 如果檔案不存在，則下載

### 2. 檔案比對方式

#### 方式一：檔案大小比對（預設）
- 比對本地和遠端檔案的大小
- 如果大小相同，視為相同檔案，跳過下載
- 如果大小不同，則重新下載
- **優點**：速度快，適合大多數場景
- **缺點**：無法偵測內容修改但大小相同的情況

#### 方式二：修改時間比對
- 比對本地和遠端檔案的修改時間
- 如果遠端檔案較新，則重新下載
- 如果本地檔案較新或相同，則跳過下載
- **優點**：更準確，可偵測檔案更新
- **缺點**：需要 FTP 伺服器支援 MLSD 命令

### 3. 強制下載模式
- 忽略所有檢查，強制下載所有檔案
- 適用於需要確保檔案一致性的情況

## 設定方式

### 在設定檔中設定

編輯 `config.properties`：

```properties
# 啟用智慧下載（檢查本地檔案，只下載不存在或較新的檔案）
skip_if_exists=true

# 使用修改時間進行比對（如果為 false 則使用檔案大小比對）
compare_by_modtime=false

# 強制下載所有檔案（忽略本地檔案狀態）
# 注意：此選項會覆蓋 skip_if_exists 設定
force_download=false
```

### 使用命令列參數

```bash
# 啟用智慧下載（預設使用檔案大小比對）
ftps-downloader.exe -skip-if-exists

# 使用修改時間比對
ftps-downloader.exe -skip-if-exists -compare-by-modtime

# 強制下載所有檔案
ftps-downloader.exe -force-download
```

## 使用場景

### 場景 1：定期自動下載（推薦）

**需求**：每天定期執行，只下載新檔案或更新的檔案

**設定**：
```properties
skip_if_exists=true
compare_by_modtime=false
monitor_mode=true
check_interval=30
```

**效果**：
- 每 30 分鐘檢查一次
- 只下載大小不同的檔案
- 減少不必要的下載和處理時間

### 場景 2：確保檔案最新

**需求**：確保本地檔案是最新版本

**設定**：
```properties
skip_if_exists=true
compare_by_modtime=true
```

**效果**：
- 根據修改時間判斷
- 只有遠端檔案較新時才下載
- 避免覆蓋較新的本地檔案

### 場景 3：完全同步

**需求**：每次都重新下載所有檔案，確保完全一致

**設定**：
```properties
force_download=true
```

**效果**：
- 忽略所有檢查
- 每次都重新下載
- 適用於檔案內容可能變更但大小相同的情況

### 場景 4：首次下載

**需求**：首次執行，下載所有檔案

**設定**：
```properties
skip_if_exists=false
```

**效果**：
- 不檢查本地檔案
- 下載所有指定的檔案
- 覆蓋已存在的檔案

## 日誌訊息說明

### 跳過下載
```
⊘ Skipping BONDW -> BONDW (file is identical (size: 12345 bytes))
```
表示本地檔案與遠端檔案相同，跳過下載。

### 需要下載
```
⟳ Need to download BONDW: file size differs (remote: 12345 bytes, local: 12000 bytes)
```
表示偵測到差異，需要重新下載。

### 首次下載
```
⟳ Need to download BONDW: local file does not exist
```
表示本地檔案不存在，首次下載。

### 修改時間比對
```
⟳ Need to download BONDW: remote file is newer (remote: 2026-01-14 10:30:00, local: 2026-01-14 09:00:00)
```
表示遠端檔案較新，需要下載。

```
⊘ Skipping BONDW -> BONDW (local file is up-to-date (remote: 2026-01-14 09:00:00, local: 2026-01-14 10:30:00))
```
表示本地檔案較新或相同，跳過下載。

## 注意事項

1. **修改時間比對的限制**
   - 需要 FTP 伺服器支援 MLSD 或 LIST 命令
   - 某些伺服器可能不提供準確的修改時間
   - 如果無法取得修改時間，會自動降級為大小比對

2. **檔案處理與比對**
   - 比對是針對「下載前的原始檔案」進行
   - 如果啟用了編碼轉換或 Guardian 格式處理，會在下載後處理
   - 處理後的檔案大小可能與遠端不同

3. **監控模式的建議**
   - 建議啟用 `skip_if_exists=true`
   - 可大幅減少不必要的下載
   - 降低網路流量和 CPU 使用率

4. **強制下載的使用時機**
   - 懷疑本地檔案損壞
   - 需要確保與遠端完全一致
   - 測試下載流程

## 效能優勢

### 啟用智慧下載前
```
檔案 A: 10 MB, 已存在且相同 → 下載 10 MB
檔案 B: 20 MB, 已存在且相同 → 下載 20 MB
檔案 C: 5 MB, 不存在 → 下載 5 MB
總計：下載 35 MB
```

### 啟用智慧下載後
```
檔案 A: 10 MB, 已存在且相同 → 跳過（檢查 < 1 KB）
檔案 B: 20 MB, 已存在且相同 → 跳過（檢查 < 1 KB）
檔案 C: 5 MB, 不存在 → 下載 5 MB
總計：下載 5 MB（節省 85.7% 流量）
```

## 疑難排解

### 問題：總是重複下載相同檔案

**原因**：未啟用 `skip_if_exists`

**解決方式**：
```properties
skip_if_exists=true
```

### 問題：修改時間比對不生效

**原因**：FTP 伺服器不支援或權限不足

**解決方式**：
```properties
# 改用檔案大小比對
compare_by_modtime=false
```

### 問題：需要強制重新下載某個檔案

**方式 1**：刪除本地檔案後執行

**方式 2**：臨時啟用強制下載
```bash
ftps-downloader.exe -force-download
```

**方式 3**：修改設定檔
```properties
force_download=true
```
執行後記得改回 `false`

## 最佳實踐

1. **日常使用**：啟用 `skip_if_exists=true`，使用大小比對
2. **關鍵資料**：使用修改時間比對，確保資料最新
3. **測試環境**：使用強制下載，確保完全同步
4. **監控模式**：搭配智慧下載，減少資源消耗
5. **定期清理**：定期清理不再需要的舊檔案，避免累積過多檔案

## 相關文件

- [README.md](README.md) - 主要功能說明
- [MONITOR_MODE_GUIDE.md](MONITOR_MODE_GUIDE.md) - 監控模式使用指南
- [config.properties.example](config.properties.example) - 設定檔範例
