# 前綴/後綴批次重命名功能說明

## 功能概述

當使用前綴或後綴篩選下載檔案時，可以批次修改下載檔案的前綴或後綴名稱。

## 配置語法

```properties
# 基本篩選
file_names.0.include_prefixes.0=TCD
file_names.0.include_suffixes.0=.5920

# 批次重命名前綴
file_names.0.rename_prefix.0=TCD:DATA
file_names.0.rename_prefix.1=TSC:INFO

# 批次重命名後綴
file_names.0.rename_suffix.0=.5920:.txt
file_names.0.rename_suffix.1=.dat:.data
```

## 配置說明

### 前綴重命名 (rename_prefix)
格式: `舊前綴:新前綴`

**範例**:
```properties
file_names.0.rename_prefix.0=TCD:DATA
```
- 下載 `TCD5920` → 儲存為 `DATA5920`
- 下載 `TCD5921` → 儲存為 `DATA5921`
- 下載 `TCDABC` → 儲存為 `DATAABC`

### 後綴重命名 (rename_suffix)
格式: `舊後綴:新後綴`

**範例 1: 替換現有後綴**:
```properties
file_names.0.rename_suffix.0=.5920:.txt
```
- 下載 `TCD.5920` → 儲存為 `TCD.txt`
- 下載 `TSC.5920` → 儲存為 `TSC.txt`

**範例 2: 為無副檔名的檔案添加副檔名**:
```properties
file_names.0.rename_suffix.0=:.txt
```
- 下載 `RYM01` → 儲存為 `RYM01.txt`
- 下載 `RYM02` → 儲存為 `RYM02.txt`
- 下載 `DATAFILE` → 儲存為 `DATAFILE.txt`

**重要**: 使用 `:副檔名` 格式（冒號前為空）可以為所有無副檔名的檔案批次添加副檔名。

## 完整範例

### 範例 1: 前綴篩選 + 前綴重命名
```properties
# 下載所有 TCD 開頭的檔案，並將前綴改為 DATA
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.include_prefixes.0=TCD
file_names.0.rename_prefix.0=TCD:DATA
```

**效果**:
- 遠端檔案: `TCD5920`, `TCD5921`, `TCDABC`
- 本地檔案: `DATA5920`, `DATA5921`, `DATAABC`

### 範例 2: 後綴篩選 + 後綴重命名
```properties
# 下載所有 .5920 結尾的檔案，並改為 .txt
file_names.1.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.1.include_suffixes.0=.5920
file_names.1.rename_suffix.0=.5920:.txt
```

**效果**:
- 遠端檔案: `TCD.5920`, `TSC.5920`, `RYM.5920`
- 本地檔案: `TCD.txt`, `TSC.txt`, `RYM.txt`

### 範例 3: 組合使用 - 同時改前綴和後綴
```properties
# 下載 TCD 開頭且 .5920 結尾的檔案，改為 DATA 開頭 .txt 結尾
file_names.2.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.2.include_prefixes.0=TCD
file_names.2.include_suffixes.0=.5920
file_names.2.rename_prefix.0=TCD:DATA
file_names.2.rename_suffix.0=.5920:.txt
```

**效果**:
- 遠端檔案: `TCD5920.5920`
- 本地檔案: `DATA5920.txt`

### 範例 4: 多個前綴重命名規則
```properties
# 不同前綴使用不同的新名稱
file_names.3.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.3.include_prefixes.0=TCD
file_names.3.include_prefixes.1=TSC
file_names.3.include_prefixes.2=RYM
file_names.3.rename_prefix.0=TCD:DATA
file_names.3.rename_prefix.1=TSC:INFO
file_names.3.rename_prefix.2=RYM:REPORT
```

**效果**:
- `TCD5920` → `DATA5920`
- `TSC5921` → `INFO5921`
- `RYM01` → `REPORT01`

### 範例 5: 結合時間範圍和排除規則
```properties
# 凌晨2-5點下載 TCD 開頭檔案，改名為 DATA，但排除測試檔
file_names.4.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.4.allowed_time_range=02:00-05:00
file_names.4.include_prefixes.0=TCD
file_names.4.exclude_files.0=TCD_TEST
file_names.4.exclude_files.1=TCD_BACKUP
file_names.4.rename_prefix.0=TCD:DATA
```

### 範例 6: 為無副檔名的檔案批次添加副檔名
```properties
# 下載 RYM 開頭的檔案（無副檔名），統一添加 .txt 副檔名
file_names.5.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.5.include_prefixes.0=RYM
file_names.5.rename_suffix.0=:.txt
```

**效果**:
- `RYM01` → `RYM01.txt`
- `RYM02` → `RYM02.txt`
- `RYMDATA` → `RYMDATA.txt`

### 範例 7: 前綴改名 + 添加副檔名
```properties
# 同時改前綴和添加副檔名
file_names.6.remote_path=\\CSTP96.$DATA.SKDATA92
file_names.6.include_prefixes.0=TCD
file_names.6.rename_prefix.0=TCD:DATA
file_names.6.rename_suffix.0=:.dat
```

**效果**:
- `TCD5920` → `DATA5920.dat`
- `TCD5921` → `DATA5921.dat`

## 注意事項

1. **優先順序**: 重命名規則按順序應用，只會應用第一個匹配的規則
2. **大小寫**: 匹配時不區分大小寫，但新名稱會保留您指定的大小寫
3. **組合使用**: 可以同時使用前綴和後綴重命名
4. **與明確指定衝突**: 如果使用 `files.N=遠端:本地` 語法，會優先使用該語法，重命名規則不適用
5. **部分匹配**: 前綴/後綴必須完全匹配才會替換
6. **添加副檔名**: 使用 `rename_suffix.N=:.副檔名` 格式（冒號前為空）可為所有檔案添加副檔名
7. **替換副檔名**: 使用 `rename_suffix.N=.舊副檔名:.新副檔名` 格式替換現有副檔名

## 常見應用場景

### 場景 1: Guardian/NonStop 系統下載無副檔名檔案
Guardian 系統的檔案通常沒有副檔名，下載後需要添加副檔名方便 Windows 識別：
```properties
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.include_prefixes.0=RYM
file_names.0.rename_suffix.0=:.txt
```

### 場景 2: 統一前綴命名規範
將不同來源的檔案統一命名：
```properties
file_names.0.include_prefixes.0=TCD
file_names.0.include_prefixes.1=TSC
file_names.0.rename_prefix.0=TCD:REPORT
file_names.0.rename_prefix.1=TSC:REPORT
file_names.0.rename_suffix.0=:.dat
# TCD5920 → REPORT5920.dat
# TSC9999 → REPORT9999.dat
```

## 實現狀態

### 下載程式 (main.go)
需要在 PathMapping 結構中新增:
```go
type PathMapping struct {
    // ... 現有欄位 ...
    PrefixRename map[string]string
    SuffixRename map[string]string
}
```

並實現:
1. 配置解析邏輯 (loadConfig)
2. 重命名應用函數 (applyFileNameRename)
3. 在下載點應用重命名

### 上傳程式 (uploader.go)
同樣可以實現類似功能，讓上傳時也能批次重命名。

## 相關文件

- [DOWNLOADER_FILTER_GUIDE.md](DOWNLOADER_FILTER_GUIDE.md) - 完整的篩選功能說明
- [config.downloader.example2.properties](config.downloader.example2.properties) - 進階配置範例
