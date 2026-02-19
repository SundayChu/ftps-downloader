# FTPS Uploader 檔案篩選功能說明

## 功能概覽

已在上傳程式中新增強大的檔案篩選功能，讓您可以在同一個本地路徑下靈活控制要上傳哪些檔案。

## 支援的篩選方式

### 1. 明確指定檔案 (files)
```properties
file_names.0.local_path=./downloads
file_names.0.files.0=RYM01
file_names.0.files.1=RYM02:RYM02_RENAMED
```
- 指定特定檔案名稱
- 支援重新命名 (本地檔名:遠端檔名)

### 2. 萬用字元模式 (patterns)
```properties
file_names.0.local_path=./downloads
file_names.0.patterns.0=*.txt      # 所有 .txt 檔案
file_names.0.patterns.1=TCD*       # TCD 開頭的檔案
file_names.0.patterns.2=RYM??      # RYM 後接兩個字元的檔案
```
- 支援 `*` (匹配多個字元)
- 支援 `?` (匹配單一字元)

### 3. 前綴篩選 (include_prefixes)
```properties
file_names.0.local_path=./downloads
file_names.0.include_prefixes.0=TCD
file_names.0.include_prefixes.1=TSC
```
- 只上傳檔名符合指定前綴的檔案
- 自動掃描整個目錄
- 不區分大小寫

### 4. 後綴篩選 (include_suffixes)
```properties
file_names.0.local_path=./downloads
file_names.0.include_suffixes.0=.txt
file_names.0.include_suffixes.1=.5920
```
- 只上傳檔名符合指定後綴的檔案
- 通常用於副檔名篩選
- 不區分大小寫

### 5. 排除檔案 (exclude_files)
```properties
file_names.0.local_path=./downloads
file_names.0.patterns.0=*          # 所有檔案
file_names.0.exclude_files.0=test.txt
file_names.0.exclude_files.1=backup.dat
```
- 排除特定檔案，不進行上傳
- 優先級最高
- 不區分大小寫

## 組合使用範例

### 範例 1: 只上傳 TCD 和 TSC 開頭的所有檔案
```properties
file_names.0.local_path=./downloads
file_names.0.include_prefixes.0=TCD
file_names.0.include_prefixes.1=TSC
```

### 範例 2: 上傳 TCD 開頭且副檔名為 .5920 的檔案
```properties
file_names.0.local_path=./downloads
file_names.0.include_prefixes.0=TCD
file_names.0.include_suffixes.0=.5920
```

### 範例 3: 上傳所有 .txt 檔案但排除特定檔案
```properties
file_names.0.local_path=./downloads
file_names.0.patterns.0=*.txt
file_names.0.exclude_files.0=test.txt
file_names.0.exclude_files.1=debug.txt
```

### 範例 4: 使用萬用字元上傳多種類型
```properties
file_names.0.local_path=./downloads
file_names.0.patterns.0=TCD*
file_names.0.patterns.1=TSC*
file_names.0.patterns.2=RYM??
```

## 篩選規則優先級

1. **排除規則 (exclude_files)** - 最高優先級，一旦符合就不上傳
2. **前綴篩選 (include_prefixes)** - 必須符合其中一個前綴
3. **後綴篩選 (include_suffixes)** - 必須符合其中一個後綴
4. 前綴和後綴可以組合使用，必須同時符合

## 注意事項

- 所有比對都不區分大小寫
- 可以在同一個配置中混用多種篩選方式
- 如果只指定 `files` 而沒有其他篩選規則，則只上傳列表中的檔案
- 如果指定了 `include_prefixes` 或 `include_suffixes` 但沒有 `files` 或 `patterns`，程式會自動掃描目錄
- 排除規則對所有來源的檔案都有效 (files, patterns, 自動掃描)

## 測試建議

1. 先在測試目錄中建立一些測試檔案
2. 使用 `patterns.0=*` 配合 log 輸出查看會上傳哪些檔案
3. 確認篩選規則正確後再連接到正式環境

## 完整範例

參考以下範例檔案：
- `config.uploader.properties.example` - 基本說明
- `config.uploader.example2.properties` - 進階範例
