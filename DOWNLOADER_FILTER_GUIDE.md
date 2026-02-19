# FTPS Downloader 時間範圍與檔案篩選功能說明

## ⚡ 重要更新：時間範圍設定方式改變

**新版本支援針對每個檔案群組設定不同的下載時間區間！**

- ✅ **舊版**：全域時間範圍，所有檔案使用同一個時間區間
- ✨ **新版**：每個檔案群組獨立時間範圍，更靈活的排程控制

## 更新概覽

下載程式已新增以下功能，讓您可以精確控制下載的時機和範圍：
1. **📅 獨立時間範圍** - 每個檔案群組可設定不同的下載時間
2. **🔍 檔案篩選功能** - 支援萬用字元、前綴、後綴、排除規則

## 新增功能詳解

### 1. 獨立時間範圍限制 (allowed_time_range)

**重要：時間範圍現在是針對每個 file_names 群組單獨設定**

```properties
# RYM 檔案在凌晨 2-5 點下載
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.allowed_time_range=02:00-05:00
file_names.0.include_prefixes.0=RYM

# TCD 檔案在早上 8-10 點下載
file_names.1.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.1.allowed_time_range=08:00-10:00
file_names.1.include_prefixes.0=TCD

# TSC 檔案在下午 2-4 點下載
file_names.2.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.2.allowed_time_range=14:00-16:00
file_names.2.include_prefixes.0=TSC

# 特定檔案不限時間
file_names.3.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.3.files.0=CONFIG
# 沒有 allowed_time_range，任何時間都可以下載
```

**功能說明：**
- 每個 `file_names.索引` 可以有自己的 `allowed_time_range`
- 格式: `file_names.索引.allowed_time_range=HH:mm-HH:mm` (24 小時制)
- 如果當前時間不在範圍內，該群組會被跳過，但其他群組不受影響
- 支援跨午夜的時間範圍（例如: `22:00-04:00`）
- 不設定此參數則該群組任何時間都可以下載

**使用場景：**
- 不同類型檔案有不同的業務時間窗口
- 避免在同一時段下載太多檔案造成系統負荷
- 配合不同系統的資料產生時間
- 更精細的排程控制

### 2. 檔案篩選功能

#### 2.1 明確指定檔案 (files)
```properties
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.files.0=RYM01
file_names.0.files.1=RYM02:renamed.txt
```
- 明確指定要下載的檔案
- 支援重新命名: `遠端檔名:本地檔名`

#### 2.2 萬用字元模式 (patterns)
```properties
file_names.0.patterns.0=*.txt      # 所有 .txt 檔案
file_names.0.patterns.1=TCD*       # TCD 開頭的所有檔案
file_names.0.patterns.2=RYM??      # RYM 後接兩個字元的檔案
```

**支援的萬用字元：**
- `*` - 匹配 0 個或多個任意字元
- `?` - 匹配單一字元
- 不區分大小寫

#### 2.3 前綴篩選 (include_prefixes)
```properties
file_names.0.include_prefixes.0=TCD
file_names.0.include_prefixes.1=TSC
```
- 只下載檔名符合指定前綴的檔案
- 可指定多個前綴（任一符合即可）
- 不區分大小寫

#### 2.4 後綴篩選 (include_suffixes)
```properties
file_names.0.include_suffixes.0=.txt
file_names.0.include_suffixes.1=.5920
```
- 只下載檔名符合指定後綴的檔案
- 通常用於副檔名篩選
- 不區分大小寫

#### 2.5 排除規則 (exclude_files)
```properties
file_names.0.patterns.0=*
file_names.0.exclude_files.0=test
file_names.0.exclude_files.1=backup
```
- 排除特定檔案，不進行下載
- **優先級最高**，即使符合其他規則也會被排除
- 不區分大小寫

## 組合使用範例

### 範例 1: 不同檔案群組在不同時間下載
```properties
# RYM 檔案在凌晨 2-5 點下載
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.allowed_time_range=02:00-05:00
file_names.0.include_prefixes.0=RYM

# TCD 檔案在早上 8-10 點下載
file_names.1.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.1.allowed_time_range=08:00-10:00
file_names.1.include_prefixes.0=TCD

# TSC 檔案在下午 2-4 點下載
file_names.2.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.2.allowed_time_range=14:00-16:00
file_names.2.include_prefixes.0=TSC
```

### 範例 2: 跨午夜時間範圍
```properties
# .5920 檔案在晚上 10 點到隔天凌晨 1 點下載
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.allowed_time_range=22:00-01:00
file_names.0.patterns.0=*.5920
```

### 範例 3: 組合時間範圍和篩選規則
```properties
# 早上 6-7 點下載 TCD 開頭且 .5920 結尾的檔案，但排除測試檔
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA92
file_names.0.allowed_time_range=06:00-07:00
file_names.0.include_prefixes.0=TCD
file_names.0.include_suffixes.0=.5920
file_names.0.exclude_files.0=TCD_TEST.5920
```

### 範例 4: 混合有時間限制和無時間限制的群組
```properties
# 凌晨 2-5 點下載業務檔案
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.allowed_time_range=02:00-05:00
file_names.0.include_prefixes.0=TCD
file_names.0.include_prefixes.1=TSC

# 配置檔案隨時可下載（無時間限制）
file_names.1.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.1.files.0=CONFIG
file_names.1.files.1=DATCLOSE
```

### 範例 5: 多路徑、多時段策略
```properties
# 路徑 1：主要業務檔案，凌晨處理
file_names.0.remote_path=\\CSTP96.$DATA.SKDATA91
file_names.0.allowed_time_range=02:00-05:00
file_names.0.patterns.0=RYM*

# 路徑 2：報表檔案，早上處理
file_names.1.remote_path=\\CSTP96.$DATA.REPORTS
file_names.1.allowed_time_range=08:00-09:00
file_names.1.patterns.0=*.txt

# 路徑 3：備份檔案，下午處理
file_names.2.remote_path=\\CSTP96.$DATA.BACKUP
file_names.2.allowed_time_range=15:00-16:00
file_names.2.patterns.0=*
```

## 篩選規則優先級

1. **排除規則 (exclude_files)** - 最高優先級，一旦符合就不下載
2. **前綴篩選 (include_prefixes)** - 必須符合其中一個前綴
3. **後綴篩選 (include_suffixes)** - 必須符合其中一個後綴
4. 前綴和後綴可以組合使用，必須**同時符合**

## 實際運作流程

```
1. 連線到 FTPS 伺服器

2. 檢查結帳檔（如果啟用）
   └─ 不存在 → 結束程式
   └─ 存在 → 繼續

3. 列出遠端檔案清單

4. 對每個 file_names 配置：
   ├─ 【新增】檢查此群組的時間範圍
   │  ├─ 不在範圍內 → ⏭️ 跳過此群組，繼續下一個
   │  └─ 在範圍內或無限制 → ✓ 繼續處理
   │
   ├─ 處理明確指定的檔案 (files)
   │  └─ 套用篩選規則
   ├─ 處理萬用字元模式 (patterns)
   │  └─ 套用篩選規則
   └─ 自動掃描（如果有前綴/後綴篩選）
      └─ 套用篩選規則

5. 下載符合條件的檔案

6. 處理下一個 file_names 群組（重複步驟 4）
```

**重點變化：**
- ✨ 每個群組獨立檢查時間範圍
- ✨ 某群組時間不符只跳過該群組，其他群組繼續執行
- ✨ 程式只連線一次，處理所有符合時間條件的群組

## 注意事項

- 所有檔名比對都**不區分大小寫**
- 萬用字元只在檔名本身匹配，不包含路徑
- 如果同時指定 `files` 和篩選規則，篩選規則會應用到明確指定的檔案上
- 排除規則對所有來源的檔案都有效（files, patterns, 自動掃描）
- **時間範圍是針對每個 file_names 群組檢查**，不是全域檢查
- 某個群組時間不符只會跳過該群組，不影響其他群組
- 程式只會連線一次 FTPS 伺服器，然後依序處理所有符合時間條件的群組
- 建議將時間限制嚴格的群組放在配置檔前面

## 日誌輸出

程式會記錄以下資訊，方便除錯：
```
✓ 時間範圍檢查通過 (02:00-05:00)，處理路徑: \CSTP96.$DATA.SKDATA91
⏰ 目前時間不在允許的範圍內 (08:00-10:00)，跳過路徑: \CSTP96.$DATA.SKDATA92
- 哪些檔案被篩選規則排除
- 哪些檔案符合規則並被下載
- 最終下載的檔案數量
```

## 測試建議

1. 先使用 `patterns.0=*` 配合 log 查看會下載哪些檔案
2. 逐步增加篩選規則，觀察效果
3. 使用排除規則剔除不需要的檔案
4. 測試時可以暫時註解掉 `allowed_time_range` 以便隨時測試

## 相關檔案

- [main.go](main.go) - 主程式
- [config.properties.example](config.properties.example) - 基本配置說明
- [config.downloader.example2.properties](config.downloader.example2.properties) - 進階範例
