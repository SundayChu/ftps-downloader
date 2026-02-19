# 專案結構說明

## 目錄結構

```
ftps-downloader/
│
├── 📁 核心程式碼
│   ├── main.go                          # 下載器主程式
│   ├── uploader.go                      # 上傳器主程式
│   ├── go.mod                           # Go 模組定義
│   └── go.sum                           # Go 模組依賴鎖定
│
├── 📁 執行檔
│   ├── ftps-downloader.exe              # 下載器執行檔
│   └── ftps-uploader.exe                # 上傳器執行檔
│
├── 📁 設定檔
│   ├── config.properties                # 當前使用的設定檔（需自行建立）
│   │
│   ├── 【下載器範例】
│   ├── config.properties.example        # 下載器基本設定範例
│   ├── config.downloader.example2.properties  # 下載器進階設定範例
│   ├── config.monitor.example.properties      # 監控模式設定範例
│   └── config.monitor.autostop.example.properties  # 監控+自動停止範例
│   │
│   └── 【上傳器範例】
│       ├── config.uploader.properties   # 上傳器當前設定
│       ├── config.uploader.properties.example     # 上傳器基本範例
│       └── config.uploader.example2.properties    # 上傳器進階範例
│
├── 📁 執行腳本
│   ├── 【編譯腳本】
│   ├── build_no_console.bat             # 編譯下載器（無視窗）
│   ├── build_no_console.ps1             # 編譯下載器（PowerShell）
│   ├── build_uploader.bat               # 編譯上傳器
│   └── build_uploader_no_console.bat    # 編譯上傳器（無視窗）
│   │
│   ├── 【下載器執行腳本】
│   ├── run_ftps_downloader.bat          # 下載器（顯示視窗）
│   ├── run_ftps_downloader_hidden.vbs   # 下載器（背景執行）
│   ├── run_ftps_downloader_monitor.bat  # 監控模式（顯示視窗）
│   └── run_ftps_downloader_monitor_hidden.vbs  # 監控模式（背景執行）
│   │
│   ├── 【上傳器執行腳本】
│   ├── run_ftps_uploader.bat            # 上傳器（顯示視窗）
│   └── run_ftps_uploader_hidden.vbs     # 上傳器（背景執行）
│   │
│   ├── 【測試腳本】
│   ├── test_monitor_mode.bat            # 測試監控模式
│   ├── test_auto_stop.bat               # 測試自動停止
│   ├── test_monitor_log.bat             # 測試日誌輸出
│   └── demo_monitor_log.bat             # 展示日誌功能
│   │
│   └── 【其他工具】
│       ├── setup_scheduler.ps1          # 設定 Windows 排程器
│       └── push_to_github.ps1           # 推送到 GitHub
│
├── 📁 說明文件
│   ├── README.md                        # 專案主要說明
│   ├── CHANGELOG.md                     # 版本更新記錄
│   │
│   ├── 【監控模式相關】
│   ├── MONITOR_MODE_GUIDE.md            # 監控模式完整指南
│   ├── MONITOR_LOG_GUIDE.md             # 監控日誌說明
│   └── AUTO_STOP_GUIDE.md               # 自動停止功能指南
│   │
│   ├── 【下載器相關】
│   └── DOWNLOADER_FILTER_GUIDE.md       # 下載器篩選功能
│   │
│   └── 【上傳器相關】
│       ├── UPLOADER_FILTER_GUIDE.md     # 上傳器篩選功能
│       ├── UPLOADER_HIDDEN_GUIDE.md     # 上傳器背景執行
│       └── PREFIX_RENAME_GUIDE.md       # 檔案重命名功能
│
├── 📁 資料目錄
│   ├── downloads/                       # 下載的檔案存放處
│   ├── uploads/                         # 待上傳的檔案存放處
│   ├── logs/                            # 日誌檔案目錄
│   └── vendor/                          # Go 依賴套件
│
└── 📁 版本控制
    ├── .git/                            # Git 版本控制
    └── .gitignore                       # Git 忽略清單
```

## 檔案用途說明

### 核心程式

| 檔案 | 說明 |
|------|------|
| `main.go` | 下載器主程式，包含 FTPS 下載、監控模式、編碼轉換等功能 |
| `uploader.go` | 上傳器主程式，包含 FTPS 上傳、篩選、重命名等功能 |

### 執行檔

| 檔案 | 說明 |
|------|------|
| `ftps-downloader.exe` | 下載器可執行檔（最新編譯版本） |
| `ftps-uploader.exe` | 上傳器可執行檔（最新編譯版本） |

### 設定檔範例

#### 下載器設定檔

| 檔案 | 用途 |
|------|------|
| `config.properties.example` | 基本設定範例，包含連線資訊、編碼設定等 |
| `config.downloader.example2.properties` | 進階設定範例，包含篩選、時間控制等 |
| `config.monitor.example.properties` | 監控模式專用設定範例 |
| `config.monitor.autostop.example.properties` | 監控模式 + 自動停止範例 |

#### 上傳器設定檔

| 檔案 | 用途 |
|------|------|
| `config.uploader.properties.example` | 基本設定範例 |
| `config.uploader.example2.properties` | 進階設定範例，包含篩選、重命名等 |

### 執行腳本

#### 編譯腳本

| 檔案 | 用途 |
|------|------|
| `build_no_console.bat` | 編譯下載器（無控制台視窗） |
| `build_uploader.bat` | 編譯上傳器（標準版本） |

#### 執行腳本

| 檔案 | 用途 |
|------|------|
| `run_ftps_downloader.bat` | 執行下載器（顯示控制台） |
| `run_ftps_downloader_hidden.vbs` | 執行下載器（背景運行） |
| `run_ftps_downloader_monitor.bat` | 執行監控模式（顯示控制台） |
| `run_ftps_downloader_monitor_hidden.vbs` | 執行監控模式（背景運行） |

#### 測試腳本

| 檔案 | 用途 |
|------|------|
| `test_monitor_mode.bat` | 測試監控模式基本功能 |
| `test_auto_stop.bat` | 測試自動停止功能 |
| `test_monitor_log.bat` | 測試日誌記錄功能 |
| `demo_monitor_log.bat` | 展示完整的日誌輸出 |

### 說明文件

| 檔案 | 內容 |
|------|------|
| `README.md` | 專案主要說明，包含功能介紹、安裝、使用方法 |
| `CHANGELOG.md` | 版本更新記錄 |
| `MONITOR_MODE_GUIDE.md` | 監控模式完整使用指南 |
| `MONITOR_LOG_GUIDE.md` | 監控日誌格式和分析說明 |
| `AUTO_STOP_GUIDE.md` | 自動停止功能詳細說明 |
| `DOWNLOADER_FILTER_GUIDE.md` | 下載器篩選功能說明 |
| `UPLOADER_FILTER_GUIDE.md` | 上傳器篩選功能說明 |
| `PREFIX_RENAME_GUIDE.md` | 檔案重命名功能說明 |

## 快速開始

### 1. 下載器使用

```bash
# 複製設定檔範例
copy config.properties.example config.properties

# 編輯設定檔，設定連線參數
notepad config.properties

# 執行下載
ftps-downloader.exe
```

### 2. 監控模式使用

```bash
# 使用監控模式設定檔
copy config.monitor.example.properties config.properties

# 編輯設定檔
notepad config.properties

# 執行監控模式（顯示視窗）
run_ftps_downloader_monitor.bat

# 或背景執行
run_ftps_downloader_monitor_hidden.vbs
```

### 3. 上傳器使用

```bash
# 複製設定檔範例
copy config.uploader.properties.example config.uploader.properties

# 編輯設定檔
notepad config.uploader.properties

# 執行上傳
ftps-uploader.exe
```

## 開發相關

### 重新編譯

```bash
# 編譯下載器
go build -o ftps-downloader.exe main.go

# 編譯上傳器
go build -o ftps-uploader.exe uploader.go
```

### 更新依賴

```bash
go mod tidy
go mod vendor
```

## 注意事項

1. **設定檔管理**
   - `config.properties` 是實際使用的設定檔（不在版本控制中）
   - 請從範例檔案複製並修改

2. **日誌檔案**
   - 會自動產生在 `logs/` 目錄
   - 建議定期清理舊日誌

3. **資料目錄**
   - `downloads/` - 下載的檔案
   - `uploads/` - 待上傳的檔案
   - 這些目錄會自動建立

4. **執行檔**
   - 編譯後的執行檔可獨立執行
   - 不需要 Go 環境

## 相關連結

- [主要說明文件](README.md)
- [版本更新記錄](CHANGELOG.md)
- [監控模式指南](MONITOR_MODE_GUIDE.md)
