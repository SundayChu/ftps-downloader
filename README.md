# FTPS Downloader (Go Version)

這是一個使用 Go 語言開發的 FTPS (FTP over SSL/TLS) 下載工具。它支援 Explicit TLS (Port 21) 和 Implicit TLS (Port 990)，並可以自動下載指定目錄下的所有檔案。

## 主要功能

### 基本功能
*   支援 FTPS (Explicit TLS & Implicit TLS)
*   自動列出並下載遠端目錄中的所有檔案
*   可透過命令列參數或設定檔設定連線資訊
*   支援略過 SSL 憑證驗證 (Insecure Skip Verify)

### 進階功能
*   **全天監控模式** 🆕：持續運行，定期自動檢查並下載檔案
*   **時間範圍控制**：設定只在特定時間段下載（例如：凌晨 2-5 點）
*   **編碼轉換**：支援 EBCDIC、Big5、UTF-8 等多種編碼轉換
*   **Guardian/NonStop 支援**：自動處理 Guardian 區塊格式
*   **原始下載模式**：保持與遠端檔案完全一致的二進制內容
*   **背景執行**：可配合 VBS 腳本在背景執行，不顯示視窗
*   **日誌記錄**：所有操作都會記錄到日誌檔案
*   **檔案時間同步** 🆕：下載後自動設定為遠端檔案的修改時間
*   **獨立檔案 Log** 🆕：為每個檔案產生獨立的 log，詳細記錄時間與大小資訊

## 開發環境需求

*   Go 1.16 或更高版本

## 安裝與編譯

1.  **下載程式碼**
    將專案複製到您的工作目錄。

2.  **初始化模組 (如果尚未初始化)**
    ```bash
    go mod init ftps-downloader
    go get github.com/jlaffaye/ftp
    ```

3.  **編譯程式**
    
    **編譯下載器：**
    ```bash
    # 一般模式（顯示控制台視窗）
    go build -o ftps-downloader.exe ./cmd/downloader
    
    # 或使用提供的批次檔
    build_no_console.bat
    ```
    
    **編譯上傳器：**
    ```bash
    # 一般模式（顯示控制台視窗）
    go build -o ftps-uploader.exe ./cmd/uploader
    
    # 或使用提供的批次檔
    build_uploader.bat
    ```

## 使用說明

編譯完成後，您可以直接在命令列執行 `ftps-downloader.exe`。程式使用內建的 Go FTPS 客戶端進行下載，無需額外安裝其他軟體。

### 使用方式

#### 方式一：使用設定檔（推薦）

適合需要固定設定或使用監控模式的場景。

1. 複製範例設定檔：
   ```bash
   copy config.properties.example config.properties
   ```

2. 編輯 `config.properties`，設定連線參數

3. 執行程式：
   ```bash
   ftps-downloader.exe
   # 或指定設定檔
   ftps-downloader.exe -config my-config.properties
   ```

#### 方式二：使用命令列參數

適合臨時或一次性的下載任務。

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword
```

### 全天監控模式 🆕

監控模式讓程式持續運行，定期自動檢查並下載檔案。

#### 設定方式

在 `config.properties` 中添加：

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

#### 執行方式

**前台運行（顯示視窗）：**
```bash
ftps-downloader.exe
# 或
run_ftps_downloader_monitor.bat
```

**背景運行（隱藏視窗）：**
```bash
run_ftps_downloader_monitor_hidden.vbs
```

詳細說明請參考：[監控模式使用指南](MONITOR_MODE_GUIDE.md)

### 主要參數說明

| 參數 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `-config` | `config.properties` | 設定檔路徑 |
| `-host` | - | FTP 伺服器位址 |
| `-port` | `21` | FTP 伺服器連接埠 |
| `-user` | - | 使用者名稱 |
| `-pass` | - | 密碼 |
| `-remote-dir` | - | 遠端要下載的目錄路徑 |
| `-local-dir` | `./downloads` | 本地儲存檔案的目錄 |
| `-log-dir` | - | 日誌檔目錄 |
| `-implicit-tls` | `false` | 是否使用 Implicit TLS (通常是 Port 990) |
| `-insecure-skip-verify` | `false` | 是否略過 SSL 憑證驗證 (用於自簽憑證) |
| `-raw-download` | `false` | 原始下載模式，不進行任何資料處理 |
| `-monitor-mode` | `false` | 啟用全天監控模式 🆕 |
| `-check-interval` | `30` | 檢查間隔（分鐘）🆕 |
| `-allowed-time-range` | - | 下載時間範圍（HH:mm-HH:mm）🆕 |
| `-stop-time` | - | 自動停止時間（HH:mm）🆕 |

### 執行範例

**1. 基本連線 (Explicit TLS, Port 21)**

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword
```

**2. 指定遠端目錄與本地下載目錄**

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword -remote-dir /remote/data -local-dir c:\data\downloads
```

**3. 使用 Implicit TLS (Port 990)**

```bash
ftps-downloader.exe -host ftp.example.com -port 990 -user myuser -pass mypassword -implicit-tls
```

**4. 略過憑證驗證 (針對自簽憑證)**

```bash
ftps-downloader.exe -host 192.168.1.100 -user test -pass test -insecure-skip-verify
```

**5. 原始下載模式（保持與遠端檔案完全一致）**

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword -raw-download
```

**6. 全天監控模式（每 30 分鐘檢查，只在凌晨 2-5 點下載）🆕**

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword -monitor-mode -check-interval 30 -allowed-time-range "02:00-05:00"
```

**7. 全天監控模式（每 30 分鐘檢查，晚上 6 點自動停止）🆕**

```bash
ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword -monitor-mode -check-interval 30 -stop-time "18:00"
```

**8. 使用設定檔（推薦）**

```bash
# 使用預設設定檔 config.properties
ftps-downloader.exe

# 使用自訂設定檔
ftps-downloader.exe -config my-config.properties
```

## 佈署說明

### 一般佈署

1.  **編譯**：在開發機上執行 `go build -o ftps-downloader.exe ./cmd/downloader` 或 `go build -o ftps-uploader.exe ./cmd/uploader`。
2.  **複製**：將產生的執行檔複製到目標伺服器或電腦上。
3.  **設定**：複製並編輯 `config.properties` 設定檔。
4.  **執行**：在目標電腦上開啟命令提示字元 (CMD) 或 PowerShell，依照上述「使用說明」執行程式即可。

### 監控模式佈署 🆕

適合需要持續運行、定期下載的場景。

#### 使用 Windows 工作排程器

1. 開啟「工作排程器」
2. 建立新工作：
   - **一般**：選擇「不論使用者登入與否均執行」
   - **觸發程序**：「系統啟動時」
   - **動作**：執行 `run_ftps_downloader_monitor_hidden.vbs`
   - **條件**：取消勾選「只有在使用 AC 電源時才啟動工作」
   - **設定**：勾選「如果工作失敗，在下列時間重新啟動」

#### 使用 NSSM 註冊為服務

```batch
nssm install FTPSDownloader "C:\path\to\ftps-downloader.exe"
nssm set FTPSDownloader AppDirectory "C:\path\to\ftps-downloader"
nssm set FTPSDownloader AppParameters "-config config.properties"
nssm start FTPSDownloader
```

### 定期執行（不使用監控模式）

如果不需要持續運行，只需定期執行一次：

**Windows 工作排程器**：
- 觸發程序：每天特定時間
- 動作：執行 `ftps-downloader.exe`

**Linux cron**：
```bash
# 每天凌晨 2 點執行
0 2 * * * /path/to/ftps-downloader -config /path/to/config.properties
```

## 相關文件

- [監控模式使用指南](MONITOR_MODE_GUIDE.md) - 全天監控模式完整說明
- [監控日誌說明](MONITOR_LOG_GUIDE.md) - 詳細的日誌格式和分析 🆕
- [自動停止功能指南](AUTO_STOP_GUIDE.md) - 自動停止時間設定說明
- [獨立檔案 Log 指南](SEPARATE_FILE_LOG_GUIDE.md) - 為每個檔案產生獨立 log，記錄時間與大小資訊 🆕
- [設定檔範例](config.properties.example) - 完整設定檔範例與說明
- [監控模式設定範例](config.monitor.example.properties) - 監控模式專用設定檔
- [下載器篩選指南](DOWNLOADER_FILTER_GUIDE.md) - 檔案篩選功能說明
- [上傳器使用指南](UPLOADER_FILTER_GUIDE.md) - 上傳器功能說明
- [上傳器自動清理指南](UPLOADER_AUTO_CLEANUP_GUIDE.md) - 日誌自動清理與單一實例控制 🆕

## 注意事項

*   請確保防火牆允許程式連線到 FTP 伺服器的 Port (通常是 21 或 990，以及被動模式的 Data Ports)。
*   本程式預設使用被動模式 (PASV) 進行資料傳輸。
*   監控模式會持續運行，建議搭配日誌記錄功能，並定期清理舊日誌檔案。
*   上傳器啟動時會自動清理超過 3 天的舊日誌，保持日誌目錄整潔。🆕
*   上傳器會自動偵測並終止已存在的執行實例，確保同時只有一個程式在執行。🆕
*   時間範圍檢查基於本機系統時間，請確保系統時間正確。
