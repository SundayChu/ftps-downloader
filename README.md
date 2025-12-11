# FTPS Downloader (Go Version)

這是一個使用 Go 語言開發的 FTPS (FTP over SSL/TLS) 下載工具。它支援 Explicit TLS (Port 21) 和 Implicit TLS (Port 990)，並可以自動下載指定目錄下的所有檔案。

## 功能

*   支援 FTPS (Explicit TLS & Implicit TLS)
*   自動列出並下載遠端目錄中的所有檔案
*   可透過命令列參數設定連線資訊
*   支援略過 SSL 憑證驗證 (Insecure Skip Verify)

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
    在專案目錄下執行以下指令來編譯出執行檔 (Windows 下會產生 `ftps-downloader.exe`)：
    ```bash
    go build -o ftps-downloader.exe main.go
    ```

## 使用說明

編譯完成後，您可以直接在命令列執行 `ftps-downloader.exe`。程式使用內建的 Go FTPS 客戶端進行下載，無需額外安裝其他軟體。

### 參數說明

| 參數 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `-host` | `localhost` | FTP 伺服器位址 |
| `-port` | `21` | FTP 伺服器連接埠 |
| `-user` | `anonymous` | 使用者名稱 |
| `-pass` | `anonymous` | 密碼 |
| `-dir` | `/` | 遠端要下載的目錄路徑 |
| `-out` | `./downloads` | 本地儲存檔案的目錄 |
| `-implicit` | `false` | 是否使用 Implicit TLS (通常是 Port 990) |
| `-insecure` | `false` | 是否略過 SSL 憑證驗證 (用於自簽憑證) |
| `-raw-download` | `false` | 原始下載模式，不進行任何資料處理，保持與遠端檔案完全一致 |

### 執行範例

**1. 基本連線 (Explicit TLS, Port 21)**

```bash
./ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword
```

**2. 指定遠端目錄與本地下載目錄**

```bash
./ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword -dir /remote/data -out c:\data\downloads
```

**3. 使用 Implicit TLS (Port 990)**

```bash
./ftps-downloader.exe -host ftp.example.com -port 990 -user myuser -pass mypassword -implicit=true
```

**4. 略過憑證驗證 (針對自簽憑證)**

```bash
./ftps-downloader.exe -host 192.168.1.100 -user test -pass test -insecure=true
```

**5. 原始下載模式（保持與遠端檔案完全一致）**

```bash
./ftps-downloader.exe -host ftp.example.com -user myuser -pass mypassword --raw-download
```

## 佈署說明

1.  **編譯**：在開發機上執行 `go build -o ftps-downloader.exe main.go`。
2.  **複製**：將產生的 `ftps-downloader.exe` 檔案複製到目標伺服器或電腦上。
3.  **執行**：在目標電腦上開啟命令提示字元 (CMD) 或 PowerShell，依照上述「使用說明」執行程式即可。
4.  **排程 (選用)**：如果需要定期下載，可以使用 Windows 的「工作排程器」或 Linux 的 `cron` 來定期執行此程式。

## 注意事項

*   請確保防火牆允許程式連線到 FTP 伺服器的 Port (通常是 21 或 990，以及被動模式的 Data Ports)。
*   本程式預設使用被動模式 (PASV) 進行資料傳輸。
