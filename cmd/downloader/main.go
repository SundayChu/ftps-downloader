package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jlaffaye/ftp"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex  = kernel32.NewProc("CreateMutexW")
	procGetLastError = kernel32.NewProc("GetLastError")
)

type PathMapping struct {
	RemotePath       string
	Files            []string
	CheckFlagFile    bool   // 是否檢查結帳檔（此路徑專用）
	FlagFileName     string // 結帳檔名稱（此路徑專用）
	AllowedTimeRange string // 此路徑的允許下載時間範圍（格式: HH:mm-HH:mm）
}

type Config struct {
	Host               string
	Port               string
	User               string
	Pass               string
	RemoteDir          string
	LocalDir           string
	LogDir             string
	FileTimesDir       string // 記錄檔案原始時間的資料夾
	FileNames          []PathMapping
	UseTLS             bool // 是否使用 TLS（false = 純文字 FTP，true = FTPS）
	UseImplicitTLS     bool
	InsecureSkipVerify bool
	SourceEncoding     string
	TargetEncoding     string
	DebugEncoding      bool
	SkipHeaderBytes    int
	GuardianAddCRLF    bool
	RawDownload        bool
	AllowedTimeRange   string   // 格式: "HH:mm-HH:mm", 例如 "02:00-05:00"
	CheckInterval      int      // 檢查間隔(分鐘)，預設 30 分鐘
	MonitorMode        bool     // 是否啟用全天監控模式
	StopTime           string   // 自動停止時間，格式: "HH:mm", 例如 "18:00"
	SplitFilePrefixes  []string // 需要自動分檔的檔案前綴，例如: ["TCD", "TSC"]
	SeparateFileLog    bool     // 是否為每個檔案產生獨立的 log
	LogRetentionDays   int      // 日誌保留天數（包含分檔日誌）
	CheckFlagFile      bool     // 是否檢查結帳檔（全局，已棄用）
	FlagFileName       string   // 結帳檔名稱
	FlagFilePath       string   // DATCLOSE 專用下載路徑
	AutoDeleteFlagFile bool     // 程式結束時自動刪除 DATCLOSE
}

type fileSpecList []string

func (l *fileSpecList) String() string {
	if l == nil {
		return ""
	}
	out := make([]string, len(*l))
	copy(out, *l)
	return strings.Join(out, ",")
}

func (l *fileSpecList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("file specification cannot be empty")
	}
	*l = append(*l, value)
	return nil
}

func (l fileSpecList) toSlice() []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

func getEncoder(name string) encoding.Encoding {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "ebcdic", "ebcdic-us", "cp037":
		return charmap.CodePage037
	case "ebcdic-1047", "cp1047":
		return charmap.CodePage1047
	case "ebcdic-1140", "cp1140":
		return charmap.CodePage1140
	case "big5", "big-5", "cp950", "windows-950":
		return traditionalchinese.Big5
	case "utf-8", "utf8":
		return unicode.UTF8
	case "iso-8859-1", "latin1":
		return charmap.ISO8859_1
	case "windows-1252", "cp1252":
		return charmap.Windows1252
	case "ascii":
		return nil
	default:
		return nil
	}
}

func convertEncoding(data []byte, sourceEncoding, targetEncoding string) ([]byte, error) {
	if sourceEncoding == "" || targetEncoding == "" || strings.EqualFold(sourceEncoding, targetEncoding) {
		return data, nil
	}

	srcEnc := getEncoder(sourceEncoding)
	dstEnc := getEncoder(targetEncoding)

	var decoded []byte
	if srcEnc != nil {
		reader := transform.NewReader(bytes.NewReader(data), srcEnc.NewDecoder())
		d, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to decode input data (%s): %w", sourceEncoding, err)
		}
		decoded = d
	} else {
		decoded = data
	}

	if strings.EqualFold(targetEncoding, "utf-8") || dstEnc == nil {
		return decoded, nil
	}

	var buf bytes.Buffer
	writer := transform.NewWriter(&buf, dstEnc.NewEncoder())
	if _, err := writer.Write(decoded); err != nil {
		return nil, fmt.Errorf("failed to encode data (%s): %w", targetEncoding, err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize encoding (%s): %w", targetEncoding, err)
	}

	return buf.Bytes(), nil
}

func stripGuardianBlocks(data []byte) ([]byte, bool) {
	const (
		guardianBlockSize  = 4096
		guardianFooterSize = 4
		minHeaderSize      = 20
	)

	if len(data) < guardianBlockSize {
		return data, false
	}

	var output bytes.Buffer
	converted := false
	offset := 0

	for offset < len(data) {
		remaining := len(data) - offset
		blockLen := guardianBlockSize
		if remaining < guardianBlockSize {
			blockLen = remaining
		}

		if blockLen < minHeaderSize+guardianFooterSize {
			// Last incomplete block, append as-is if we already converted something
			if converted && remaining > 0 {
				output.Write(data[offset:])
			}
			break
		}

		block := data[offset : offset+blockLen]

		// Trailer contains first-free offset and header size as big-endian uint16 values
		// Located at the last 4 bytes of each 4096-byte block
		firstFree := int(binary.BigEndian.Uint16(block[blockLen-4 : blockLen-2]))
		headerSize := int(binary.BigEndian.Uint16(block[blockLen-2:]))

		// Validate Guardian block structure
		if headerSize < minHeaderSize || headerSize > blockLen-guardianFooterSize {
			// Not a valid Guardian block
			if !converted {
				return data, false
			}
			// If we've already converted some blocks, this might be trailing data
			output.Write(data[offset:])
			break
		}

		if firstFree < headerSize || firstFree > blockLen {
			// Invalid first-free pointer
			if !converted {
				return data, false
			}
			output.Write(data[offset:])
			break
		}

		// Extract actual data between header and first-free marker
		dataStart := headerSize
		dataEnd := firstFree

		if dataEnd > dataStart {
			output.Write(block[dataStart:dataEnd])
			converted = true
		}

		offset += blockLen
	}

	if !converted {
		return data, false
	}

	return output.Bytes(), true
}

func filterControlBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	buf := make([]byte, 0, len(data))
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			buf = append(buf, b)
			continue
		}
		if b >= 0x20 {
			buf = append(buf, b)
		}
	}

	return buf
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{
		Port:               "21",
		LocalDir:           "./downloads",
		FileTimesDir:       "./file_times",
		FileNames:          make([]PathMapping, 0),
		UseTLS:             true,
		GuardianAddCRLF:    true,
		FlagFileName:       "DATCLOSE",
		AutoDeleteFlagFile: true,
	}

	scanner := bufio.NewScanner(file)
	fileItems := make(map[string]string)
	pathMappings := make(map[int]*PathMapping)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove inline comments (space + # or space + //)
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		if idx := strings.Index(value, " //"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}

		switch key {
		case "host":
			cfg.Host = value
		case "port":
			cfg.Port = value
		case "user":
			cfg.User = value
		case "pass":
			cfg.Pass = value
		case "remote_dir":
			cfg.RemoteDir = value
		case "local_dir":
			cfg.LocalDir = value
		case "log_dir":
			cfg.LogDir = value
		case "use_tls":
			cfg.UseTLS = (value == "true")
		case "use_implicit_tls":
			cfg.UseImplicitTLS = (value == "true")
		case "insecure_skip_verify":
			cfg.InsecureSkipVerify = (value == "true")
		case "source_encoding":
			cfg.SourceEncoding = value
		case "target_encoding":
			cfg.TargetEncoding = value
		case "debug_encoding":
			cfg.DebugEncoding = (value == "true")
		case "skip_header_bytes":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.SkipHeaderBytes = n
			}
		case "guardian_add_crlf":
			cfg.GuardianAddCRLF = (value == "true")
		case "raw_download":
			cfg.RawDownload = (value == "true")
		case "allowed_time_range":
			cfg.AllowedTimeRange = value
		case "check_interval":
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				cfg.CheckInterval = n
			}
		case "monitor_mode":
			cfg.MonitorMode = (value == "true")
		case "stop_time":
			cfg.StopTime = value
		case "split_file_prefixes":
			if value != "" {
				prefixes := strings.Split(value, ",")
				for _, p := range prefixes {
					p = strings.TrimSpace(p)
					if p != "" {
						cfg.SplitFilePrefixes = append(cfg.SplitFilePrefixes, p)
					}
				}
			}
		case "separate_file_log":
			cfg.SeparateFileLog = (value == "true")
		case "log_retention_days":
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				cfg.LogRetentionDays = n
			}
		case "check_flag_file":
			cfg.CheckFlagFile = (value == "true")
		case "flag_file_name":
			cfg.FlagFileName = value
		case "flag_file_path":
			cfg.FlagFilePath = value
		case "auto_delete_flag_file":
			cfg.AutoDeleteFlagFile = (value == "true")
		case "file_times_dir":
			cfg.FileTimesDir = value
		default:
			if strings.HasPrefix(key, "file_names.") {
				tokens := strings.Split(key, ".")
				if len(tokens) >= 3 {
					pathIdx, _ := strconv.Atoi(tokens[1])
					if tokens[2] == "remote_path" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{Files: make([]string, 0)}
						}
						pathMappings[pathIdx].RemotePath = value
					} else if tokens[2] == "check_flag_file" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{Files: make([]string, 0)}
						}
						pathMappings[pathIdx].CheckFlagFile = (value == "true")
					} else if tokens[2] == "flag_file_name" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{Files: make([]string, 0)}
						}
						pathMappings[pathIdx].FlagFileName = value
					} else if tokens[2] == "allowed_time_range" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{Files: make([]string, 0)}
						}
						pathMappings[pathIdx].AllowedTimeRange = value
					} else if tokens[2] == "files" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						fileItems[mapKey] = value
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Resolve relative directories against the config file location so
	// behavior stays consistent no matter where the process is launched from.
	if absConfigPath, err := filepath.Abs(path); err == nil {
		configDir := filepath.Dir(absConfigPath)

		if cfg.LocalDir != "" && !filepath.IsAbs(cfg.LocalDir) {
			cfg.LocalDir = filepath.Clean(filepath.Join(configDir, cfg.LocalDir))
		}
		if cfg.LogDir != "" && !filepath.IsAbs(cfg.LogDir) {
			cfg.LogDir = filepath.Clean(filepath.Join(configDir, cfg.LogDir))
		}
		if cfg.FileTimesDir != "" && !filepath.IsAbs(cfg.FileTimesDir) {
			cfg.FileTimesDir = filepath.Clean(filepath.Join(configDir, cfg.FileTimesDir))
		}
	}

	maxIdx := len(pathMappings) + 10
	for pathIdx := 0; pathIdx < maxIdx; pathIdx++ {
		if mapping, exists := pathMappings[pathIdx]; exists && mapping != nil {
			for fileIdx := 0; fileIdx < 100; fileIdx++ {
				mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
				if fileName, ok := fileItems[mapKey]; ok {
					mapping.Files = append(mapping.Files, fileName)
				}
			}

			// 如果此映射沒有設定結帳檔名稱，則使用全局預設值
			if mapping.FlagFileName == "" {
				mapping.FlagFileName = cfg.FlagFileName
			}
			// 注意：CheckFlagFile 的預設值是 false，如果需要使用全局設定，
			// 需要在配置檔中明確指定該路徑的 check_flag_file=true

			cfg.FileNames = append(cfg.FileNames, *mapping)
		}
	}

	return cfg, nil
}

// getRecordedFileTime 從 txt 檔案讀取記錄的遠端檔案時間
// 返回讀取到的時間，如果檔案不存在或讀取失敗則返回 zero time
func getRecordedFileTime(cfg *Config, fileName string) (time.Time, error) {
	if cfg.FileTimesDir == "" {
		return time.Time{}, nil
	}

	// 如果檔名已經以 .txt 結尾，就不再添加
	timeFileName := fileName
	if !strings.HasSuffix(strings.ToLower(fileName), ".txt") {
		timeFileName = fileName + ".txt"
	}
	timeFilePath := filepath.Join(cfg.FileTimesDir, timeFileName)

	data, err := os.ReadFile(timeFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil // 檔案不存在，返回 zero time
		}
		return time.Time{}, err
	}

	timeStr := strings.TrimSpace(string(data))
	if timeStr == "" {
		return time.Time{}, nil
	}

	// 嘗試解析時間（格式: 2006-01-02 15:04:05）
	parsedTime, err := time.ParseInLocation("2006-01-02 15:04:05", timeStr, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time from %s: %w", timeFilePath, err)
	}

	return parsedTime, nil
}

// saveRecordedFileTime 將遠端檔案時間寫入 txt 檔案
func saveRecordedFileTime(cfg *Config, fileName string, remoteTime time.Time) error {
	if cfg.FileTimesDir == "" {
		return nil
	}

	// 確保目錄存在
	if err := os.MkdirAll(cfg.FileTimesDir, 0755); err != nil {
		return fmt.Errorf("create file times directory: %w", err)
	}

	// 如果檔名已經以 .txt 結尾，就不再添加
	timeFileName := fileName
	if !strings.HasSuffix(strings.ToLower(fileName), ".txt") {
		timeFileName = fileName + ".txt"
	}
	timeFilePath := filepath.Join(cfg.FileTimesDir, timeFileName)

	// 將時間轉換為本地時間後寫入
	timeStr := remoteTime.Local().Format("2006-01-02 15:04:05")

	if err := os.WriteFile(timeFilePath, []byte(timeStr), 0644); err != nil {
		return fmt.Errorf("write time file %s: %w", timeFilePath, err)
	}

	log.Printf("📝 已記錄檔案時間: %s -> %s", fileName, timeStr)

	return nil
}

// parseRemotePath 解析遠端路徑，回傳 (目錄, 檔名)
func parseRemotePath(remotePath string) (string, string) {
	if strings.Contains(remotePath, "\\") {
		// Guardian/NonStop 路徑格式: \CSTP96.$DATA.SKDATA91.FILENAME
		lastDot := strings.LastIndex(remotePath, ".")
		if lastDot > 0 {
			return remotePath[:lastDot], remotePath[lastDot+1:]
		}
		return remotePath, ""
	}
	return filepath.Dir(remotePath), filepath.Base(remotePath)
}

// writeFileLog 寫入獨立的檔案下載 log
func writeFileLog(cfg *Config, localName string, info map[string]string) error {
	if !cfg.SeparateFileLog {
		return nil
	}

	logDir := cfg.LogDir
	if logDir == "" {
		logDir = "logs"
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	// 產生 log 檔案名稱：原檔名-日期.log（分天記錄）
	today := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("%s-%s.log", localName, today)
	logPath := filepath.Join(logDir, logFileName)

	// 開啟或建立 log 檔案（附加模式）
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	// 寫入日誌
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "\n========================================\n")
	fmt.Fprintf(f, "下載時間: %s\n", timestamp)

	if remoteTime, ok := info["remote_time"]; ok {
		fmt.Fprintf(f, "遠端檔案時間: %s\n", remoteTime)
	}
	if remoteSize, ok := info["remote_size"]; ok {
		fmt.Fprintf(f, "遠端檔案大小: %s bytes\n", remoteSize)
	}
	if localTimeBefore, ok := info["local_time_before"]; ok {
		fmt.Fprintf(f, "本地檔案時間(下載前): %s\n", localTimeBefore)
	}
	if localSizeBefore, ok := info["local_size_before"]; ok {
		fmt.Fprintf(f, "本地檔案大小(下載前): %s bytes\n", localSizeBefore)
	}
	if downloaded, ok := info["downloaded_bytes"]; ok {
		fmt.Fprintf(f, "下載位元組數: %s bytes\n", downloaded)
	}
	if finalSize, ok := info["final_size"]; ok {
		fmt.Fprintf(f, "最終檔案大小: %s bytes\n", finalSize)
	}
	if localTimeAfter, ok := info["local_time_after"]; ok {
		fmt.Fprintf(f, "本地檔案時間(下載後): %s\n", localTimeAfter)
	}
	if reason, ok := info["reason"]; ok {
		fmt.Fprintf(f, "下載原因: %s\n", reason)
	}
	if status, ok := info["status"]; ok {
		fmt.Fprintf(f, "狀態: %s\n", status)
	}

	fmt.Fprintf(f, "========================================\n")

	return nil
}

func downloadFile(client *ftp.ServerConn, cfg *Config, remotePath, localName string) (bool, error) {
	localPath := filepath.Join(cfg.LocalDir, localName)

	// 準備 log 資訊
	logInfo := make(map[string]string)

	// 取得遠端檔案資訊
	remoteSize := int64(-1)
	var remoteTime time.Time

	if size, err := client.FileSize(remotePath); err == nil {
		remoteSize = size
		logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
		log.Printf("  📊 遠端檔案大小: %d bytes", remoteSize)
	} else {
		log.Printf("WARNING: 無法以 SIZE 命令取得遠端檔案大小 %s: %v，嘗試使用 LIST...", remotePath, err)
		// NonStop 伺服器不支援 SIZE 命令，改用 LIST 取得
		remoteDir, remoteFileName := parseRemotePath(remotePath)
		if entries, listErr := client.List(remoteDir); listErr == nil {
			for _, entry := range entries {
				if entry.Name == remoteFileName {
					remoteSize = int64(entry.Size)
					logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
					log.Printf("  📊 遠端檔案大小 (via LIST): %d bytes", remoteSize)
					break
				}
			}
		}
		if remoteSize == -1 {
			logInfo["remote_size"] = "無法取得"
			log.Printf("WARNING: LIST 也無法取得遠端檔案大小: %s", remotePath)
		}
	}

	if remoteSize == 0 {
		log.Printf("  ⊘ 跳過下載 %s：遠端檔案大小為 0 bytes，不進行下載", localName)
		logInfo["status"] = "skipped"
		logInfo["reason"] = "遠端檔案大小為 0 bytes，跳過下載"
		if err := writeFileLog(cfg, localName, logInfo); err != nil {
			log.Printf("Warning: Failed to write file log for %s: %v", localName, err)
		}
		return false, nil
	}

	if modTime, err := client.GetTime(remotePath); err == nil {
		remoteTime = modTime
		// 轉換為本地時間顯示
		logInfo["remote_time"] = remoteTime.Local().Format("2006-01-02 15:04:05")
	} else {
		// GetTime 失敗，嘗試使用 List 取得檔案資訊
		log.Printf("WARNING: Cannot retrieve remote file time via MDTM for %s: %v", remotePath, err)
		log.Printf("嘗試使用 LIST 命令取得檔案時間...")

		remoteDir, remoteFileName := parseRemotePath(remotePath)
		log.Printf("嘗試列出目錄: %s", remoteDir)
		log.Printf("尋找檔案: %s", remoteFileName)

		// 列出目錄
		if entries, listErr := client.List(remoteDir); listErr == nil {
			log.Printf("LIST 成功，找到 %d 個項目", len(entries))
			// 尋找目標檔案
			for _, entry := range entries {
				if entry.Name == remoteFileName {
					if !entry.Time.IsZero() {
						remoteTime = entry.Time
						// 轉換為本地時間顯示
						logInfo["remote_time"] = remoteTime.Local().Format("2006-01-02 15:04:05")
						log.Printf("✓ 成功透過 LIST 取得檔案時間: %s", remoteTime.Local().Format("2006-01-02 15:04:05"))
					} else {
						log.Printf("WARNING: List 回傳的檔案時間為空")
						logInfo["remote_time"] = "無法取得"
					}
					// 同時從 LIST 更新檔案大小（若 SIZE 命令之前也失敗）
					if remoteSize == -1 {
						remoteSize = int64(entry.Size)
						logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
						log.Printf("  📊 遠端檔案大小 (via LIST): %d bytes", remoteSize)
					}
					break
				}
			}
			if remoteTime.IsZero() {
				log.Printf("WARNING: 在 LIST 結果中找不到檔案 %s", remoteFileName)
				// 列出所有找到的檔案名稱以便除錯
				if len(entries) > 0 {
					log.Printf("DEBUG: LIST 回傳的檔案:")
					for i, entry := range entries {
						if i < 10 { // 只顯示前 10 個
							log.Printf("  - %s (Time: %v)", entry.Name, entry.Time)
						}
					}
				}
				logInfo["remote_time"] = "無法取得"
			}
		} else {
			log.Printf("WARNING: LIST 命令也失敗: %v", listErr)
			logInfo["remote_time"] = "無法取得"
		}
	}

	// 檢查本地檔案是否存在
	var downloadReason string
	if localInfo, err := os.Stat(localPath); err == nil {
		// 記錄本地檔案的原始狀態
		logInfo["local_time_before"] = localInfo.ModTime().Format("2006-01-02 15:04:05")
		logInfo["local_size_before"] = fmt.Sprintf("%d", localInfo.Size())

		// 本地檔案存在，比對是否需要更新
		needDownload := false

		// 比對檔案大小
		if remoteSize > 0 && localInfo.Size() != remoteSize {
			log.Printf("📊 檔案大小不同: %s (本地: %d bytes, 遠端: %d bytes)", localName, localInfo.Size(), remoteSize)
			needDownload = true
			downloadReason = fmt.Sprintf("檔案大小不同 (本地: %d bytes, 遠端: %d bytes)", localInfo.Size(), remoteSize)
		}

		// 比對修改時間（使用 txt 記錄的時間）
		if !remoteTime.IsZero() {
			// 讀取 txt 記錄的時間
			recordedTime, err := getRecordedFileTime(cfg, localName)
			if err != nil {
				log.Printf("⚠️  讀取記錄時間失敗: %v", err)
			}

			if recordedTime.IsZero() {
				// 沒有記錄，表示是新檔案或首次使用此功能，需要下載
				log.Printf("🕒 首次下載或無時間記錄: %s (遠端: %s)", localName,
					remoteTime.Local().Format("2006-01-02 15:04:05"))
				needDownload = true
				if downloadReason != "" {
					downloadReason += "、無時間記錄"
				} else {
					downloadReason = "無時間記錄，需要下載"
				}
			} else if remoteTime.After(recordedTime) {
				// 遠端時間比記錄的時間新
				log.Printf("🕒 遠端檔案較新: %s (記錄: %s, 遠端: %s)", localName,
					recordedTime.Format("2006-01-02 15:04:05"),
					remoteTime.Local().Format("2006-01-02 15:04:05"))
				needDownload = true
				if downloadReason != "" {
					downloadReason += "、遠端檔案較新"
				} else {
					downloadReason = "遠端檔案較新"
				}
			} else {
				log.Printf("✓ 遠端檔案未更新: %s (記錄: %s, 遠端: %s)", localName,
					recordedTime.Format("2006-01-02 15:04:05"),
					remoteTime.Local().Format("2006-01-02 15:04:05"))
			}
		}

		// 如果檔案相同，跳過下載
		if !needDownload {
			if remoteSize > 0 {
				log.Printf("⏭️  跳過下載: %s (本地檔案已是最新，大小: %d bytes)", localName, localInfo.Size())
			} else {
				log.Printf("⏭️  跳過下載: %s (本地檔案已存在)", localName)
			}

			// 記錄跳過的原因
			logInfo["status"] = "跳過下載"
			logInfo["reason"] = "本地檔案已是最新"
			writeFileLog(cfg, localName, logInfo)

			return false, nil
		}

		log.Printf("🔄 更新檔案: %s (遠端大小: %d bytes)", localName, remoteSize)
	} else {
		// 本地檔案不存在，需要下載
		downloadReason = "本地檔案不存在"
		if remoteSize > 0 {
			log.Printf("📥 下載新檔案: %s (遠端大小: %d bytes)", localName, remoteSize)
		} else {
			log.Printf("📥 下載新檔案: %s", localName)
		}
	}

	logInfo["reason"] = downloadReason

	reader, err := client.Retr(remotePath)
	if err != nil {
		// If ASCII mode fails with filecode error, try binary mode
		if strings.Contains(err.Error(), "Can't use ASCII transfer mode") || strings.Contains(err.Error(), "filecode") {
			log.Printf("ASCII mode not supported for %s, switching to binary mode...", remotePath)
			if switchErr := client.Type(ftp.TransferTypeBinary); switchErr != nil {
				return false, fmt.Errorf("retrieve %s: failed to switch to binary mode: %w", remotePath, switchErr)
			}
			reader, err = client.Retr(remotePath)
			if err != nil {
				return false, fmt.Errorf("retrieve %s (binary mode): %w", remotePath, err)
			}
			// Switch back to ASCII for next file
			defer func() {
				if switchErr := client.Type(ftp.TransferTypeASCII); switchErr != nil {
					log.Printf("Warning: failed to switch back to ASCII mode: %v", switchErr)
				}
			}()
		} else {
			return false, fmt.Errorf("retrieve %s: %w", remotePath, err)
		}
	}
	defer reader.Close()

	var buf bytes.Buffer
	rawBytesRead, err := io.Copy(&buf, reader)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", remotePath, err)
	}

	// Verify download size matches remote size
	if remoteSize > 0 && rawBytesRead != remoteSize {
		return false, fmt.Errorf("download size mismatch for %s: expected %d bytes, got %d bytes", remotePath, remoteSize, rawBytesRead)
	}

	rawData := buf.Bytes()
	processed := processData(cfg, remotePath, rawData)

	if err := os.WriteFile(localPath, processed, 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", localPath, err)
	}

	// 記錄下載的位元組數
	logInfo["downloaded_bytes"] = fmt.Sprintf("%d", rawBytesRead)

	// 設定檔案時間為本地當前時間，並將遠端時間記錄到 txt
	localNow := time.Now()
	log.Printf("🕒 設定檔案時間為本地時間: %s", localNow.Format("2006-01-02 15:04:05"))

	if err := os.Chtimes(localPath, localNow, localNow); err != nil {
		log.Printf("⚠️  Warning: Failed to set file time for %s: %v", localPath, err)
	}

	// 記錄遠端檔案時間到 txt
	if !remoteTime.IsZero() {
		if err := saveRecordedFileTime(cfg, localName, remoteTime); err != nil {
			log.Printf("⚠️  Warning: Failed to save recorded time for %s: %v", localName, err)
		}
	}

	// Verify written file
	writtenInfo, err := os.Stat(localPath)
	if err != nil {
		return false, fmt.Errorf("verify written file %s: %w", localPath, err)
	}

	// 記錄最終檔案資訊
	logInfo["final_size"] = fmt.Sprintf("%d", writtenInfo.Size())
	logInfo["local_time_after"] = writtenInfo.ModTime().Format("2006-01-02 15:04:05")
	logInfo["status"] = "下載成功"

	log.Printf("✓ Downloaded %s to %s", remotePath, localPath)
	if !remoteTime.IsZero() {
		log.Printf("  Remote time: %s", remoteTime.Local().Format("2006-01-02 15:04:05"))
	}
	log.Printf("  Remote size: %d bytes", remoteSize)
	log.Printf("  Downloaded: %d bytes", rawBytesRead)
	log.Printf("  Final size: %d bytes", writtenInfo.Size())
	log.Printf("  Local time: %s", writtenInfo.ModTime().Format("2006-01-02 15:04:05"))

	if cfg.RawDownload {
		if writtenInfo.Size() != rawBytesRead {
			return false, fmt.Errorf("verification failed for %s: written size (%d) != downloaded size (%d)", localPath, writtenInfo.Size(), rawBytesRead)
		}
		if remoteSize > 0 && writtenInfo.Size() != remoteSize {
			return false, fmt.Errorf("verification failed for %s: final size (%d) != remote size (%d)", localPath, writtenInfo.Size(), remoteSize)
		}
		log.Printf("✓ Verification passed: file content exactly matches remote file")
	} else if remoteSize > 0 && rawBytesRead == remoteSize {
		log.Printf("✓ Download verification passed: raw data matches remote size")
	}

	// 寫入獨立的檔案 log
	if err := writeFileLog(cfg, localName, logInfo); err != nil {
		log.Printf("⚠️  Warning: Failed to write file log for %s: %v", localName, err)
	}

	return true, nil
}

// splitFileByPrefix 根據每行前四碼分割檔案
func splitFileByPrefix(filePath string, prefixes []string) error {
	// 檢查檔案名稱是否匹配需要分檔的前綴
	fileName := filepath.Base(filePath)
	shouldSplit := false
	for _, prefix := range prefixes {
		if strings.HasPrefix(strings.ToUpper(fileName), strings.ToUpper(prefix)) {
			shouldSplit = true
			break
		}
	}

	if !shouldSplit {
		return nil
	}

	log.Printf("📂 開始分檔處理: %s", fileName)

	// 讀取檔案內容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("讀取檔案失敗: %w", err)
	}

	// 按行分割
	lines := strings.Split(string(data), "\n")

	// 用於存儲每個前綴的內容
	splitData := make(map[string][]string)
	lineCount := 0

	for _, line := range lines {
		// 跳過空行
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 取得前四碼作為分類鍵
		var key string
		if len(line) >= 4 {
			key = line[:4]
		} else {
			key = "UNKNOWN"
		}

		splitData[key] = append(splitData[key], line)
		lineCount++
	}

	if len(splitData) == 0 {
		log.Printf("⚠️  檔案 %s 沒有可分割的內容", fileName)
		return nil
	}

	log.Printf("📊 檔案 %s 共 %d 行，分為 %d 個子檔案", fileName, lineCount, len(splitData))

	// 為每個前綴創建獨立檔案
	fileDir := filepath.Dir(filePath)
	baseNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	splitCount := 0

	for prefix, content := range splitData {
		if len(content) == 0 {
			continue
		}

		// 新檔案名稱格式: 原檔名.前四碼 (例如: TCD.9b2r)
		newFileName := fmt.Sprintf("%s.%s", baseNameWithoutExt, prefix)
		newFilePath := filepath.Join(fileDir, newFileName)

		// 組合內容（保持原始換行）
		fileContent := strings.Join(content, "\n")
		if !strings.HasSuffix(fileContent, "\n") {
			fileContent += "\n"
		}

		// 寫入新檔案
		if err := os.WriteFile(newFilePath, []byte(fileContent), 0644); err != nil {
			log.Printf("❌ 寫入分檔失敗 %s: %v", newFileName, err)
			continue
		}

		log.Printf("  ✓ 已建立: %s (%d 行)", newFileName, len(content))
		splitCount++
	}

	if splitCount > 0 {
		log.Printf("✓ 分檔完成: %s → %d 個子檔案（保留原始檔案供比對使用）", fileName, splitCount)
	}

	return nil
}

func isWithinTimeRange(rangeStr string) (bool, error) {
	if rangeStr == "" {
		return true, nil
	}

	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid time range format: %s", rangeStr)
	}

	now := time.Now()
	today := now.Format("2006-01-02")

	start, err := time.ParseInLocation("2006-01-02 15:04", today+" "+parts[0], time.Local)
	if err != nil {
		return false, err
	}

	end, err := time.ParseInLocation("2006-01-02 15:04", today+" "+parts[1], time.Local)
	if err != nil {
		return false, err
	}

	// Handle overnight ranges (e.g., 22:00-04:00)
	if end.Before(start) {
		if now.Before(start) {
			start = start.AddDate(0, 0, -1)
		} else {
			end = end.AddDate(0, 0, 1)
		}
	}

	return now.After(start) && now.Before(end), nil
}

func shouldStopMonitor(stopTimeStr string) (bool, error) {
	if stopTimeStr == "" {
		return false, nil
	}

	now := time.Now()
	today := now.Format("2006-01-02")

	stopTime, err := time.ParseInLocation("2006-01-02 15:04", today+" "+stopTimeStr, time.Local)
	if err != nil {
		return false, fmt.Errorf("invalid stop time format: %s (expected HH:mm)", stopTimeStr)
	}

	// 檢查當前時間是否已經到達或超過停止時間
	// 使用 After 或 Equal 來確保在精確時間也會停止
	return now.After(stopTime) || now.Equal(stopTime), nil
}

func processData(cfg *Config, remotePath string, data []byte) []byte {
	if cfg.RawDownload {
		log.Printf("[RAW MODE] Preserving exact binary content for %s (%d bytes, no processing)", remotePath, len(data))
		return data
	}

	processed := data

	if cfg.DebugEncoding && len(processed) > 0 {
		debugLen := 100
		if len(processed) < debugLen {
			debugLen = len(processed)
		}
		log.Printf("First %d raw bytes (hex) for %s: % X", debugLen, remotePath, processed[:debugLen])
		log.Printf("First %d raw bytes (as text) for %s: %q", debugLen, remotePath, string(processed[:debugLen]))
	}

	switch {
	case cfg.SkipHeaderBytes > 0:
		if len(processed) > cfg.SkipHeaderBytes {
			log.Printf("Skipping first %d bytes for %s (manual configuration)", cfg.SkipHeaderBytes, remotePath)
			processed = processed[cfg.SkipHeaderBytes:]
		} else {
			processed = processed[:0]
		}
	case cfg.SkipHeaderBytes == -1:
		filtered := filterControlBytes(processed)
		removed := len(processed) - len(filtered)
		if removed > 0 {
			log.Printf("Filtered %d control bytes from %s (legacy filter)", removed, remotePath)
		}
		processed = filtered
	default:
		if stripped, ok := stripGuardianBlocks(processed); ok {
			log.Printf("Detected Guardian/NonStop block format in %s. Stripped to %d bytes (raw %d bytes).", remotePath, len(stripped), len(processed))

			processed = stripped

			if cfg.GuardianAddCRLF {
				trimmed := bytes.TrimRight(processed, "\x00")
				if removed := len(processed) - len(trimmed); removed > 0 {
					log.Printf("Trimmed %d trailing NUL byte(s) from Guardian record for %s", removed, remotePath)
				}
				processed = trimmed
			}

			if cfg.GuardianAddCRLF && len(processed) > 0 {
				last := processed[len(processed)-1]
				if last != '\n' {
					copyBuf := make([]byte, len(processed))
					copy(copyBuf, processed)
					if last == '\r' {
						copyBuf = append(copyBuf, '\n')
					} else {
						copyBuf = append(copyBuf, '\r', '\n')
					}
					processed = copyBuf
					log.Printf("Appended CRLF to Guardian record for %s (final size: %d bytes)", remotePath, len(processed))
				}
			}
		}
	}

	if cfg.SourceEncoding != "" && cfg.TargetEncoding != "" {
		converted, err := convertEncoding(processed, cfg.SourceEncoding, cfg.TargetEncoding)
		if err != nil {
			log.Printf("Error converting encoding for %s: %v", remotePath, err)
			log.Printf("Saving original bytes without conversion...")
		} else {
			processed = converted
			log.Printf("Converted encoding from %s to %s for %s", cfg.SourceEncoding, cfg.TargetEncoding, remotePath)
		}
	}

	return processed
}

func combineRemotePath(basePath, remoteFile string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return remoteFile
	}
	if strings.HasSuffix(basePath, ".") {
		return basePath + remoteFile
	}
	return basePath + "." + remoteFile
}

func runDownload(cfg *Config, logWriter io.Writer) error {
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("Connecting to %s ...", addr)

	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(10 * time.Second),
		// 不設定 DialWithLocation，讓 FTP 庫用 UTC 解析時間
		// 然後在設定檔案時間時用 .Local() 轉換成本地時間
	}

	if cfg.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			ServerName:         cfg.Host,
		}
		if cfg.UseImplicitTLS {
			dialOptions = append(dialOptions, ftp.DialWithTLS(tlsConfig))
		} else {
			dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
		}
	}

	client, err := ftp.Dial(addr, dialOptions...)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer func() {
		if quitErr := client.Quit(); quitErr != nil {
			log.Printf("Error closing FTP connection: %v", quitErr)
		}
	}()

	log.Println("Connected. Logging in...")
	if err := client.Login(cfg.User, cfg.Pass); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	log.Println("Logged in successfully.")

	// Use ASCII mode for Guardian/NonStop systems - this automatically handles Guardian block format
	if err := client.Type(ftp.TransferTypeASCII); err != nil {
		log.Printf("Warning: failed to set ASCII transfer mode: %v", err)
		log.Println("Attempting binary mode as fallback...")
		if err := client.Type(ftp.TransferTypeBinary); err != nil {
			return fmt.Errorf("failed to set transfer mode: %w", err)
		}
		log.Println("✓ Binary transfer mode enabled")
	} else {
		log.Println("✓ ASCII transfer mode enabled (auto-handles Guardian/NonStop format)")
	}

	if curDir, err := client.CurrentDir(); err == nil {
		log.Printf("Current remote directory: %s", curDir)
	} else {
		log.Printf("Error getting current directory: %v", err)
	}

	if cfg.RemoteDir != "" {
		if err := client.ChangeDir(cfg.RemoteDir); err != nil {
			return fmt.Errorf("change directory to %s: %w", cfg.RemoteDir, err)
		}
		log.Printf("Changed directory to %s", cfg.RemoteDir)
	}

	entries, err := client.NameList("")
	if err != nil {
		return fmt.Errorf("list files: %w", err)
	}

	// 先下載結帳檔（如果有設定專用路徑）
	if err := downloadFlagFile(client, cfg); err != nil {
		log.Printf("⚠️  結帳檔下載失敗: %v", err)
		log.Printf("ℹ️  繼續執行其他下載作業...")
	}

	downloadCount := 0

	if len(cfg.FileNames) > 0 {
		log.Println("Downloading specified files from config...")
		for _, mapping := range cfg.FileNames {
			basePath := strings.TrimSpace(mapping.RemotePath)

			// 檢查路徑專屬的時間範圍
			if mapping.AllowedTimeRange != "" {
				within, err := isWithinTimeRange(mapping.AllowedTimeRange)
				if err != nil {
					log.Printf("❌ 路徑 %s 的時間範圍格式錯誤: %v", basePath, err)
					continue
				}
				if !within {
					log.Printf("⏭️  跳過目錄 %s：目前時間不在允許範圍 %s 內", basePath, mapping.AllowedTimeRange)
					continue
				}
				log.Printf("✅ 目錄 %s 在允許時間範圍 %s 內，執行下載", basePath, mapping.AllowedTimeRange)
			}

			// 檢查結帳檔（針對此路徑映射）- 檢查本地是否有當天的 DATCLOSE
			if mapping.CheckFlagFile && mapping.FlagFileName != "" {
				log.Printf("🔍 檢查本地結帳檔: %s", mapping.FlagFileName)

				if !checkLocalFlagFile(cfg) {
					log.Printf("⏭️  跳過目錄 %s：本地結帳檔 %s 不存在或不是當天的檔案", basePath, mapping.FlagFileName)
					continue
				}
				log.Printf("✓ 本地結帳檔存在，開始下載檔案")
			}

			for _, fileSpec := range mapping.Files {
				fileSpec = strings.TrimSpace(fileSpec)
				if fileSpec == "" {
					continue
				}

				remoteFileName := fileSpec
				localFileName := fileSpec
				if idx := strings.Index(fileSpec, ":"); idx >= 0 {
					remoteFileName = strings.TrimSpace(fileSpec[:idx])
					localFileName = strings.TrimSpace(fileSpec[idx+1:])
					if localFileName == "" {
						localFileName = remoteFileName
					}
				}

				remotePath := combineRemotePath(basePath, remoteFileName)

				downloaded, err := downloadFile(client, cfg, remotePath, localFileName)
				if err != nil {
					log.Printf("Error downloading %s: %v", remotePath, err)
					continue
				}
				if downloaded {
					downloadCount++

					// 下載成功後，檢查是否需要分檔
					if len(cfg.SplitFilePrefixes) > 0 {
						localPath := filepath.Join(cfg.LocalDir, localFileName)
						if err := splitFileByPrefix(localPath, cfg.SplitFilePrefixes); err != nil {
							log.Printf("⚠️  分檔處理失敗 %s: %v", localFileName, err)
						}
					}
				}
			}
		}
	} else {
		for _, name := range entries {
			if name == "." || name == ".." {
				continue
			}

			downloaded, err := downloadFile(client, cfg, name, name)
			if err != nil {
				log.Printf("Error downloading %s: %v", name, err)
				continue
			}
			if downloaded {
				downloadCount++

				// 下載成功後，檢查是否需要分檔
				if len(cfg.SplitFilePrefixes) > 0 {
					localPath := filepath.Join(cfg.LocalDir, name)
					if err := splitFileByPrefix(localPath, cfg.SplitFilePrefixes); err != nil {
						log.Printf("⚠️  分檔處理失敗 %s: %v", name, err)
					}
				}
			}
		}
	}

	log.Printf("Download completed. %d file(s) downloaded.", downloadCount)

	// 下載完成後，刪除結帳檔（如果啟用自動刪除）
	deleteFlagFile(cfg)

	return nil
}

func main() {
	// Setup logging with timestamp
	log.SetFlags(log.LstdFlags)

	// ---------------------------------------------------------------
	// 盡早建立啟動 log。
	// 策略（依序嘗試，全部成功時同時寫入）：
	//   1. <exe目錄>\logs\ftps-downloader-<日期>.log   (正式日誌)
	//   2. <exe目錄>\ftps-downloader-startup.log        (緊急備援，直接放在 exe 旁)
	//   3. stdout                                        (最後手段)
	// ---------------------------------------------------------------
	var logWriters []io.Writer
	logWriters = append(logWriters, os.Stdout)

	today := time.Now().Format("2006-01-02")
	var startupLogFile *os.File

	exePath, exeErr := os.Executable()
	if exeErr == nil {
		exeDir := filepath.Dir(exePath)

		// 1. 正式日誌：<exe目錄>\logs\ftps-downloader-<日期>.log
		logsDir := filepath.Join(exeDir, "logs")
		_ = os.MkdirAll(logsDir, 0755)
		mainLogPath := filepath.Join(logsDir, "ftps-downloader-"+today+".log")
		if f, err := os.OpenFile(mainLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			if info, _ := f.Stat(); info != nil && info.Size() <= 3 {
				_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})
			}
			startupLogFile = f
			logWriters = append(logWriters, f)
		}

		// 2. 緊急備援：<exe目錄>\ftps-downloader-startup.log（不分日期，方便檢查）
		emergencyPath := filepath.Join(exeDir, "ftps-downloader-startup.log")
		if ef, err := os.OpenFile(emergencyPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			defer ef.Close()
			fmt.Fprintf(ef, "\n--- %s ---\n", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Fprintf(ef, "exe: %s\n", exePath)
			fmt.Fprintf(ef, "main log: %s\n", mainLogPath)
			logWriters = append(logWriters, ef)
		}
	}

	log.SetOutput(io.MultiWriter(logWriters...))

	if exeErr != nil {
		log.Printf("⚠️  無法取得 exe 路徑: %v，日誌僅輸出至 stdout", exeErr)
	}

	log.Printf("========================================")
	log.Printf("FTPS Downloader started")
	log.Printf("========================================")
	log.Println()

	// 1. 確保單一執行實例（終止舊實例）
	if err := ensureSingleInstance(); err != nil {
		log.Printf("❌ 執行實例檢查失敗: %v", err)
		if startupLogFile != nil {
			startupLogFile.Close()
		}
		os.Exit(1)
	}

	configPath := flag.String("config", "", "Path to configuration file (default: config.properties next to the exe)")
	hostFlag := flag.String("host", "", "FTP server host (direct mode or override)")
	portFlag := flag.String("port", "21", "FTP server port")
	userFlag := flag.String("user", "", "FTP username (direct mode or override)")
	passFlag := flag.String("pass", "", "FTP password (direct mode or override)")
	remoteDirFlag := flag.String("remote-dir", "", "Remote directory to change into before downloading")
	remoteBaseFlag := flag.String("remote-base", "", "Remote path prefix prepended to each -file entry (direct mode)")
	localDirFlag := flag.String("local-dir", "", "Local download directory override")
	logDirFlag := flag.String("log-dir", "", "Log directory override")
	implicitFlag := flag.Bool("implicit-tls", false, "Use implicit TLS")
	noTLSFlag := flag.Bool("no-tls", false, "Disable TLS, use plain FTP")
	insecureFlag := flag.Bool("insecure-skip-verify", false, "Skip TLS certificate verification")
	sourceEncFlag := flag.String("source-encoding", "", "Source encoding name")
	targetEncFlag := flag.String("target-encoding", "", "Target encoding name")
	debugEncodingFlag := flag.Bool("debug-encoding", false, "Enable encoding debug output")
	skipHeaderFlag := flag.Int("skip-header-bytes", 0, "Number of header bytes to skip (-1 filters control bytes)")
	guardianAddCRLFFlag := flag.Bool("guardian-add-crlf", true, "Append CRLF when stripping Guardian blocks")
	rawDownloadFlag := flag.Bool("raw-download", false, "Download files without any processing (preserve exact binary content)")
	allowedTimeRangeFlag := flag.String("allowed-time-range", "", "Allowed download time range (format: HH:mm-HH:mm, e.g., 02:00-05:00)")
	checkIntervalFlag := flag.Int("check-interval", 30, "Check interval in minutes for monitor mode (default: 30)")
	monitorModeFlag := flag.Bool("monitor-mode", false, "Enable continuous monitor mode")
	stopTimeFlag := flag.String("stop-time", "", "Auto stop time for monitor mode (format: HH:mm, e.g., 18:00)")

	var filesFlag fileSpecList
	flag.Var(&filesFlag, "file", "Remote file specification remote[:local]; repeat for multiple files (direct mode)")

	flag.Parse()

	// 若使用者沒有明確指定 -config，自動決定設定檔路徑：
	// 優先用 exe 所在目錄的 config.properties，確保無論從哪個工作目錄執行都能找到。
	if *configPath == "" {
		resolvedConfig := "config.properties"
		// 嘗試從 exe 所在目錄尋找
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			candidate := filepath.Join(exeDir, "config.properties")
			// 優先用 exe 目錄旁的設定檔；若不存在才嘗試當前工作目錄
			if _, err := os.Stat(candidate); err == nil {
				resolvedConfig = candidate
			}
		}
		*configPath = resolvedConfig
		log.Printf("設定檔: %s", *configPath)
	}

	overrides := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		overrides[f.Name] = true
	})

	directMode := len(filesFlag) > 0

	if directMode {
		if !overrides["host"] || strings.TrimSpace(*hostFlag) == "" {
			fmt.Fprintln(os.Stderr, "host is required when using direct mode (-file)")
			os.Exit(2)
		}
		if !overrides["user"] || strings.TrimSpace(*userFlag) == "" {
			fmt.Fprintln(os.Stderr, "user is required when using direct mode (-file)")
			os.Exit(2)
		}
		if !overrides["pass"] || *passFlag == "" {
			fmt.Fprintln(os.Stderr, "pass is required when using direct mode (-file)")
			os.Exit(2)
		}

		files := filesFlag.toSlice()
		mapping := PathMapping{
			RemotePath: strings.TrimSpace(*remoteBaseFlag),
			Files:      files,
		}

		cfg := &Config{
			Host:               strings.TrimSpace(*hostFlag),
			Port:               strings.TrimSpace(*portFlag),
			User:               *userFlag,
			Pass:               *passFlag,
			RemoteDir:          strings.TrimSpace(*remoteDirFlag),
			LocalDir:           strings.TrimSpace(*localDirFlag),
			LogDir:             strings.TrimSpace(*logDirFlag),
			FileNames:          []PathMapping{mapping},
			UseTLS:             !*noTLSFlag,
			UseImplicitTLS:     *implicitFlag,
			InsecureSkipVerify: *insecureFlag,
			SourceEncoding:     strings.TrimSpace(*sourceEncFlag),
			TargetEncoding:     strings.TrimSpace(*targetEncFlag),
			DebugEncoding:      *debugEncodingFlag,
			SkipHeaderBytes:    *skipHeaderFlag,
			GuardianAddCRLF:    *guardianAddCRLFFlag,
			RawDownload:        *rawDownloadFlag,
			AllowedTimeRange:   strings.TrimSpace(*allowedTimeRangeFlag),
			CheckInterval:      *checkIntervalFlag,
			MonitorMode:        *monitorModeFlag,
			StopTime:           strings.TrimSpace(*stopTimeFlag),
		}

		if err := run(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "\n下載失敗: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if overrides["file"] {
		fmt.Fprintln(os.Stderr, "-file requires -host and is only available in direct mode")
		os.Exit(2)
	}
	if overrides["remote-base"] {
		fmt.Fprintln(os.Stderr, "-remote-base can only be used together with -file")
		os.Exit(2)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n無法載入設定檔 '%s': %v\n", *configPath, err)
		os.Exit(1)
	}

	if overrides["host"] {
		cfg.Host = strings.TrimSpace(*hostFlag)
	}
	if overrides["port"] {
		cfg.Port = strings.TrimSpace(*portFlag)
	}
	if overrides["user"] {
		cfg.User = strings.TrimSpace(*userFlag)
	}
	if overrides["pass"] {
		cfg.Pass = *passFlag
	}
	if overrides["remote-dir"] {
		cfg.RemoteDir = strings.TrimSpace(*remoteDirFlag)
	}
	if overrides["local-dir"] {
		cfg.LocalDir = strings.TrimSpace(*localDirFlag)
	}
	if overrides["log-dir"] {
		cfg.LogDir = strings.TrimSpace(*logDirFlag)
	}
	if overrides["implicit-tls"] {
		cfg.UseImplicitTLS = *implicitFlag
	}
	if overrides["no-tls"] {
		cfg.UseTLS = !*noTLSFlag
	}
	if overrides["insecure-skip-verify"] {
		cfg.InsecureSkipVerify = *insecureFlag
	}
	if overrides["source-encoding"] {
		cfg.SourceEncoding = strings.TrimSpace(*sourceEncFlag)
	}
	if overrides["target-encoding"] {
		cfg.TargetEncoding = strings.TrimSpace(*targetEncFlag)
	}
	if overrides["debug-encoding"] {
		cfg.DebugEncoding = *debugEncodingFlag
	}
	if overrides["skip-header-bytes"] {
		cfg.SkipHeaderBytes = *skipHeaderFlag
	}
	if overrides["guardian-add-crlf"] {
		cfg.GuardianAddCRLF = *guardianAddCRLFFlag
	}
	if overrides["raw-download"] {
		cfg.RawDownload = *rawDownloadFlag
	}
	if overrides["allowed-time-range"] {
		cfg.AllowedTimeRange = strings.TrimSpace(*allowedTimeRangeFlag)
	}
	if overrides["check-interval"] {
		cfg.CheckInterval = *checkIntervalFlag
	}
	if overrides["monitor-mode"] {
		cfg.MonitorMode = *monitorModeFlag
	}
	if overrides["stop-time"] {
		cfg.StopTime = strings.TrimSpace(*stopTimeFlag)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\n下載失敗: %v\n", err)
		os.Exit(1)
	}
}

// formatFileSize 格式化檔案大小顯示
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// ensureSingleInstance 確保只有一個程式實例在執行
// 使用 Windows Mutex 機制，如果檢測到已有實例在執行，會終止舊實例
func ensureSingleInstance() error {
	mutexName, err := syscall.UTF16PtrFromString("Local\\FTPSDownloader_Mutex_Singleton")
	if err != nil {
		return fmt.Errorf("建立 Mutex 名稱失敗: %w", err)
	}

	// 嘗試建立 Mutex
	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(mutexName)),
	)

	if ret == 0 {
		return fmt.Errorf("建立 Mutex 失敗: %w", err)
	}

	// 取得 GetLastError 的值
	lastErr, _, _ := procGetLastError.Call()

	const ERROR_ALREADY_EXISTS = 183

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("【執行實例檢查】")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if lastErr == ERROR_ALREADY_EXISTS {
		log.Printf("⚠️  偵測到已有執行中的下載程式實例")
		log.Printf("正在終止舊的執行實例...")

		// 查找並終止已存在的 ftps-downloader.exe 程式
		if err := killExistingDownloaderProcess(); err != nil {
			log.Printf("❌ 無法終止舊實例: %v", err)
			log.Printf("請手動關閉其他執行中的下載程式後重試")
			return fmt.Errorf("已有程式實例在執行中，且無法自動終止")
		}

		log.Printf("✓ 舊實例已終止，繼續執行新程式")
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Println()

		// 等待一下確保舊程式完全結束
		time.Sleep(2 * time.Second)
	} else {
		log.Printf("✓ 沒有其他執行中的實例，程式正常啟動")
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Println()
	}

	return nil
}

// killExistingDownloaderProcess 查找並終止已存在的 ftps-downloader.exe 程式（排除自己）
func killExistingDownloaderProcess() error {
	// 取得當前程式的 PID
	currentPID := os.Getpid()

	// 使用 tasklist 查找所有名為 ftps-downloader.exe 的程式
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq ftps-downloader.exe", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("執行 tasklist 失敗: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	killedCount := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// CSV 格式: "程式名稱","PID","工作階段名稱","工作階段#","記憶體使用量"
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}

		// 移除引號並取得 PID
		pidStr := strings.Trim(fields[1], "\" ")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// 不要終止自己
		if pid == currentPID {
			continue
		}

		// 終止該程式
		log.Printf("🔫 終止程式 PID: %d", pid)
		killCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid))
		if err := killCmd.Run(); err != nil {
			log.Printf("⚠️  無法終止 PID %d: %v", pid, err)
		} else {
			killedCount++
			log.Printf("✓ 已終止 PID: %d", pid)
		}
	}

	if killedCount == 0 {
		// 雖然 Mutex 顯示有實例，但可能剛好結束了
		log.Printf("ℹ️  未找到需要終止的程式實例")
		return nil
	}

	return nil
}

// cleanOldLogs 清理超過指定天數的舊日誌檔案
func cleanOldLogs(logDir string, keepDays int) error {
	if logDir == "" {
		return nil
	}

	// 檢查目錄是否存在
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		return nil
	}

	now := time.Now()
	cutoffTime := now.AddDate(0, 0, -keepDays)

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("【日誌清理】檢查日誌目錄: %s", logDir)
	log.Printf("保留天數: %d 天 (刪除 %s 之前的日誌)", keepDays, cutoffTime.Format("2006-01-02"))
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		log.Printf("⚠️  無法讀取日誌目錄: %v", err)
		return fmt.Errorf("read log directory: %w", err)
	}

	deletedCount := 0
	var deletedSize int64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// 只處理 .log 檔案
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".log") {
			continue
		}

		filePath := filepath.Join(logDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			log.Printf("⚠️  無法取得檔案資訊: %s (%v)", entry.Name(), err)
			continue
		}

		// 檢查檔案修改時間
		if info.ModTime().Before(cutoffTime) {
			fileSize := info.Size()
			if err := os.Remove(filePath); err != nil {
				log.Printf("⚠️  無法刪除: %s (%v)", entry.Name(), err)
			} else {
				deletedCount++
				deletedSize += fileSize
				log.Printf("🗑️  已刪除: %s (修改時間: %s, 大小: %s)",
					entry.Name(),
					info.ModTime().Format("2006-01-02 15:04:05"),
					formatFileSize(fileSize))
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("✓ 清理完成: 刪除 %d 個舊日誌檔案，釋放空間 %s", deletedCount, formatFileSize(deletedSize))
	} else {
		log.Printf("✓ 無需清理: 沒有超過 %d 天的日誌檔案", keepDays)
	}
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println()

	return nil
}

// checkLocalFlagFile 檢查本地是否存在當天的結帳檔
func checkLocalFlagFile(cfg *Config) bool {
	if cfg.FlagFileName == "" {
		return true // 如果沒設定檔名，視為不需檢查
	}

	flagPath := filepath.Join(cfg.LocalDir, cfg.FlagFileName)
	info, err := os.Stat(flagPath)
	if err != nil {
		return false // 檔案不存在
	}

	// 檢查是否為今天的檔案
	today := time.Now().Format("2006-01-02")
	fileDate := info.ModTime().Format("2006-01-02")

	return today == fileDate
}

// downloadFlagFile 下載結帳檔（DATCLOSE）
func downloadFlagFile(client *ftp.ServerConn, cfg *Config) error {
	if cfg.FlagFilePath == "" || cfg.FlagFileName == "" {
		return nil // 沒有設定專用路徑，不下載
	}

	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("【下載結帳檔】開始下載 DATCLOSE...")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// 構建遠端完整路徑
	var flagPath string
	basePath := strings.TrimSpace(cfg.FlagFilePath)

	if basePath != "" {
		// Guardian 路徑格式處理
		if strings.Contains(basePath, "\\") {
			flagPath = basePath + "." + cfg.FlagFileName
		} else {
			flagPath = basePath + "/" + cfg.FlagFileName
		}
	} else {
		flagPath = cfg.FlagFileName
	}

	log.Printf("🔍 遠端路徑: %s", flagPath)

	// 檢查遠端檔案是否存在
	remoteSize, err := client.FileSize(flagPath)
	if err != nil {
		log.Printf("⚠️  遠端結帳檔不存在或無法讀取: %v", err)
		return fmt.Errorf("remote flag file not found: %w", err)
	}

	log.Printf("✓ 遠端結帳檔存在 (大小: %d bytes)", remoteSize)

	// 下載檔案
	downloaded, err := downloadFile(client, cfg, flagPath, cfg.FlagFileName)
	if err != nil {
		return fmt.Errorf("download flag file: %w", err)
	}

	if downloaded {
		log.Printf("✅ 結帳檔下載成功: %s", cfg.FlagFileName)
	} else {
		log.Printf("ℹ️  結帳檔已存在，跳過下載")
	}

	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// deleteFlagFile 刪除本地的結帳檔
func deleteFlagFile(cfg *Config) {
	if !cfg.AutoDeleteFlagFile || cfg.FlagFileName == "" {
		return
	}

	flagPath := filepath.Join(cfg.LocalDir, cfg.FlagFileName)
	if _, err := os.Stat(flagPath); os.IsNotExist(err) {
		return // 檔案不存在，無需刪除
	}

	if err := os.Remove(flagPath); err != nil {
		log.Printf("⚠️  無法刪除結帳檔 %s: %v", cfg.FlagFileName, err)
	} else {
		log.Printf("🗑️  已刪除結帳檔: %s", cfg.FlagFileName)
	}
}

func run(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	// ========================================
	// 參數驗證
	// ========================================
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("【參數驗證】檢查設定檔參數...")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Port = strings.TrimSpace(cfg.Port)

	// 驗證必要參數
	if cfg.Host == "" {
		return fmt.Errorf("❌ 驗證失敗: host 參數未設定")
	}
	log.Printf("✓ FTP 主機: %s", cfg.Host)

	if cfg.Port == "" {
		cfg.Port = "21"
		log.Printf("ℹ️  FTP 埠號: %s (使用預設值)", cfg.Port)
	} else {
		// 驗證埠號格式
		if port, err := strconv.Atoi(cfg.Port); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("❌ 驗證失敗: port 參數無效 (%s)，必須是 1-65535 之間的數字", cfg.Port)
		}
		log.Printf("✓ FTP 埠號: %s", cfg.Port)
	}

	if cfg.User == "" {
		return fmt.Errorf("❌ 驗證失敗: user 參數未設定")
	}
	log.Printf("✓ FTP 帳號: %s", cfg.User)

	if cfg.Pass == "" {
		return fmt.Errorf("❌ 驗證失敗: pass 參數未設定")
	}
	log.Printf("✓ FTP 密碼: %s", strings.Repeat("*", len(cfg.Pass)))

	// 驗證目錄設定
	if cfg.LocalDir == "" {
		cfg.LocalDir = "./downloads"
		log.Printf("ℹ️  本地目錄: %s (使用預設值)", cfg.LocalDir)
	} else {
		log.Printf("✓ 本地目錄: %s", cfg.LocalDir)
	}

	if cfg.RemoteDir != "" {
		log.Printf("✓ 遠端目錄: %s", cfg.RemoteDir)
	}

	// 驗證監控模式參數
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 30
	}
	if cfg.MonitorMode {
		log.Printf("✓ 監控模式: 已啟用 (間隔: %d 分鐘)", cfg.CheckInterval)

		// 驗證時間範圍格式
		if cfg.AllowedTimeRange != "" {
			if _, err := isWithinTimeRange(cfg.AllowedTimeRange); err != nil {
				return fmt.Errorf("❌ 驗證失敗: allowed_time_range 格式錯誤 (%s)，正確格式: HH:mm-HH:mm", cfg.AllowedTimeRange)
			}
			log.Printf("✓ 時間範圍: %s", cfg.AllowedTimeRange)
		}

		// 驗證停止時間格式
		if cfg.StopTime != "" {
			if _, err := shouldStopMonitor(cfg.StopTime); err != nil {
				return fmt.Errorf("❌ 驗證失敗: stop_time 格式錯誤 (%s)，正確格式: HH:mm", cfg.StopTime)
			}
			log.Printf("✓ 停止時間: %s", cfg.StopTime)
		}
	}

	// 驗證 TLS 設定
	if !cfg.UseTLS {
		log.Printf("✓ 連線模式: 純文字 FTP（無加密）")
	} else if cfg.UseImplicitTLS {
		log.Printf("✓ 連線模式: FTPS Implicit TLS (通常使用 port 990)")
	} else {
		log.Printf("✓ 連線模式: FTPS Explicit TLS")
	}

	if cfg.UseTLS && cfg.InsecureSkipVerify {
		log.Printf("⚠️  SSL 驗證: 已停用 (insecure_skip_verify=true)")
	}

	// 驗證檔案設定
	if len(cfg.FileNames) == 0 {
		log.Printf("ℹ️  下載模式: 下載遠端目錄所有檔案")
	} else {
		log.Printf("✓ 下載模式: 指定檔案清單 (%d 個路徑)", len(cfg.FileNames))
	}

	// 驗證編碼設定
	if cfg.SourceEncoding != "" || cfg.TargetEncoding != "" {
		if cfg.SourceEncoding != "" && cfg.TargetEncoding != "" {
			log.Printf("✓ 編碼轉換: %s → %s", cfg.SourceEncoding, cfg.TargetEncoding)
		} else {
			return fmt.Errorf("❌ 驗證失敗: source_encoding 和 target_encoding 必須同時設定")
		}
	}

	if cfg.RawDownload {
		log.Printf("✓ 下載模式: 原始模式 (不處理任何資料)")
	}

	// 驗證分檔設定
	if len(cfg.SplitFilePrefixes) > 0 {
		log.Printf("✓ 分檔功能: 已啟用 (前綴: %s)", strings.Join(cfg.SplitFilePrefixes, ", "))
	}

	log.Println("✓ 參數驗證通過")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println()

	absLocalDir, err := filepath.Abs(cfg.LocalDir)
	if err != nil {
		return fmt.Errorf("resolve local directory %s: %w", cfg.LocalDir, err)
	}
	cfg.LocalDir = absLocalDir

	if err := os.MkdirAll(cfg.LocalDir, 0755); err != nil {
		return fmt.Errorf("create local directory %s: %w", cfg.LocalDir, err)
	}

	var logWriter io.Writer = io.Discard
	var logFile *os.File
	var logPath string

	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
			log.Printf("Error creating log directory: %v", err)
		} else {
			logFileName := fmt.Sprintf("ftps-downloader-%s.log", time.Now().Format("2006-01-02"))
			logPath = filepath.Join(cfg.LogDir, logFileName)

			// 檢查文件是否是新建的
			fileInfo, _ := os.Stat(logPath)
			isNewFile := fileInfo == nil || fileInfo.Size() == 0

			file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("Error opening log file: %v", err)
			} else {
				// 為新文件寫入 UTF-8 BOM，讓 Windows 記事本能正確識別 UTF-8
				if isNewFile {
					file.Write([]byte{0xEF, 0xBB, 0xBF})
				}
				logFile = file
				logWriter = logFile
			}
		}
	}

	if logWriter == io.Discard && os.Stdout != nil {
		logWriter = os.Stdout
	}

	log.SetOutput(logWriter)
	if logFile != nil {
		defer logFile.Close()
		log.Printf("Logging to %s", logPath)
	}

	// 設置完日誌輸出後，清理超過指定天數的舊日誌（預設 3 天）
	if cfg.LogDir != "" {
		keepDays := cfg.LogRetentionDays
		if keepDays <= 0 {
			keepDays = 3
		}
		if err := cleanOldLogs(cfg.LogDir, keepDays); err != nil {
			log.Printf("⚠️  清理舊日誌時發生錯誤: %v", err)
		}
	}

	// 如果啟用監控模式，進入循環
	if cfg.MonitorMode {
		log.Printf("=== 啟動全天監控模式 ===")
		if cfg.AllowedTimeRange != "" {
			log.Printf("下載時間範圍: %s", cfg.AllowedTimeRange)
		}
		log.Printf("檢查間隔: %d 分鐘", cfg.CheckInterval)
		if cfg.StopTime != "" {
			log.Printf("自動停止時間: %s", cfg.StopTime)
		}
		log.Printf("按 Ctrl+C 停止監控")
		log.Println()

		// 記錄設定檔路徑，用於動態重新讀取
		configPath := flag.Lookup("config")
		var configFile string
		if configPath != nil {
			configFile = configPath.Value.String()
		} else {
			configFile = "config.properties"
		}

		for {
			currentTime := time.Now()
			log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			log.Printf("【監控檢查】時間: %s", currentTime.Format("2006-01-02 15:04:05"))
			log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			// 動態重新讀取設定檔的可變參數（每次循環都重新讀取）
			if tempCfg, err := loadConfig(configFile); err == nil {
				oldStopTime := cfg.StopTime
				oldTimeRange := cfg.AllowedTimeRange
				oldInterval := cfg.CheckInterval

				cfg.StopTime = tempCfg.StopTime
				cfg.AllowedTimeRange = tempCfg.AllowedTimeRange
				if tempCfg.CheckInterval > 0 {
					cfg.CheckInterval = tempCfg.CheckInterval
				}

				// 記錄參數變更
				if oldStopTime != cfg.StopTime {
					log.Printf("🔄 偵測到參數變更: stop_time [%s] → [%s]", oldStopTime, cfg.StopTime)
				}
				if oldTimeRange != cfg.AllowedTimeRange {
					log.Printf("🔄 偵測到參數變更: allowed_time_range [%s] → [%s]", oldTimeRange, cfg.AllowedTimeRange)
				}
				if oldInterval != cfg.CheckInterval {
					log.Printf("🔄 偵測到參數變更: check_interval [%d] → [%d] 分鐘", oldInterval, cfg.CheckInterval)
				}
			}

			// 檢查是否到達停止時間
			if cfg.StopTime != "" {
				should, err := shouldStopMonitor(cfg.StopTime)
				if err != nil {
					log.Printf("❌ 停止時間檢查錯誤: %v", err)
				} else if should {
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					log.Printf("🛑 已到達設定的停止時間 (%s)", cfg.StopTime)
					log.Printf("【作業停止】程式自動關閉")
					log.Printf("=== 監控模式正常結束 ===")
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					return nil
				} else {
					log.Printf("⏰ 停止時間設定: %s (尚未到達)", cfg.StopTime)
				}
			}

			// 檢查是否在允許的時間範圍內
			shouldDownload := true
			if cfg.AllowedTimeRange != "" {
				within, err := isWithinTimeRange(cfg.AllowedTimeRange)
				if err != nil {
					log.Printf("❌ 時間範圍檢查錯誤: %v", err)
					shouldDownload = false
				} else if !within {
					log.Printf("⏰ 下載時間範圍: %s", cfg.AllowedTimeRange)
					log.Printf("⚠️  目前時間不在設定範圍內，跳過本次下載")
					log.Printf("ℹ️  狀態: 監控中 (待機狀態)")
					shouldDownload = false
				} else {
					log.Printf("✓ 下載時間範圍: %s", cfg.AllowedTimeRange)
					log.Printf("✓ 目前時間在允許範圍內，開始執行下載")
				}
			} else {
				log.Printf("ℹ️  無時間範圍限制，可隨時下載")
			}

			// 執行下載或顯示待機狀態
			if shouldDownload {
				log.Println("▼▼▼ 開始下載作業 ▼▼▼")
				if err := runDownload(cfg, logWriter); err != nil {
					log.Printf("❌ 下載錯誤: %v", err)
				} else {
					log.Printf("✓ 下載作業完成")
				}
				log.Println("▲▲▲ 下載作業結束 ▲▲▲")
			} else {
				log.Printf("⏸️  本次循環跳過下載，程式持續監控中")
			}

			// 在休眠前再次檢查停止時間
			if cfg.StopTime != "" {
				should, err := shouldStopMonitor(cfg.StopTime)
				if err == nil && should {
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					log.Printf("🛑 已到達設定的停止時間 (%s)", cfg.StopTime)
					log.Printf("【作業停止】程式自動關閉")
					log.Printf("=== 監控模式正常結束 ===")
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					return nil
				}
			}

			nextCheck := currentTime.Add(time.Duration(cfg.CheckInterval) * time.Minute)
			log.Printf("⏭️  下次檢查時間: %s", nextCheck.Format("2006-01-02 15:04:05"))
			log.Printf("💤 進入休眠 %d 分鐘...\n", cfg.CheckInterval)

			time.Sleep(time.Duration(cfg.CheckInterval) * time.Minute)

			// 休眠後立即檢查停止時間（避免在休眠期間錯過停止時間）
			if cfg.StopTime != "" {
				should, err := shouldStopMonitor(cfg.StopTime)
				if err == nil && should {
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					log.Printf("🛑 休眠結束，已到達設定的停止時間 (%s)", cfg.StopTime)
					log.Printf("【作業停止】程式自動關閉")
					log.Printf("=== 監控模式正常結束 ===")
					log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					return nil
				}
			}
		}
	}

	return runDownload(cfg, logWriter)
}
