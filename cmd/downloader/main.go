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
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
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
	DisableMLSD        bool     // 停用 MLSD，強制使用 LIST（NonStop 建議）
	DebugList          bool     // 顯示 LIST/RawList 遠端清單解析細節
	LogRetentionDays   int      // 日誌保留天數（包含分檔日誌）
	CheckFlagFile      bool     // 是否檢查結帳檔（全局，已棄用）
	FlagFileName       string   // 結帳檔名稱
	FlagFilePath       string   // DATCLOSE 專用下載路徑
	AutoDeleteFlagFile bool     // 程式結束時自動刪除 DATCLOSE
	UseSFTP            bool     // 是否使用 SFTP（SSH File Transfer Protocol）
	SSHKeyPath         string   // SSH 私鑰路徑（留空則使用密碼認證）
	SSHHostKeyCheck    bool     // 是否驗證 SSH 主機金鑰（false = 跳過驗證）
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

func parseConfigBool(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
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
			cfg.UseTLS = parseConfigBool(value)
		case "use_implicit_tls":
			cfg.UseImplicitTLS = parseConfigBool(value)
		case "insecure_skip_verify":
			cfg.InsecureSkipVerify = parseConfigBool(value)
		case "source_encoding":
			cfg.SourceEncoding = value
		case "target_encoding":
			cfg.TargetEncoding = value
		case "debug_encoding":
			cfg.DebugEncoding = parseConfigBool(value)
		case "skip_header_bytes":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.SkipHeaderBytes = n
			}
		case "guardian_add_crlf":
			cfg.GuardianAddCRLF = parseConfigBool(value)
		case "raw_download":
			cfg.RawDownload = parseConfigBool(value)
		case "allowed_time_range":
			cfg.AllowedTimeRange = value
		case "check_interval":
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				cfg.CheckInterval = n
			}
		case "monitor_mode":
			cfg.MonitorMode = parseConfigBool(value)
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
			cfg.SeparateFileLog = parseConfigBool(value)
		case "disable_mlsd":
			cfg.DisableMLSD = parseConfigBool(value)
		case "debug_list":
			cfg.DebugList = parseConfigBool(value)
		case "log_retention_days":
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				cfg.LogRetentionDays = n
			}
		case "check_flag_file":
			cfg.CheckFlagFile = parseConfigBool(value)
		case "flag_file_name":
			cfg.FlagFileName = value
		case "flag_file_path":
			cfg.FlagFilePath = value
		case "auto_delete_flag_file":
			cfg.AutoDeleteFlagFile = parseConfigBool(value)
		case "file_times_dir":
			cfg.FileTimesDir = value
		case "use_sftp":
			cfg.UseSFTP = parseConfigBool(value)
		case "ssh_key_path":
			cfg.SSHKeyPath = value
		case "ssh_host_key_check":
			cfg.SSHHostKeyCheck = parseConfigBool(value)
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

// saveRecordedFileSize 將成功下載的檔案大小儲存以供下次比對
func saveRecordedFileSize(cfg *Config, fileName string, size int64) error {
	if cfg.FileTimesDir == "" {
		return nil
	}
	if err := os.MkdirAll(cfg.FileTimesDir, 0755); err != nil {
		return fmt.Errorf("create file times directory: %w", err)
	}
	sizeFilePath := filepath.Join(cfg.FileTimesDir, fileName+".size")
	if err := os.WriteFile(sizeFilePath, []byte(fmt.Sprintf("%d", size)), 0644); err != nil {
		return fmt.Errorf("write size file %s: %w", sizeFilePath, err)
	}
	log.Printf("📝 已記錄檔案大小: %s -> %d bytes", fileName, size)
	return nil
}

// getRecordedFileSize 讀取之前記錄的檔案大小，找不到時回傳 -1
func getRecordedFileSize(cfg *Config, fileName string) (int64, error) {
	if cfg.FileTimesDir == "" {
		return -1, nil
	}
	sizeFilePath := filepath.Join(cfg.FileTimesDir, fileName+".size")
	data, err := os.ReadFile(sizeFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, nil
		}
		return -1, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return -1, fmt.Errorf("parse size from %s: %w", sizeFilePath, err)
	}
	return size, nil
}

func shouldDownloadExistingFileFromInfo(localSize int64, recordedTime time.Time, recordedSize int64, remoteTime time.Time, remoteSize int64, timeOK, sizeOK bool) (bool, string) {
	if timeOK && !remoteTime.IsZero() {
		remoteTimeText := remoteTime.Local().Format("2006-01-02 15:04:05")
		if recordedTime.IsZero() {
			return true, "無時間記錄，首次下載"
		}

		recordedTimeText := recordedTime.Local().Format("2006-01-02 15:04:05")
		if remoteTime.After(recordedTime) {
			return true, fmt.Sprintf("遠端檔案較新 (記錄: %s, 遠端: %s)", recordedTimeText, remoteTimeText)
		}
		return false, fmt.Sprintf("遠端檔案未更新 (記錄: %s, 遠端: %s)", recordedTimeText, remoteTimeText)
	}

	if sizeOK && remoteSize > 0 {
		if localSize != remoteSize {
			return true, fmt.Sprintf("無法取得遠端時間，檔案大小不同 (本地: %d bytes, 遠端: %d bytes)", localSize, remoteSize)
		}
		return false, fmt.Sprintf("無法取得遠端時間，檔案大小相同 (%d bytes)", remoteSize)
	}

	if recordedSize < 0 {
		return true, "無遠端時間/大小資訊且無大小記錄，首次下載"
	}
	if localSize != recordedSize {
		return true, fmt.Sprintf("無遠端時間/大小資訊，本地大小與記錄不同 (本地: %d bytes, 記錄: %d bytes)", localSize, recordedSize)
	}
	return false, fmt.Sprintf("無遠端時間/大小資訊，本地大小與記錄一致 (%d bytes)", localSize)
}

func remoteFileIsKnownEmpty(remoteSize int64, sizeOK bool) bool {
	return sizeOK && remoteSize == 0
}

func shouldDownloadExistingFile(cfg *Config, localName string, localInfo os.FileInfo, remoteTime time.Time, remoteSize int64, timeOK, sizeOK bool) (bool, string) {
	recordedTime := time.Time{}
	recordedSize := int64(-1)

	if timeOK && !remoteTime.IsZero() {
		var err error
		recordedTime, err = getRecordedFileTime(cfg, localName)
		if err != nil {
			log.Printf("⚠️  讀取記錄時間失敗: %v", err)
		}
	} else if !sizeOK || remoteSize <= 0 {
		var err error
		recordedSize, err = getRecordedFileSize(cfg, localName)
		if err != nil {
			log.Printf("⚠️  讀取記錄大小失敗: %v", err)
		}
	}

	return shouldDownloadExistingFileFromInfo(
		localInfo.Size(),
		recordedTime,
		recordedSize,
		remoteTime,
		remoteSize,
		timeOK,
		sizeOK,
	)
}

// parseRemotePath 解析遠端路徑，回傳 (目錄, 檔名)
func parseRemotePath(remotePath string) (string, string) {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return "", ""
	}

	if looksLikeGuardianPath(remotePath) {
		lastDot := strings.LastIndex(remotePath, ".")
		if lastDot > 0 && lastDot < len(remotePath)-1 {
			return remotePath[:lastDot], remotePath[lastDot+1:]
		}
	}

	remotePath = strings.ReplaceAll(remotePath, "\\", "/")
	dir := path.Dir(remotePath)
	if dir == "." {
		dir = ""
	}
	return dir, path.Base(remotePath)
}

func looksLikeGuardianPath(remotePath string) bool {
	p := strings.TrimSpace(remotePath)
	if p == "" || strings.Contains(p, "/") {
		return false
	}
	return strings.Contains(p, "$") || strings.HasPrefix(p, "\\") || strings.Count(p, ".") >= 2
}

func normalizeRemoteName(name string) string {
	name = strings.TrimSpace(strings.Trim(name, "'\""))
	if idx := strings.Index(name, ";"); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	for _, sep := range []string{".", "/", "\\"} {
		if idx := strings.LastIndex(name, sep); idx >= 0 && idx+1 < len(name) {
			name = strings.TrimSpace(name[idx+1:])
		}
	}
	return strings.ToUpper(name)
}

func remoteNameMatches(entryName, targetName string) bool {
	return normalizeRemoteName(entryName) == normalizeRemoteName(targetName)
}

type remoteFileInfo struct {
	modTime       time.Time
	size          int64
	timeAvailable bool
	sizeAvailable bool
}

type ftpRawLister interface {
	RawList(path string) ([]string, error)
}

func ftpRawList(client *ftp.ServerConn, listPath string) ([]string, error) {
	rawClient, ok := any(client).(ftpRawLister)
	if !ok {
		return nil, fmt.Errorf("RawList not supported by current ftp library version")
	}
	return rawClient.RawList(listPath)
}

func newRemoteFileInfo() remoteFileInfo {
	return remoteFileInfo{size: -1}
}

func (info *remoteFileInfo) merge(other remoteFileInfo) {
	if !info.timeAvailable && other.timeAvailable {
		info.modTime = other.modTime
		info.timeAvailable = true
	}
	if !info.sizeAvailable && other.sizeAvailable {
		info.size = other.size
		info.sizeAvailable = true
	}
}

func getRemoteInfoByMLST(client *ftp.ServerConn, remotePath string) remoteFileInfo {
	info := newRemoteFileInfo()
	entry, err := client.GetEntry(remotePath)
	if err != nil || entry == nil {
		return info
	}

	if !entry.Time.IsZero() {
		info.modTime = entry.Time
		info.timeAvailable = true
	}
	info.size = int64(entry.Size)
	info.sizeAvailable = true

	return info
}

func getRemoteFileInfo(client *ftp.ServerConn, cfg *Config, remotePath string) (time.Time, int64, bool, bool) {
	info := newRemoteFileInfo()

	if size, err := client.FileSize(remotePath); err == nil {
		info.size = size
		info.sizeAvailable = true
	} else if cfg.DebugList {
		log.Printf("  ⚠️  SIZE 失敗 %s: %v", remotePath, err)
	}

	if modTime, err := client.GetTime(remotePath); err == nil {
		info.modTime = modTime
		info.timeAvailable = true
	} else if cfg.DebugList {
		log.Printf("  ⚠️  MDTM 失敗 %s: %v", remotePath, err)
	}

	if !info.timeAvailable || !info.sizeAvailable {
		mlstInfo := getRemoteInfoByMLST(client, remotePath)
		if cfg.DebugList && (mlstInfo.timeAvailable || mlstInfo.sizeAvailable) {
			log.Printf("  ✓ MLST 取得 %s: time=%v size=%d", remotePath, mlstInfo.modTime, mlstInfo.size)
		}
		info.merge(mlstInfo)
	}

	if !info.timeAvailable || !info.sizeAvailable {
		listInfo := getRemoteInfoByList(client, cfg, remotePath)
		info.merge(listInfo)
	}

	return info.modTime, info.size, info.timeAvailable, info.sizeAvailable
}

func getRemoteInfoByList(client *ftp.ServerConn, cfg *Config, remotePath string) remoteFileInfo {
	info := newRemoteFileInfo()
	remoteDir, remoteFileName := parseRemotePath(remotePath)

	for _, listPath := range remoteListTargets(remoteDir, remotePath) {
		if cfg.DebugList {
			log.Printf("  🔎 LIST 查詢: %s (尋找: %s)", listPath, remoteFileName)
		}

		entries, err := client.List(listPath)
		if err == nil {
			for i, entry := range entries {
				if cfg.DebugList {
					log.Printf("     [LIST %d] Name=%s Size=%d Time=%v Type=%s", i, entry.Name, entry.Size, entry.Time, entry.Type)
				}
				if remoteNameMatches(entry.Name, remoteFileName) || (len(entries) == 1 && listPath == remotePath) {
					if !entry.Time.IsZero() {
						info.modTime = entry.Time
						info.timeAvailable = true
					}
					info.size = int64(entry.Size)
					info.sizeAvailable = true
					if info.timeAvailable && info.sizeAvailable {
						return info
					}
				}
			}
		} else if cfg.DebugList {
			log.Printf("  ⚠️  LIST 失敗 %s: %v", listPath, err)
		}

		rawInfo := parseNonStopListOutput(client, listPath, remoteFileName, cfg.DebugList)
		info.merge(rawInfo)
		if info.timeAvailable && info.sizeAvailable {
			return info
		}
	}

	return info
}

func remoteListTargets(remoteDir, remotePath string) []string {
	seen := make(map[string]bool)
	targets := make([]string, 0, 3)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if !seen[value] {
			seen[value] = true
			targets = append(targets, value)
		}
	}

	add(remoteDir)
	add(remotePath)
	if remoteDir == "." {
		add("")
	}
	return targets
}

func configuredRemotePaths(cfg *Config) []string {
	seen := make(map[string]bool)
	paths := make([]string, 0)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			value = "."
		}
		if !seen[value] {
			seen[value] = true
			paths = append(paths, value)
		}
	}

	if len(cfg.FileNames) > 0 {
		for _, mapping := range cfg.FileNames {
			add(mapping.RemotePath)
		}
	} else if strings.TrimSpace(cfg.RemoteDir) != "" {
		add(cfg.RemoteDir)
	} else {
		add(".")
	}

	sort.Strings(paths)
	return paths
}

func initialSnapshotBaseDir(cfg *Config) string {
	if strings.TrimSpace(cfg.FileTimesDir) != "" {
		return cfg.FileTimesDir
	}
	if strings.TrimSpace(cfg.LocalDir) != "" {
		return cfg.LocalDir
	}
	return "."
}

func initialSnapshotMarkerPath(cfg *Config) string {
	return filepath.Join(initialSnapshotBaseDir(cfg), ".initial_remote_listing_done")
}

func shouldCreateInitialSnapshot(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	_, err := os.Stat(initialSnapshotMarkerPath(cfg))
	return os.IsNotExist(err)
}

func writeInitialSnapshot(cfg *Config, title string, pathToFiles map[string][]string, pathErrors map[string]error) (string, error) {
	baseDir := initialSnapshotBaseDir(cfg)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", fmt.Errorf("create snapshot directory: %w", err)
	}

	now := time.Now()
	reportPath := filepath.Join(baseDir, fmt.Sprintf("initial-remote-file-list-%s.txt", now.Format("20060102-150405")))

	var sb strings.Builder
	sb.WriteString(title)
	sb.WriteString("\n")
	sb.WriteString("產生時間: ")
	sb.WriteString(now.Format("2006-01-02 15:04:05"))
	sb.WriteString("\n\n")

	paths := make([]string, 0, len(pathToFiles))
	for p := range pathToFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, remotePath := range paths {
		files := append([]string(nil), pathToFiles[remotePath]...)
		sort.Strings(files)

		sb.WriteString("[remote_path] ")
		sb.WriteString(remotePath)
		sb.WriteString("\n")

		if err, exists := pathErrors[remotePath]; exists && err != nil {
			sb.WriteString("ERROR: ")
			sb.WriteString(err.Error())
			sb.WriteString("\n\n")
			continue
		}

		if len(files) == 0 {
			sb.WriteString("(no files)\n\n")
			continue
		}

		for _, fileName := range files {
			sb.WriteString(fileName)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("write snapshot file: %w", err)
	}

	markerPath := initialSnapshotMarkerPath(cfg)
	markerBody := fmt.Sprintf("created_at=%s\nreport=%s\n", now.Format("2006-01-02 15:04:05"), filepath.Base(reportPath))
	if err := os.WriteFile(markerPath, []byte(markerBody), 0644); err != nil {
		return "", fmt.Errorf("write snapshot marker: %w", err)
	}

	return reportPath, nil
}

func listRemoteFilesFTP(client *ftp.ServerConn, remotePath string) ([]string, error) {
	target := strings.TrimSpace(remotePath)
	if target == "" {
		target = "."
	}

	nameSet := make(map[string]bool)

	entries, listErr := client.List(target)
	if listErr == nil {
		for _, entry := range entries {
			if entry.Type == ftp.EntryTypeFolder {
				continue
			}
			name := strings.TrimSpace(entry.Name)
			if name == "" || name == "." || name == ".." {
				continue
			}
			nameSet[name] = true
		}
	}

	if len(nameSet) == 0 {
		names, nameErr := client.NameList(target)
		if nameErr == nil {
			for _, item := range names {
				item = strings.TrimSpace(item)
				if item == "" || item == "." || item == ".." {
					continue
				}
				item = strings.ReplaceAll(item, "\\", "/")
				item = strings.TrimSpace(path.Base(item))
				if item == "" || item == "." || item == ".." {
					continue
				}
				nameSet[item] = true
			}
		} else if listErr != nil {
			return nil, fmt.Errorf("LIST failed: %w; NLST failed: %v", listErr, nameErr)
		}
	}

	if len(nameSet) == 0 {
		lines, rawErr := ftpRawList(client, target)
		if rawErr == nil {
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				name := strings.TrimSpace(fields[0])
				if name == "" || name == "." || name == ".." {
					continue
				}
				name = strings.ReplaceAll(name, "\\", "/")
				name = strings.TrimSpace(path.Base(name))
				if name == "" || name == "." || name == ".." {
					continue
				}
				nameSet[name] = true
			}
		} else if listErr != nil {
			return nil, fmt.Errorf("LIST failed: %w; RAW LIST failed: %v", listErr, rawErr)
		}
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	if len(names) == 0 && listErr != nil {
		return nil, listErr
	}

	return names, nil
}

func listRemoteFilesSFTP(sftpClient *sftp.Client, remotePath string) ([]string, error) {
	target := strings.TrimSpace(remotePath)
	if target == "" {
		target = "."
	}

	entries, err := sftpClient.ReadDir(target)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" || name == "." || name == ".." {
			continue
		}
		names = append(names, name)
	}

	sort.Strings(names)
	return names, nil
}

func captureInitialRemoteSnapshotFTP(client *ftp.ServerConn, cfg *Config) {
	if !shouldCreateInitialSnapshot(cfg) {
		return
	}

	paths := configuredRemotePaths(cfg)
	if len(paths) == 0 {
		return
	}

	log.Printf("🧭 首次啟動：開始建立遠端檔名清單快照 (FTP)")
	pathToFiles := make(map[string][]string, len(paths))
	pathErrors := make(map[string]error)

	for _, remotePath := range paths {
		files, err := listRemoteFilesFTP(client, remotePath)
		if err != nil {
			pathErrors[remotePath] = err
			pathToFiles[remotePath] = []string{}
			log.Printf("⚠️  首次快照無法列出路徑 %s: %v", remotePath, err)
			continue
		}
		pathToFiles[remotePath] = files
		log.Printf("📝 首次快照路徑 %s: %d 個檔案", remotePath, len(files))
	}

	reportPath, err := writeInitialSnapshot(cfg, "FTPS Downloader 初次啟動遠端檔名清單 (FTP)", pathToFiles, pathErrors)
	if err != nil {
		log.Printf("⚠️  寫入首次快照失敗: %v", err)
		return
	}

	log.Printf("✅ 首次遠端檔名清單已寫入: %s", reportPath)
}

func captureInitialRemoteSnapshotSFTP(sftpClient *sftp.Client, cfg *Config) {
	if !shouldCreateInitialSnapshot(cfg) {
		return
	}

	paths := configuredRemotePaths(cfg)
	if len(paths) == 0 {
		return
	}

	log.Printf("🧭 首次啟動：開始建立遠端檔名清單快照 (SFTP)")
	pathToFiles := make(map[string][]string, len(paths))
	pathErrors := make(map[string]error)

	for _, remotePath := range paths {
		files, err := listRemoteFilesSFTP(sftpClient, remotePath)
		if err != nil {
			pathErrors[remotePath] = err
			pathToFiles[remotePath] = []string{}
			log.Printf("⚠️  首次快照無法列出路徑 %s: %v", remotePath, err)
			continue
		}
		pathToFiles[remotePath] = files
		log.Printf("📝 首次快照路徑 %s: %d 個檔案", remotePath, len(files))
	}

	reportPath, err := writeInitialSnapshot(cfg, "FTPS Downloader 初次啟動遠端檔名清單 (SFTP)", pathToFiles, pathErrors)
	if err != nil {
		log.Printf("⚠️  寫入首次快照失敗: %v", err)
		return
	}

	log.Printf("✅ 首次遠端檔名清單已寫入: %s", reportPath)
}

// parseNonStopListOutput 透過原始 LIST 輸出解析 NonStop/Guardian 檔案時間與大小。
func parseNonStopListOutput(client *ftp.ServerConn, listPath, remoteFileName string, debug bool) remoteFileInfo {
	info := newRemoteFileInfo()
	lines, err := ftpRawList(client, listPath)
	if err != nil {
		if debug {
			log.Printf("  ⚠️  Raw LIST 失敗 %s: %v", listPath, err)
		}
		return info
	}

	for i, line := range lines {
		if debug {
			log.Printf("     [RAW %d] %s", i, line)
		}
		parsed, ok := parseNonStopListLine(line, remoteFileName)
		if !ok {
			continue
		}
		return parsed
	}

	return info
}

func parseNonStopListLine(line, remoteFileName string) (remoteFileInfo, bool) {
	info := newRemoteFileInfo()
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return info, false
	}

	nameIdx := -1
	for i, field := range fields {
		if remoteNameMatches(field, remoteFileName) {
			nameIdx = i
			break
		}
	}
	if nameIdx < 0 {
		return info, false
	}

	for dateIdx := 0; dateIdx < len(fields)-1; dateIdx++ {
		parsedTime, ok := parseListDateTime(fields[dateIdx], fields[dateIdx+1])
		if !ok {
			continue
		}

		info.modTime = parsedTime
		info.timeAvailable = true
		if size, ok := parseLastInteger(fields, nameIdx+1, dateIdx); ok {
			info.size = size
			info.sizeAvailable = true
		} else if size, ok := parseLastInteger(fields, 0, dateIdx); ok {
			info.size = size
			info.sizeAvailable = true
		}
		return info, true
	}

	return info, false
}

func parseLastInteger(fields []string, start, end int) (int64, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	for i := end - 1; i >= start; i-- {
		value := strings.Trim(fields[i], ",;")
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return n, true
		}
	}
	return -1, false
}

func parseListDateTime(dateField, timeField string) (time.Time, bool) {
	dateTime := strings.Trim(dateField, ",;") + " " + strings.Trim(timeField, ",;")
	layouts := []string{
		"_2-Jan-06 15:04:05",
		"_2-Jan-2006 15:04:05",
		"02-Jan-06 15:04:05",
		"02-Jan-2006 15:04:05",
		"_2-Jan-06 15:04",
		"_2-Jan-2006 15:04",
		"02-Jan-06 15:04",
		"02-Jan-2006 15:04",
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, dateTime, time.Local); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func formatLogSize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "byte") || strings.Contains(value, "無法") {
		return value
	}
	return value + " bytes"
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
		fmt.Fprintf(f, "遠端檔案大小: %s\n", formatLogSize(remoteSize))
	}
	if localTimeBefore, ok := info["local_time_before"]; ok {
		fmt.Fprintf(f, "本地檔案時間(下載前): %s\n", localTimeBefore)
	}
	if localSizeBefore, ok := info["local_size_before"]; ok {
		fmt.Fprintf(f, "本地檔案大小(下載前): %s\n", formatLogSize(localSizeBefore))
	}
	if downloaded, ok := info["downloaded_bytes"]; ok {
		fmt.Fprintf(f, "下載位元組數: %s\n", formatLogSize(downloaded))
	}
	if finalSize, ok := info["final_size"]; ok {
		fmt.Fprintf(f, "最終檔案大小: %s\n", formatLogSize(finalSize))
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
	remoteTime, remoteSize, timeOK, sizeOK := getRemoteFileInfo(client, cfg, remotePath)
	if sizeOK {
		logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
		log.Printf("  📊 遠端檔案大小: %d bytes", remoteSize)
	} else {
		logInfo["remote_size"] = "無法取得"
		log.Printf("WARNING: 無法取得遠端檔案大小: %s", remotePath)
	}
	if timeOK {
		logInfo["remote_time"] = remoteTime.Local().Format("2006-01-02 15:04:05")
		log.Printf("  🕒 遠端檔案時間: %s", remoteTime.Local().Format("2006-01-02 15:04:05"))
	} else {
		logInfo["remote_time"] = "無法取得"
		log.Printf("WARNING: 無法取得遠端檔案時間: %s", remotePath)
	}
	if remoteFileIsKnownEmpty(remoteSize, sizeOK) {
		log.Printf("  ⊘ 跳過下載 %s：遠端檔案大小為 0 bytes，不進行下載", localName)
		logInfo["status"] = "skipped"
		logInfo["reason"] = "遠端檔案大小為 0 bytes，跳過下載"
		if err := writeFileLog(cfg, localName, logInfo); err != nil {
			log.Printf("Warning: Failed to write file log for %s: %v", localName, err)
		}
		return false, nil
	}

	// 檢查本地檔案是否存在
	var downloadReason string
	if localInfo, err := os.Stat(localPath); err == nil {
		// 記錄本地檔案的原始狀態
		logInfo["local_time_before"] = localInfo.ModTime().Format("2006-01-02 15:04:05")
		logInfo["local_size_before"] = fmt.Sprintf("%d", localInfo.Size())

		needDownload, downloadReason := shouldDownloadExistingFile(cfg, localName, localInfo, remoteTime, remoteSize, timeOK, sizeOK)
		if needDownload {
			log.Printf("🔄 需要下載 %s：%s", localName, downloadReason)
		} else {
			log.Printf("✓ 跳過 %s：%s", localName, downloadReason)
		}

		// 如果檔案相同，跳過下載
		if !needDownload {
			if remoteSize > 0 {
				log.Printf("⏭️  跳過下載: %s (本地已是最新，大小: %d bytes)", localName, localInfo.Size())
			} else {
				log.Printf("⏭️  跳過下載: %s (本地已存在)", localName)
			}
			logInfo["status"] = "跳過下載"
			logInfo["reason"] = downloadReason
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

	if rawBytesRead == 0 {
		log.Printf("  ⊘ 跳過下載 %s：遠端檔案大小為 0 bytes（實際下載長度）", localName)
		logInfo["status"] = "skipped"
		logInfo["reason"] = "遠端檔案大小為 0 bytes，跳過下載"
		if err := writeFileLog(cfg, localName, logInfo); err != nil {
			log.Printf("Warning: Failed to write file log for %s: %v", localName, err)
		}
		return false, nil
	}

	if remoteSize > 0 && rawBytesRead != remoteSize {
		log.Printf("⚠️  遠端宣告大小與實際下載位元組不同，繼續寫入: %s (遠端宣告: %d bytes, 實際下載: %d bytes)", remotePath, remoteSize, rawBytesRead)
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

	// 記錄實際下載大小（對于遠端大小無法取得時，下次作為比對基準）
	if err := saveRecordedFileSize(cfg, localName, rawBytesRead); err != nil {
		log.Printf("⚠️  Warning: 無法記錄檔案大小 %s: %v", localName, err)
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
	if remoteSize > 0 {
		log.Printf("  📊 遠端大小: %d bytes", remoteSize)
	} else {
		log.Printf("  📊 遠端大小: 無法取得")
	}
	log.Printf("  📊 下載大小: %d bytes", rawBytesRead)
	log.Printf("  📊 寫入大小: %d bytes", writtenInfo.Size())
	log.Printf("  Local time: %s", writtenInfo.ModTime().Format("2006-01-02 15:04:05"))

	// 同步小小小大小信息到 file log
	if remoteSize > 0 {
		logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
	} else {
		logInfo["remote_size"] = "無法取得"
	}

	if cfg.RawDownload {
		if writtenInfo.Size() != rawBytesRead {
			return false, fmt.Errorf("verification failed for %s: written size (%d) != downloaded size (%d)", localPath, writtenInfo.Size(), rawBytesRead)
		}
		log.Printf("✓ Verification passed: written file matches downloaded bytes")
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

// ─────────────────────────────────────────────────────────────────────────────
// SFTP 支援
// ─────────────────────────────────────────────────────────────────────────────

// newSSHClient 建立 SSH 連線，支援密碼與私鑰兩種認證方式
func newSSHClient(cfg *Config) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if cfg.SSHKeyPath != "" {
		keyData, err := os.ReadFile(cfg.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("讀取 SSH 私鑰失敗 %s: %w", cfg.SSHKeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私鑰失敗: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
		log.Printf("🔑 使用 SSH 私鑰認證: %s", cfg.SSHKeyPath)
	} else {
		authMethods = append(authMethods, ssh.Password(cfg.Pass))
		log.Printf("🔑 使用密碼認證")
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if cfg.SSHHostKeyCheck {
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// 只記錄金鑰指紋，實際驗證由呼叫端決定
			log.Printf("🔐 主機金鑰指紋: %s", ssh.FingerprintSHA256(key))
			return nil
		}
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	port := cfg.Port
	if port == "" || port == "21" {
		port = "22" // SFTP 預設 port
	}
	addr := fmt.Sprintf("%s:%s", cfg.Host, port)
	log.Printf("SFTP 連線至 %s ...", addr)

	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH 連線失敗: %w", err)
	}
	return client, nil
}

// downloadFileSFTP 使用 SFTP 下載單一檔案，邏輯與 downloadFile 一致
func downloadFileSFTP(sftpClient *sftp.Client, cfg *Config, remotePath, localName string) (bool, error) {
	localPath := filepath.Join(cfg.LocalDir, localName)
	logInfo := make(map[string]string)

	// 取得遠端檔案資訊
	remoteInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", remotePath, err)
	}
	remoteSize := remoteInfo.Size()
	remoteTime := remoteInfo.ModTime()
	logInfo["remote_size"] = fmt.Sprintf("%d", remoteSize)
	logInfo["remote_time"] = remoteTime.Local().Format("2006-01-02 15:04:05")
	log.Printf("  📊 遠端檔案大小: %d bytes", remoteSize)
	log.Printf("  🕒 遠端修改時間: %s", remoteTime.Local().Format("2006-01-02 15:04:05"))

	// 大小為 0 → 跳過
	if remoteFileIsKnownEmpty(remoteSize, true) {
		log.Printf("  ⊘ 跳過下載 %s：遠端檔案大小為 0 bytes，不進行下載", localName)
		logInfo["status"] = "skipped"
		logInfo["reason"] = "遠端檔案大小為 0 bytes，跳過下載"
		writeFileLog(cfg, localName, logInfo)
		return false, nil
	}

	// 比對本地檔案
	var downloadReason string
	if localInfo, err := os.Stat(localPath); err == nil {
		logInfo["local_time_before"] = localInfo.ModTime().Format("2006-01-02 15:04:05")
		logInfo["local_size_before"] = fmt.Sprintf("%d", localInfo.Size())

		needDownload, downloadReason := shouldDownloadExistingFile(cfg, localName, localInfo, remoteTime, remoteSize, true, true)
		if needDownload {
			log.Printf("🔄 需要下載 %s：%s", localName, downloadReason)
		} else {
			log.Printf("✓ 跳過 %s：%s", localName, downloadReason)
		}

		if !needDownload {
			log.Printf("⏭️  跳過下載: %s (本地檔案已是最新，大小: %d bytes)", localName, localInfo.Size())
			logInfo["status"] = "跳過下載"
			logInfo["reason"] = downloadReason
			writeFileLog(cfg, localName, logInfo)
			return false, nil
		}
		log.Printf("🔄 更新檔案: %s (遠端大小: %d bytes)", localName, remoteSize)
	} else {
		downloadReason = "本地檔案不存在"
		log.Printf("📥 下載新檔案: %s (遠端大小: %d bytes)", localName, remoteSize)
	}
	logInfo["reason"] = downloadReason

	// 開啟遠端檔案
	f, err := sftpClient.Open(remotePath)
	if err != nil {
		return false, fmt.Errorf("開啟遠端檔案 %s: %w", remotePath, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	rawBytesRead, err := io.Copy(&buf, f)
	if err != nil {
		return false, fmt.Errorf("讀取 %s: %w", remotePath, err)
	}
	if rawBytesRead == 0 {
		log.Printf("  ⊘ 跳過下載 %s：遠端檔案大小為 0 bytes（實際下載長度）", localName)
		logInfo["status"] = "skipped"
		logInfo["reason"] = "遠端檔案大小為 0 bytes，跳過下載"
		if err := writeFileLog(cfg, localName, logInfo); err != nil {
			log.Printf("⚠️  Warning: 無法寫入 file log %s: %v", localName, err)
		}
		return false, nil
	}
	if rawBytesRead != remoteSize {
		log.Printf("⚠️  遠端宣告大小與實際下載位元組不同，繼續寫入: %s (遠端宣告: %d bytes, 實際下載: %d bytes)", remotePath, remoteSize, rawBytesRead)
	}

	rawData := buf.Bytes()
	processed := processData(cfg, remotePath, rawData)

	if err := os.WriteFile(localPath, processed, 0644); err != nil {
		return false, fmt.Errorf("寫入 %s: %w", localPath, err)
	}

	logInfo["downloaded_bytes"] = fmt.Sprintf("%d", rawBytesRead)

	localNow := time.Now()
	if err := os.Chtimes(localPath, localNow, localNow); err != nil {
		log.Printf("⚠️  Warning: 無法設定檔案時間 %s: %v", localPath, err)
	}
	if !remoteTime.IsZero() {
		if err := saveRecordedFileTime(cfg, localName, remoteTime); err != nil {
			log.Printf("⚠️  Warning: 無法記錄遠端時間 %s: %v", localName, err)
		}
	}

	writtenInfo, err := os.Stat(localPath)
	if err != nil {
		return false, fmt.Errorf("驗證寫入檔案 %s: %w", localPath, err)
	}
	logInfo["final_size"] = fmt.Sprintf("%d", writtenInfo.Size())
	logInfo["local_time_after"] = writtenInfo.ModTime().Format("2006-01-02 15:04:05")
	logInfo["status"] = "下載成功"

	log.Printf("✓ 已下載 %s → %s", remotePath, localPath)
	log.Printf("  遠端大小: %d bytes, 下載: %d bytes, 最終: %d bytes", remoteSize, rawBytesRead, writtenInfo.Size())

	if err := writeFileLog(cfg, localName, logInfo); err != nil {
		log.Printf("⚠️  Warning: 無法寫入 file log %s: %v", localName, err)
	}
	return true, nil
}

// runDownloadSFTP 使用 SFTP 協定執行下載流程
func runDownloadSFTP(cfg *Config, logWriter io.Writer) error {
	sshClient, err := newSSHClient(cfg)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("建立 SFTP 客戶端失敗: %w", err)
	}
	defer sftpClient.Close()
	log.Println("✓ SFTP 連線成功")

	captureInitialRemoteSnapshotSFTP(sftpClient, cfg)

	downloadCount := 0

	if len(cfg.FileNames) > 0 {
		for _, mapping := range cfg.FileNames {
			basePath := strings.TrimSpace(mapping.RemotePath)

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
			}

			if mapping.CheckFlagFile && mapping.FlagFileName != "" {
				if !checkLocalFlagFile(cfg) {
					log.Printf("⏭️  跳過目錄 %s：本地結帳檔 %s 不存在或不是當天的檔案", basePath, mapping.FlagFileName)
					continue
				}
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
				remotePath := basePath + "/" + remoteFileName
				if basePath == "" {
					remotePath = remoteFileName
				}

				downloaded, err := downloadFileSFTP(sftpClient, cfg, remotePath, localFileName)
				if err != nil {
					log.Printf("Error downloading %s: %v", remotePath, err)
					continue
				}
				if downloaded {
					downloadCount++
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
		// 未指定檔案清單 → 下載遠端目錄下所有檔案
		remoteDir := cfg.RemoteDir
		if remoteDir == "" {
			remoteDir = "."
		}
		entries, err := sftpClient.ReadDir(remoteDir)
		if err != nil {
			return fmt.Errorf("列出遠端目錄 %s: %w", remoteDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			remotePath := remoteDir + "/" + entry.Name()
			downloaded, err := downloadFileSFTP(sftpClient, cfg, remotePath, entry.Name())
			if err != nil {
				log.Printf("Error downloading %s: %v", remotePath, err)
				continue
			}
			if downloaded {
				downloadCount++
				if len(cfg.SplitFilePrefixes) > 0 {
					localPath := filepath.Join(cfg.LocalDir, entry.Name())
					if err := splitFileByPrefix(localPath, cfg.SplitFilePrefixes); err != nil {
						log.Printf("⚠️  分檔處理失敗 %s: %v", entry.Name(), err)
					}
				}
			}
		}
	}

	log.Printf("下載完成，共 %d 個檔案。", downloadCount)
	deleteFlagFile(cfg)
	return nil
}

func runDownload(cfg *Config, logWriter io.Writer) error {
	// ===== 啟動協議確認 =====
	switch {
	case cfg.UseSFTP:
		log.Printf("🔌 通訊協議: SFTP (SSH File Transfer Protocol)")
		if cfg.SSHKeyPath != "" {
			log.Printf("   認證方式: SSH 私鑰 (%s)", cfg.SSHKeyPath)
		} else {
			log.Printf("   認證方式: 密碼")
		}
	case cfg.UseTLS && cfg.UseImplicitTLS:
		log.Printf("🔒 通訊協議: FTPS - Implicit TLS (全程加密，Port 通常為 990)")
	case cfg.UseTLS && !cfg.UseImplicitTLS:
		log.Printf("🔒 通訊協議: FTPS - Explicit TLS (STARTTLS，Port 通常為 21)")
	default:
		log.Printf("⚠️  通訊協議: FTP (純文字，無加密)")
	}
	log.Printf("   伺服器: %s:%s  使用者: %s", cfg.Host, cfg.Port, cfg.User)
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if cfg.UseSFTP {
		return runDownloadSFTP(cfg, logWriter)
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("Connecting to %s ...", addr)

	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(10 * time.Second),
		ftp.DialWithDisabledMLSD(cfg.DisableMLSD),
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

	captureInitialRemoteSnapshotFTP(client, cfg)

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
	// Step 1: 先解析 flags，才能決定正確的 log 目錄
	// ---------------------------------------------------------------
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

	// ---------------------------------------------------------------
	// Step 2: 決定設定檔路徑（優先用 exe 所在目錄的 config.properties）
	// ---------------------------------------------------------------
	exePath, exeErr := os.Executable()
	if *configPath == "" {
		resolvedConfig := "config.properties"
		if exeErr == nil {
			candidate := filepath.Join(filepath.Dir(exePath), "config.properties")
			if _, err := os.Stat(candidate); err == nil {
				resolvedConfig = candidate
			}
		}
		*configPath = resolvedConfig
	}

	// ---------------------------------------------------------------
	// Step 3: 決定早期 log 目錄
	//   優先順序：-log-dir flag > config 裡的 log_dir > <exe>\logs\
	// ---------------------------------------------------------------
	earlyLogDir := strings.TrimSpace(*logDirFlag)
	if earlyLogDir == "" {
		earlyLogDir = quickScanLogDir(*configPath)
		if earlyLogDir != "" && !filepath.IsAbs(earlyLogDir) {
			earlyLogDir = filepath.Clean(filepath.Join(filepath.Dir(*configPath), earlyLogDir))
		}
	}
	if earlyLogDir == "" && exeErr == nil {
		earlyLogDir = filepath.Join(filepath.Dir(exePath), "logs")
	}

	// ---------------------------------------------------------------
	// Step 4: 建立 log 檔（所有 log 都寫到正確的 log 目錄）
	// ---------------------------------------------------------------
	today := time.Now().Format("2006-01-02")
	var logWriters []io.Writer

	if earlyLogDir != "" {
		_ = os.MkdirAll(earlyLogDir, 0755)
		mainLogPath := filepath.Join(earlyLogDir, "ftps-downloader-"+today+".log")
		if f, err := os.OpenFile(mainLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			if info, _ := f.Stat(); info != nil && info.Size() <= 3 {
				_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})
			}
			defer f.Close()
			logWriters = append(logWriters, f)
		}

		// ftps_out-YYYY-MM-DD.log：stdout 輸出（對應 Task Scheduler 的 ftps_out.log）
		outLogPath := filepath.Join(earlyLogDir, "ftps_out-"+today+".log")
		if outF, err := os.OpenFile(outLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			defer outF.Close()
			logWriters = append(logWriters, outF)
		}

		// ftps_err-YYYY-MM-DD.log：stderr 重導向（對應 Task Scheduler 的 ftps_err.log）
		errLogPath := filepath.Join(earlyLogDir, "ftps_err-"+today+".log")
		if errF, err := os.OpenFile(errLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			defer errF.Close()
			os.Stderr = errF
		}

		emergencyPath := filepath.Join(earlyLogDir, "ftps-downloader-startup-"+today+".log")
		if ef, err := os.OpenFile(emergencyPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			defer ef.Close()
			fmt.Fprintf(ef, "\n--- %s ---\n", time.Now().Format("2006-01-02 15:04:05"))
			if exeErr == nil {
				fmt.Fprintf(ef, "exe: %s\n", exePath)
			}
			fmt.Fprintf(ef, "config: %s\n", *configPath)
			fmt.Fprintf(ef, "log dir: %s\n", earlyLogDir)
			logWriters = append(logWriters, ef)
		}
	}

	logWriters = append(logWriters, os.Stdout)

	log.SetOutput(io.MultiWriter(logWriters...))

	if exeErr != nil {
		log.Printf("⚠️  無法取得 exe 路徑: %v，日誌僅輸出至 stdout", exeErr)
	}

	log.Printf("========================================")
	log.Printf("FTPS Downloader started")
	log.Printf("========================================")
	log.Println()
	log.Printf("設定檔: %s", *configPath)
	log.Printf("日誌目錄: %s", earlyLogDir)

	// 確保單一執行實例（終止舊實例）
	if err := ensureSingleInstance(); err != nil {
		log.Printf("❌ 執行實例檢查失敗: %v", err)
		os.Exit(1)
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

// quickScanLogDir 從設定檔快速讀取 log_dir，不做完整解析
func quickScanLogDir(configPath string) string {
	f, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "log_dir=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "log_dir="))
		}
	}
	return ""
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

	var logFile *os.File
	var logPath string
	var logWriters []io.Writer

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
				logWriters = append(logWriters, logFile)
			}
		}
	}

	logWriters = append(logWriters, os.Stdout)

	logWriter := io.MultiWriter(logWriters...)
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
