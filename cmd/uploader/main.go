package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jlaffaye/ftp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex  = kernel32.NewProc("CreateMutexW")
	procGetLastError = kernel32.NewProc("GetLastError")
)

type PathMapping struct {
	LocalPath       string
	Files           []string
	FilePatterns    []string          // 支援萬用字元，例如: *.txt, TCD*, RYM??
	IncludePrefixes []string          // 只上傳符合前綴的檔案
	IncludeSuffixes []string          // 只上傳符合後綴的檔案
	ExcludeFiles    []string          // 排除的檔案名稱
	PrefixRename    map[string]string // 批次前綴重命名: {"TCD": "DATA"}
	SuffixRename    map[string]string // 批次後綴重命名: {".txt": ".dat"}
}

type Config struct {
	Host               string
	Port               string
	User               string
	Pass               string
	RemoteDir          string
	LocalDir           string
	LogDir             string
	FileNames          []PathMapping
	UseTLS             bool
	UseImplicitTLS     bool
	InsecureSkipVerify bool
	AllowedTimeRange   string // 格式: "HH:mm-HH:mm", 例如 "02:00-05:00"
	CheckInterval      int    // 檢查間隔(分鐘)，預設 30 分鐘
	MonitorMode        bool   // 是否啟用全天監控模式
	StopTime           string // 自動停止時間，格式: "HH:mm", 例如 "18:00"
	UseSFTP            bool   // 是否使用 SFTP（SSH File Transfer Protocol）
	SSHKeyPath         string // SSH 私鑰路徑（留空則使用密碼認證）
	SSHHostKeyCheck    bool   // 是否驗證 SSH 主機金鑰（false = 跳過驗證）
}

// cleanupOldLogs 清理超過指定天數的日誌檔案
func cleanupOldLogs(logDir string, retentionDays int) {
	if logDir == "" {
		return
	}

	// 確保日誌目錄存在
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		return
	}

	now := time.Now()
	cutoffTime := now.AddDate(0, 0, -retentionDays)

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("【日誌清理】檢查日誌目錄: %s", logDir)
	log.Printf("保留天數: %d 天 (刪除 %s 之前的日誌)", retentionDays, cutoffTime.Format("2006-01-02"))
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		log.Printf("⚠️  無法讀取日誌目錄: %v", err)
		return
	}

	deletedCount := 0
	var deletedSize int64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		// 只處理 .log 檔案
		if !strings.HasSuffix(strings.ToLower(fileName), ".log") {
			continue
		}

		filePath := filepath.Join(logDir, fileName)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// 檢查檔案修改時間
		if info.ModTime().Before(cutoffTime) {
			fileSize := info.Size()
			if err := os.Remove(filePath); err != nil {
				log.Printf("⚠️  無法刪除: %s (%v)", fileName, err)
			} else {
				deletedCount++
				deletedSize += fileSize
				log.Printf("🗑️  已刪除: %s (修改時間: %s, 大小: %s)",
					fileName,
					info.ModTime().Format("2006-01-02 15:04:05"),
					formatFileSize(fileSize))
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("✓ 清理完成: 刪除 %d 個舊日誌檔案，釋放空間 %s", deletedCount, formatFileSize(deletedSize))
	} else {
		log.Printf("✓ 無需清理: 沒有超過 %d 天的日誌檔案", retentionDays)
	}
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println()
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

func parseConfigBool(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// ensureSingleInstance 確保只有一個程式實例在執行
// 使用 Windows Mutex 機制，如果檢測到已有實例在執行，會終止舊實例
func ensureSingleInstance() error {
	mutexName, err := syscall.UTF16PtrFromString("Global\\FTPSUploader_Mutex_Singleton")
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
		log.Printf("⚠️  偵測到已有執行中的上傳程式實例")
		log.Printf("正在終止舊的執行實例...")

		// 查找並終止已存在的 ftps-uploader.exe 程式
		if err := killExistingProcess(); err != nil {
			log.Printf("❌ 無法終止舊實例: %v", err)
			log.Printf("請手動關閉其他執行中的上傳程式後重試")
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

// killExistingProcess 查找並終止已存在的 ftps-uploader.exe 程式（排除自己）
func killExistingProcess() error {
	// 取得當前程式的 PID
	currentPID := os.Getpid()

	// 使用 tasklist 查找所有名為 ftps-uploader.exe 的程式
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq ftps-uploader.exe", "/FO", "CSV", "/NH")
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
		// 範例: "ftps-uploader.exe","12345","Console","1","10,240 K"
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

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{
		UseTLS:   true,
		Port:     "21",
		LocalDir: "./uploads",
	}

	scanner := bufio.NewScanner(file)
	pathMappings := make(map[int]*PathMapping)
	fileItems := make(map[string]string)
	patternItems := make(map[string]string)
	prefixItems := make(map[string]string)
	suffixItems := make(map[string]string)
	excludeItems := make(map[string]string)

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

					if tokens[2] == "local_path" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{
								Files:           make([]string, 0),
								FilePatterns:    make([]string, 0),
								IncludePrefixes: make([]string, 0),
								IncludeSuffixes: make([]string, 0),
								ExcludeFiles:    make([]string, 0),
							}
						}
						pathMappings[pathIdx].LocalPath = value
					} else if tokens[2] == "files" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						fileItems[mapKey] = value
					} else if tokens[2] == "patterns" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						patternItems[mapKey] = value
					} else if tokens[2] == "include_prefixes" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						prefixItems[mapKey] = value
					} else if tokens[2] == "include_suffixes" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						suffixItems[mapKey] = value
					} else if tokens[2] == "exclude_files" && len(tokens) >= 4 {
						fileIdx, _ := strconv.Atoi(tokens[3])
						mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
						excludeItems[mapKey] = value
					} else if tokens[2] == "rename_prefix" && len(tokens) >= 4 {
						pathIdx, _ := strconv.Atoi(tokens[1])
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{
								Files:           make([]string, 0),
								FilePatterns:    make([]string, 0),
								IncludePrefixes: make([]string, 0),
								IncludeSuffixes: make([]string, 0),
								ExcludeFiles:    make([]string, 0),
								PrefixRename:    make(map[string]string),
								SuffixRename:    make(map[string]string),
							}
						}
						if pathMappings[pathIdx].PrefixRename == nil {
							pathMappings[pathIdx].PrefixRename = make(map[string]string)
						}
						// 格式: TCD:DATA (舊前綴:新前綴)
						parts := strings.SplitN(value, ":", 2)
						if len(parts) == 2 {
							oldPrefix := strings.TrimSpace(parts[0])
							newPrefix := strings.TrimSpace(parts[1])
							if oldPrefix != "" {
								pathMappings[pathIdx].PrefixRename[oldPrefix] = newPrefix
							}
						}
					} else if tokens[2] == "rename_suffix" && len(tokens) >= 4 {
						pathIdx, _ := strconv.Atoi(tokens[1])
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{
								Files:           make([]string, 0),
								FilePatterns:    make([]string, 0),
								IncludePrefixes: make([]string, 0),
								IncludeSuffixes: make([]string, 0),
								ExcludeFiles:    make([]string, 0),
								PrefixRename:    make(map[string]string),
								SuffixRename:    make(map[string]string),
							}
						}
						if pathMappings[pathIdx].SuffixRename == nil {
							pathMappings[pathIdx].SuffixRename = make(map[string]string)
						}
						// 格式: .txt:.dat (舊後綴:新後綴)
						parts := strings.SplitN(value, ":", 2)
						if len(parts) == 2 {
							oldSuffix := strings.TrimSpace(parts[0])
							newSuffix := strings.TrimSpace(parts[1])
							if oldSuffix != "" {
								pathMappings[pathIdx].SuffixRename[oldSuffix] = newSuffix
							}
						}
					}
				}
			}
		}
	}

	// Assemble path mappings
	for i := 0; i < 100; i++ {
		if mapping, ok := pathMappings[i]; ok {
			for j := 0; j < 100; j++ {
				mapKey := fmt.Sprintf("%d.%d", i, j)
				if fileName, ok := fileItems[mapKey]; ok {
					mapping.Files = append(mapping.Files, fileName)
				}
				if pattern, ok := patternItems[mapKey]; ok {
					mapping.FilePatterns = append(mapping.FilePatterns, pattern)
				}
				if prefix, ok := prefixItems[mapKey]; ok {
					mapping.IncludePrefixes = append(mapping.IncludePrefixes, prefix)
				}
				if suffix, ok := suffixItems[mapKey]; ok {
					mapping.IncludeSuffixes = append(mapping.IncludeSuffixes, suffix)
				}
				if exclude, ok := excludeItems[mapKey]; ok {
					mapping.ExcludeFiles = append(mapping.ExcludeFiles, exclude)
				}
			}
			cfg.FileNames = append(cfg.FileNames, *mapping)
		}
	}

	return cfg, nil
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

	parseTime := func(tStr string) (time.Time, error) {
		tStr = strings.TrimSpace(tStr)
		if tStr == "24:00" {
			t, err := time.ParseInLocation("2006-01-02 15:04", today+" 00:00", time.Local)
			if err != nil {
				return t, err
			}
			return t.Add(24 * time.Hour), nil
		}
		return time.ParseInLocation("2006-01-02 15:04", today+" "+tStr, time.Local)
	}

	start, err := parseTime(parts[0])
	if err != nil {
		return false, err
	}

	end, err := parseTime(parts[1])
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
	return now.After(stopTime) || now.Equal(stopTime), nil
}

func getUploadStatus(localPath string) string {
	statusPath := localPath + ".status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "" // No mark
	}
	return strings.TrimSpace(string(data))
}

func setUploadStatus(localPath, status string) {
	statusPath := localPath + ".status"
	_ = os.WriteFile(statusPath, []byte(status), 0644)
}

func uploadFile(client *ftp.ServerConn, localPath, remoteName string) (bool, error) {
	localFile, err := os.Open(localPath)
	if err != nil {
		return false, fmt.Errorf("open local file: %w", err)
	}
	defer localFile.Close()

	localStat, err := localFile.Stat()
	if err != nil {
		return false, fmt.Errorf("stat local file: %w", err)
	}

	// Check local status file
	status := getUploadStatus(localPath)
	statusPath := localPath + ".status"

	if status == "Y" {
		// 檢查本地檔案是否在狀態標記之後被修改過
		if statusInfo, err := os.Stat(statusPath); err == nil {
			if localStat.ModTime().After(statusInfo.ModTime()) {
				log.Printf("🔄 檔案已變更: %s (本地: %s, 狀態: %s)",
					filepath.Base(localPath),
					localStat.ModTime().Format("2006-01-02 15:04:05"),
					statusInfo.ModTime().Format("2006-01-02 15:04:05"))
				log.Printf("   本地檔案較新，需要重新上傳")
			} else {
				log.Printf("⏭️  跳過上傳: %s (已上傳且未變更)", filepath.Base(localPath))
				return false, nil
			}
		}
	}

	// Check if remote file exists and its modification time
	remoteTime, err := client.GetTime(remoteName)
	if err == nil {
		if !localStat.ModTime().After(remoteTime) {
			log.Printf("⏭️  跳過上傳: %s (遠端檔案已是最新)", remoteName)
			setUploadStatus(localPath, "Y") // Mark as Y since it's already up to date
			return false, nil
		}
		log.Printf("🔄 本地檔案較新: %s，重新上傳...", remoteName)
	}

	log.Printf("📤 上傳檔案: %s → %s", filepath.Base(localPath), remoteName)

	// Try to delete remote file first to avoid "553 Mismatch" error on Tandem systems
	_ = client.Delete(remoteName)

	err = client.Stor(remoteName, localFile)
	if err != nil {
		setUploadStatus(localPath, "N")
		return false, fmt.Errorf("ftp stor: %w", err)
	}

	setUploadStatus(localPath, "Y")
	log.Printf("Successfully uploaded %s", remoteName)
	return true, nil
}

type uploadTask struct {
	fullLocalPath string
	remoteName    string
}

func looksLikeGuardianRemotePath(remotePath string) bool {
	p := strings.TrimSpace(remotePath)
	if p == "" || strings.Contains(p, "/") {
		return false
	}
	return strings.Contains(p, "$") || strings.HasPrefix(p, "\\") || strings.Count(p, ".") >= 2
}

func combineUploadRemotePath(remoteDir, remoteName string) string {
	base := strings.TrimSpace(remoteDir)
	name := strings.TrimSpace(remoteName)
	if base == "" || name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return name
	}
	if looksLikeGuardianRemotePath(base) {
		if strings.HasSuffix(base, ".") {
			return base + name
		}
		return base + "." + name
	}

	base = strings.ReplaceAll(base, "\\", "/")
	name = strings.ReplaceAll(name, "\\", "/")
	return path.Join(base, name)
}

// newSSHClient 建立 SSH 連線，支援密碼與私鑰兩種認證方式。
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
	}
	if cfg.Pass != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Pass))
		if cfg.SSHKeyPath == "" {
			log.Printf("🔑 使用密碼認證")
		}
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("SFTP 需要 pass 或 ssh_key_path")
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if cfg.SSHHostKeyCheck {
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
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

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("SFTP 連線至 %s ...", addr)

	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH 連線失敗: %w", err)
	}
	return client, nil
}

func uploadFileSFTP(sftpClient *sftp.Client, cfg *Config, localPath, remoteName string) (bool, error) {
	localFile, err := os.Open(localPath)
	if err != nil {
		return false, fmt.Errorf("open local file: %w", err)
	}
	defer localFile.Close()

	localStat, err := localFile.Stat()
	if err != nil {
		return false, fmt.Errorf("stat local file: %w", err)
	}

	status := getUploadStatus(localPath)
	statusPath := localPath + ".status"
	if status == "Y" {
		if statusInfo, err := os.Stat(statusPath); err == nil {
			if localStat.ModTime().After(statusInfo.ModTime()) {
				log.Printf("🔄 檔案已變更: %s (本地: %s, 狀態: %s)",
					filepath.Base(localPath),
					localStat.ModTime().Format("2006-01-02 15:04:05"),
					statusInfo.ModTime().Format("2006-01-02 15:04:05"))
				log.Printf("   本地檔案較新，需要重新上傳")
			} else {
				log.Printf("⏭️  跳過上傳: %s (已上傳且未變更)", filepath.Base(localPath))
				return false, nil
			}
		}
	}

	remotePath := combineUploadRemotePath(cfg.RemoteDir, remoteName)
	if remoteInfo, err := sftpClient.Stat(remotePath); err == nil {
		if !localStat.ModTime().After(remoteInfo.ModTime()) {
			log.Printf("⏭️  跳過上傳: %s (遠端檔案已是最新)", remotePath)
			setUploadStatus(localPath, "Y")
			return false, nil
		}
		log.Printf("🔄 本地檔案較新: %s，重新上傳...", remotePath)
	}

	log.Printf("📤 SFTP 上傳檔案: %s → %s", filepath.Base(localPath), remotePath)

	_ = sftpClient.Remove(remotePath)

	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		setUploadStatus(localPath, "N")
		return false, fmt.Errorf("sftp create %s: %w", remotePath, err)
	}

	written, copyErr := io.Copy(remoteFile, localFile)
	closeErr := remoteFile.Close()
	if copyErr != nil {
		setUploadStatus(localPath, "N")
		return false, fmt.Errorf("sftp write %s: %w", remotePath, copyErr)
	}
	if closeErr != nil {
		setUploadStatus(localPath, "N")
		return false, fmt.Errorf("sftp close %s: %w", remotePath, closeErr)
	}
	if written != localStat.Size() {
		setUploadStatus(localPath, "N")
		return false, fmt.Errorf("sftp upload size mismatch %s: expected %d bytes, wrote %d bytes", remotePath, localStat.Size(), written)
	}

	if err := sftpClient.Chtimes(remotePath, localStat.ModTime(), localStat.ModTime()); err != nil {
		log.Printf("⚠️  無法設定遠端檔案時間 %s: %v", remotePath, err)
	}

	setUploadStatus(localPath, "Y")
	log.Printf("Successfully uploaded %s", remotePath)
	return true, nil
}

func uploadTasksSFTP(cfg *Config, tasks []uploadTask) error {
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

	uploadCount := 0
	for _, task := range tasks {
		uploaded, err := uploadFileSFTP(sftpClient, cfg, task.fullLocalPath, task.remoteName)
		if err != nil {
			log.Printf("Error uploading %s: %v", task.fullLocalPath, err)
			continue
		}
		if uploaded {
			uploadCount++
		}
	}

	if uploadCount == 0 {
		log.Println("Upload process finished. No files were uploaded this time.")
	} else {
		log.Printf("Upload process finished. %d file(s) uploaded.", uploadCount)
	}
	return nil
}

// matchFileName 檢查檔案名稱是否符合指定的規則
func matchFileName(fileName string, mapping *PathMapping) bool {
	// 如果在排除清單中，直接返回 false
	for _, exclude := range mapping.ExcludeFiles {
		if strings.EqualFold(fileName, exclude) {
			return false
		}
	}

	// 如果有指定 include_prefixes，檢查是否符合
	if len(mapping.IncludePrefixes) > 0 {
		matched := false
		for _, prefix := range mapping.IncludePrefixes {
			if strings.HasPrefix(strings.ToUpper(fileName), strings.ToUpper(prefix)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 如果有指定 include_suffixes，檢查是否符合
	if len(mapping.IncludeSuffixes) > 0 {
		matched := false
		for _, suffix := range mapping.IncludeSuffixes {
			if strings.HasSuffix(strings.ToUpper(fileName), strings.ToUpper(suffix)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// applyFileNameRename 根據 PrefixRename 和 SuffixRename 規則重命名檔案
func applyFileNameRename(fileName string, mapping *PathMapping) string {
	if mapping == nil {
		return fileName
	}

	newName := fileName

	// 應用前綴替換規則
	if len(mapping.PrefixRename) > 0 {
		for oldPrefix, newPrefix := range mapping.PrefixRename {
			if strings.HasPrefix(strings.ToUpper(newName), strings.ToUpper(oldPrefix)) {
				// 保留前綴後的部分
				remainder := newName[len(oldPrefix):]
				newName = newPrefix + remainder
				break // 只應用第一個匹配的規則
			}
		}
	}

	// 應用後綴替換規則
	if len(mapping.SuffixRename) > 0 {
		for oldSuffix, newSuffix := range mapping.SuffixRename {
			if strings.HasSuffix(strings.ToUpper(newName), strings.ToUpper(oldSuffix)) {
				// 保留後綴前的部分
				baseLen := len(newName) - len(oldSuffix)
				newName = newName[:baseLen] + newSuffix
				break // 只應用第一個匹配的規則
			}
		}
	}

	return newName
}

// expandFilePatterns 根據萬用字元展開檔案清單
func expandFilePatterns(localBase string, patterns []string) ([]string, error) {
	var expandedFiles []string
	for _, pattern := range patterns {
		// 組合完整路徑
		fullPattern := pattern
		if !filepath.IsAbs(pattern) {
			fullPattern = filepath.Join(localBase, pattern)
		}

		// 使用 filepath.Glob 進行萬用字元匹配
		matches, err := filepath.Glob(fullPattern)
		if err != nil {
			log.Printf("Warning: Invalid pattern '%s': %v", pattern, err)
			continue
		}

		for _, match := range matches {
			// 確認是檔案而非目錄
			info, err := os.Stat(match)
			if err != nil {
				continue
			}
			if !info.IsDir() {
				expandedFiles = append(expandedFiles, match)
			}
		}
	}
	return expandedFiles, nil
}

func runUpload(cfg *Config) error {
	// Log configuration summary
	log.Printf("Configuration: Host=%s, Port=%s, User=%s", cfg.Host, cfg.Port, cfg.User)
	if cfg.UseSFTP {
		log.Printf("Protocol: SFTP")
	} else if !cfg.UseTLS {
		log.Printf("Protocol: FTP")
	} else if cfg.UseImplicitTLS {
		log.Printf("Protocol: FTPS - Implicit TLS")
	} else {
		log.Printf("Protocol: FTPS - Explicit TLS")
	}
	log.Printf("Local directory: %s", cfg.LocalDir)
	if cfg.RemoteDir != "" {
		log.Printf("Remote directory: %s", cfg.RemoteDir)
	}
	if cfg.AllowedTimeRange != "" {
		log.Printf("Allowed time range: %s", cfg.AllowedTimeRange)
	}

	// 1. Check time range
	within, err := isWithinTimeRange(cfg.AllowedTimeRange)
	if err != nil {
		return fmt.Errorf("check time range: %w", err)
	}
	if !within {
		log.Printf("Current time is outside allowed range (%s). Skipping upload.", cfg.AllowedTimeRange)
		return nil
	}

	// 2. Collect files that actually exist
	var tasks []uploadTask

	for _, mapping := range cfg.FileNames {
		localBase := mapping.LocalPath
		if localBase == "" {
			localBase = cfg.LocalDir
		}

		// 處理明確指定的檔案
		for _, fileSpec := range mapping.Files {
			localName := fileSpec
			remoteName := fileSpec

			if idx := strings.Index(fileSpec, ":"); idx >= 0 {
				localName = strings.TrimSpace(fileSpec[:idx])
				remoteName = strings.TrimSpace(fileSpec[idx+1:])
			}

			fullLocalPath := localName
			if !filepath.IsAbs(localName) {
				fullLocalPath = filepath.Join(localBase, localName)
			}

			if _, err := os.Stat(fullLocalPath); err == nil {
				fileName := filepath.Base(fullLocalPath)

				// 檢查是否被排除
				isExcluded := false
				for _, exclude := range mapping.ExcludeFiles {
					if strings.EqualFold(fileName, exclude) {
						isExcluded = true
						break
					}
				}

				if !isExcluded {
					tasks = append(tasks, uploadTask{
						fullLocalPath: fullLocalPath,
						remoteName:    remoteName,
					})
				} else {
					log.Printf("Skipping %s: filtered out by rules", fileName)
				}
			}
		}

		// 處理萬用字元模式
		if len(mapping.FilePatterns) > 0 {
			expandedFiles, err := expandFilePatterns(localBase, mapping.FilePatterns)
			if err != nil {
				log.Printf("Warning: Error expanding patterns for %s: %v", localBase, err)
			}
			for _, fullLocalPath := range expandedFiles {
				fileName := filepath.Base(fullLocalPath)
				if matchFileName(fileName, &mapping) {
					// 應用前綴/後綴重命名規則
					remoteName := applyFileNameRename(fileName, &mapping)
					tasks = append(tasks, uploadTask{
						fullLocalPath: fullLocalPath,
						remoteName:    remoteName,
					})
				} else {
					log.Printf("Skipping %s: filtered out by rules", fileName)
				}
			}
		}

		// 如果沒有指定任何檔案或模式，但有前綴/後綴篩選，則掃描整個目錄
		if len(mapping.Files) == 0 && len(mapping.FilePatterns) == 0 &&
			(len(mapping.IncludePrefixes) > 0 || len(mapping.IncludeSuffixes) > 0) {
			entries, err := os.ReadDir(localBase)
			if err != nil {
				log.Printf("Warning: Cannot read directory %s: %v", localBase, err)
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				fileName := entry.Name()
				if matchFileName(fileName, &mapping) {
					// 應用前綴/後綴重命名規則
					remoteName := applyFileNameRename(fileName, &mapping)
					fullLocalPath := filepath.Join(localBase, fileName)
					tasks = append(tasks, uploadTask{
						fullLocalPath: fullLocalPath,
						remoteName:    remoteName,
					})
				}
			}
		}
	}

	if len(tasks) == 0 {
		log.Println("No local files found for upload. Skipping remote connection.")
		return nil
	}

	if cfg.UseSFTP {
		return uploadTasksSFTP(cfg, tasks)
	}

	// 3. Connect to FTP only if there are files to upload
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("Connecting to %s ...", addr)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.Host,
	}

	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(15 * time.Second),
	}

	if cfg.UseTLS {
		if cfg.UseImplicitTLS {
			dialOptions = append(dialOptions, ftp.DialWithTLS(tlsConfig))
		} else {
			dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
		}
	}

	client, err := ftp.Dial(addr, dialOptions...)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Quit()

	if err := client.Login(cfg.User, cfg.Pass); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	log.Println("Logged in successfully.")

	// 設定為 ASCII 傳輸模式（適用於文字檔案上傳到 Guardian/NonStop）
	if err := client.Type(ftp.TransferTypeASCII); err != nil {
		log.Printf("Warning: failed to set ASCII transfer mode: %v", err)
		log.Println("Attempting binary mode as fallback...")
		if err := client.Type(ftp.TransferTypeBinary); err != nil {
			return fmt.Errorf("failed to set transfer mode: %w", err)
		}
		log.Println("✓ Binary transfer mode enabled")
	} else {
		log.Println("✓ ASCII transfer mode enabled")
	}

	if cfg.RemoteDir != "" {
		log.Printf("Changing directory to %s ...", cfg.RemoteDir)
		if err := client.ChangeDir(cfg.RemoteDir); err != nil {
			return fmt.Errorf("cwd to %s: %w", cfg.RemoteDir, err)
		}
		currDir, _ := client.CurrentDir()
		log.Printf("Current remote directory: %s", currDir)
	}

	uploadCount := 0
	for _, task := range tasks {
		uploaded, err := uploadFile(client, task.fullLocalPath, task.remoteName)
		if err != nil {
			log.Printf("Error uploading %s: %v", task.fullLocalPath, err)
			continue
		}
		if uploaded {
			uploadCount++
		}
	}

	if uploadCount == 0 {
		log.Println("Upload process finished. No files were uploaded this time.")
	} else {
		log.Printf("Upload process finished. %d file(s) uploaded.", uploadCount)
	}
	return nil
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

	protocolName := "FTP/FTPS"
	if cfg.UseSFTP {
		protocolName = "SFTP"
	}

	// 驗證必要參數
	if cfg.Host == "" {
		return fmt.Errorf("❌ 驗證失敗: host 參數未設定")
	}
	log.Printf("✓ %s 主機: %s", protocolName, cfg.Host)

	if cfg.Port == "" {
		if cfg.UseSFTP {
			cfg.Port = "22"
		} else {
			cfg.Port = "21"
		}
		log.Printf("ℹ️  %s 埠號: %s (使用預設值)", protocolName, cfg.Port)
	} else if cfg.UseSFTP && cfg.Port == "21" {
		cfg.Port = "22"
		log.Printf("ℹ️  SFTP 埠號: %s (use_sftp=true 且未指定 SFTP port，使用預設值)", cfg.Port)
	} else {
		// 驗證埠號格式
		if port, err := strconv.Atoi(cfg.Port); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("❌ 驗證失敗: port 參數無效 (%s)，必須是 1-65535 之間的數字", cfg.Port)
		}
		log.Printf("✓ %s 埠號: %s", protocolName, cfg.Port)
	}

	if cfg.User == "" {
		return fmt.Errorf("❌ 驗證失敗: user 參數未設定")
	}
	log.Printf("✓ %s 帳號: %s", protocolName, cfg.User)

	if cfg.Pass == "" && !(cfg.UseSFTP && cfg.SSHKeyPath != "") {
		return fmt.Errorf("❌ 驗證失敗: pass 參數未設定")
	}
	if cfg.Pass != "" {
		log.Printf("✓ %s 密碼: %s", protocolName, strings.Repeat("*", len(cfg.Pass)))
	}
	if cfg.UseSFTP && cfg.SSHKeyPath != "" {
		log.Printf("✓ SSH 私鑰: %s", cfg.SSHKeyPath)
	}

	// 驗證目錄設定
	if cfg.LocalDir == "" {
		cfg.LocalDir = "./uploads"
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

	// 驗證通訊協議設定
	if cfg.UseSFTP {
		log.Printf("✓ 通訊協議: SFTP")
		if cfg.SSHHostKeyCheck {
			log.Printf("✓ SSH 主機金鑰檢查: 已啟用")
		} else {
			log.Printf("⚠️  SSH 主機金鑰檢查: 已停用 (ssh_host_key_check=false)")
		}
	} else {
		if !cfg.UseTLS {
			log.Printf("✓ 連線模式: 純文字 FTP（無加密）")
		} else if cfg.UseImplicitTLS {
			log.Printf("✓ TLS 模式: Implicit TLS (通常使用 port 990)")
		} else {
			log.Printf("✓ TLS 模式: Explicit TLS")
		}
		if cfg.UseTLS && cfg.InsecureSkipVerify {
			log.Printf("⚠️  SSL 驗證: 已停用 (insecure_skip_verify=true)")
		}
	}

	// 驗證檔案設定
	if len(cfg.FileNames) == 0 {
		log.Printf("⚠️  警告: 未設定上傳檔案，將無檔案可上傳")
	} else {
		log.Printf("✓ 上傳模式: 指定檔案清單 (%d 個路徑)", len(cfg.FileNames))
	}

	log.Println("✓ 參數驗證通過")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println()

	// 如果啟用監控模式，進入循環
	if cfg.MonitorMode {
		log.Printf("=== 啟動全天監控模式 ===")
		if cfg.AllowedTimeRange != "" {
			log.Printf("上傳時間範圍: %s", cfg.AllowedTimeRange)
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
			configFile = "config.uploader.properties"
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
			shouldUpload := true
			if cfg.AllowedTimeRange != "" {
				within, err := isWithinTimeRange(cfg.AllowedTimeRange)
				if err != nil {
					log.Printf("❌ 時間範圍檢查錯誤: %v", err)
					shouldUpload = false
				} else if !within {
					log.Printf("⏰ 上傳時間範圍: %s", cfg.AllowedTimeRange)
					log.Printf("⚠️  目前時間不在設定範圍內，跳過本次上傳")
					log.Printf("ℹ️  狀態: 監控中 (待機狀態)")
					shouldUpload = false
				} else {
					log.Printf("✓ 上傳時間範圍: %s", cfg.AllowedTimeRange)
					log.Printf("✓ 目前時間在允許範圍內，開始執行上傳")
				}
			} else {
				log.Printf("ℹ️  無時間範圍限制，可隨時上傳")
			}

			// 執行上傳或顯示待機狀態
			if shouldUpload {
				log.Println("▼▼▼ 開始上傳作業 ▼▼▼")
				if err := runUpload(cfg); err != nil {
					log.Printf("❌ 上傳錯誤: %v", err)
				} else {
					log.Printf("✓ 上傳作業完成")
				}
				log.Println("▲▲▲ 上傳作業結束 ▲▲▲")
			} else {
				log.Printf("⏸️  本次循環跳過上傳，程式持續監控中")
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

	return runUpload(cfg)
}

func main() {
	configPath := flag.String("config", "config.uploader.properties", "Path to uploader configuration file")
	flag.Parse()

	// Setup logging with timestamp and file info
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 先載入設定檔以取得日誌目錄設定
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup log file - ensure logs directory exists
	var logFile *os.File
	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
		} else {
			logFileName := fmt.Sprintf("ftps-uploader-%s.log", time.Now().Format("2006-01-02"))
			logPath := filepath.Join(cfg.LogDir, logFileName)
			// Check if file is new (doesn't exist or has zero size)
			fileInfo, _ := os.Stat(logPath)
			isNewFile := fileInfo == nil || fileInfo.Size() == 0
			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				logFile = f
				// Write UTF-8 BOM for new files so Windows Notepad can detect UTF-8
				if isNewFile {
					f.Write([]byte{0xEF, 0xBB, 0xBF})
				}
				// For hidden mode (no console), only write to file
				// For normal mode, write to both console and file
				if os.Stdout != nil {
					log.SetOutput(io.MultiWriter(os.Stdout, f))
				} else {
					log.SetOutput(f)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			}
		}
	}

	// Log execution start
	log.Printf("========================================")
	log.Printf("FTPS Uploader started")
	log.Printf("Config file: %s", *configPath)
	log.Printf("========================================")
	log.Println()

	// 1. 確保單一執行實例（終止舊實例）
	if err := ensureSingleInstance(); err != nil {
		log.Printf("❌ 執行實例檢查失敗: %v", err)
		if logFile != nil {
			logFile.Close()
		}
		os.Exit(1)
	}

	// 2. 清理超過3天的舊日誌
	if cfg.LogDir != "" {
		cleanupOldLogs(cfg.LogDir, 3)
	}

	// Run the upload process
	err = run(cfg)

	// Close log file if opened
	if logFile != nil {
		logFile.Close()
	}

	// Log execution result
	log.Printf("========================================")
	if err != nil {
		log.Printf("FTPS Uploader FAILED: %v", err)
		log.Printf("========================================")
		os.Exit(1)
	} else {
		log.Printf("FTPS Uploader completed successfully")
		log.Printf("========================================")
	}
}
