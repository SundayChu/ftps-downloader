package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

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

func downloadFile(client *ftp.ServerConn, cfg *Config, remotePath, localName string) (bool, error) {
	// 如果啟用獨立檔案日誌，為此檔案建立獨立的 log 檔案
	var fileLogger *log.Logger
	var fileLogHandle *os.File
	var remoteInfoTime time.Time
	var remoteInfoSize int64
	var remoteInfoTimeOK bool
	var remoteInfoSizeOK bool

	remoteInfoTime, remoteInfoSize, remoteInfoTimeOK, remoteInfoSizeOK = getRemoteFileInfo(client, cfg, remotePath)

	if cfg.SeparateFileLog && cfg.LogDir != "" {
		// 使用日期作為檔名，同一天的下載記錄會寫入同一個檔案
		dateStr := time.Now().Format("20060102")
		fileLogName := fmt.Sprintf("download_%s_%s.log", localName, dateStr)
		fileLogPath := filepath.Join(cfg.LogDir, fileLogName)

		var err error
		fileLogHandle, err = os.OpenFile(fileLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("  ⚠️  無法建立檔案日誌 %s: %v", fileLogPath, err)
		} else {
			fileLogger = log.New(fileLogHandle, "", log.LstdFlags)
			defer fileLogHandle.Close()

			// 寫入獨立日誌的檔頭
			fileLogger.Printf("")
			fileLogger.Printf("════════════════════════════════════════════════")
			fileLogger.Printf("📥 檔案下載日誌 - %s", localName)
			fileLogger.Printf("════════════════════════════════════════════════")
			fileLogger.Printf("開始時間: %s", time.Now().Format("2006-01-02 15:04:05"))
			fileLogger.Printf("")
			fileLogger.Printf("檔案資訊:")
			fileLogger.Printf("  遠端檔案: %s", remotePath)
			fileLogger.Printf("  本地檔案: %s", filepath.Join(cfg.LocalDir, localName))

			// 記錄遠端檔案修改時間和大小
			if remoteInfoTimeOK {
				fileLogger.Printf("  遠端修改時間: %s", remoteInfoTime.Format("2006-01-02 15:04:05"))
			} else {
				fileLogger.Printf("  遠端修改時間: 無法取得")
			}
			if remoteInfoSizeOK {
				fileLogger.Printf("  遠端檔案大小: %s (%d bytes)", formatFileSize(remoteInfoSize), remoteInfoSize)
			} else {
				fileLogger.Printf("  遠端檔案大小: 無法取得")
			}

			// 記錄本地檔案修改時間和大小（如果存在）
			localPath := filepath.Join(cfg.LocalDir, localName)
			if localInfo, err := os.Stat(localPath); err == nil {
				fileLogger.Printf("  本地修改時間: %s", localInfo.ModTime().Format("2006-01-02 15:04:05"))
				fileLogger.Printf("  本地檔案大小: %s (%d bytes)", formatFileSize(localInfo.Size()), localInfo.Size())
			}
			fileLogger.Printf("")
			fileLogger.Printf("下載判斷:")
		}
	}

	// 輔助函數：同時寫入主日誌和檔案日誌
	logBoth := func(format string, v ...interface{}) {
		msg := fmt.Sprintf(format, v...)
		log.Print(msg)
		if fileLogger != nil {
			fileLogger.Print(msg)
		}
	}

	// 檢查是否需要下載
	needDownload, reason, err := shouldDownloadFile(client, cfg, remotePath, localName)
	if err != nil {
		logBoth("  ⚠️  檢查檔案時發生錯誤: %v", err)
		logBoth("  ➜  將繼續下載以確保檔案完整性")
		// 錯誤時強制下載（needDownload 應該已經是 true）
	}

	if !needDownload {
		if fileLogger != nil {
			fileLogger.Printf("  ⊘  檔案未更新，跳過下載")
			if reason != "" {
				fileLogger.Printf("     原因: %s", reason)
			}
		}
		logBoth("  ⊘  跳過下載: %s", reason)

		// 即使跳過下載，也對已存在的檔案進行分檔檢查
		localPath := filepath.Join(cfg.LocalDir, localName)
		if data, err := os.ReadFile(localPath); err == nil {
			if err := splitFileByPrefix(cfg, localName, data); err != nil {
				logBoth("  ⚠️  檔案分割失敗: %v", err)
			}
		}

		if fileLogger != nil {
			fileLogger.Printf("════════════════════════════════════════════════")
			fileLogger.Printf("結束時間: %s", time.Now().Format("2006-01-02 15:04:05"))
			fileLogger.Printf("狀態: 跳過下載")
			fileLogger.Printf("════════════════════════════════════════════════")
		}
		return false, nil
	}

	if reason != "" {
		logBoth("  ➜  下載原因: %s", reason)
	}

	// 直接覆寫檔案，不保留備份
	localPath := filepath.Join(cfg.LocalDir, localName)

	remoteSize := int64(-1)
	if size, err := client.FileSize(remotePath); err == nil {
		remoteSize = size
		logBoth("  📥 開始下載 (檔案大小: %d bytes)", remoteSize)
	} else {
		logBoth("  📥 開始下載 (無法確認檔案大小)")
	}

	reader, err := client.Retr(remotePath)
	if err != nil {
		// If ASCII mode fails with filecode error, try binary mode
		if strings.Contains(err.Error(), "Can't use ASCII transfer mode") || strings.Contains(err.Error(), "filecode") {
			logBoth("ASCII mode not supported for %s, switching to binary mode...", remotePath)
			if switchErr := client.Type(ftp.TransferTypeBinary); switchErr != nil {
				if fileLogger != nil {
					fileLogger.Printf("錯誤: 無法切換到 binary 模式: %v", switchErr)
				}
				return false, fmt.Errorf("retrieve %s: failed to switch to binary mode: %w", remotePath, switchErr)
			}
			reader, err = client.Retr(remotePath)
			if err != nil {
				if fileLogger != nil {
					fileLogger.Printf("錯誤: binary 模式下載失敗: %v", err)
				}
				return false, fmt.Errorf("retrieve %s (binary mode): %w", remotePath, err)
			}
			// Switch back to ASCII for next file
			defer func() {
				if switchErr := client.Type(ftp.TransferTypeASCII); switchErr != nil {
					logBoth("Warning: failed to switch back to ASCII mode: %v", switchErr)
				}
			}()
		} else {
			if fileLogger != nil {
				fileLogger.Printf("錯誤: 下載失敗: %v", err)
			}
			return false, fmt.Errorf("retrieve %s: %w", remotePath, err)
		}
	}
	defer reader.Close()

	var buf bytes.Buffer
	rawBytesRead, err := io.Copy(&buf, reader)
	if err != nil {
		if fileLogger != nil {
			fileLogger.Printf("錯誤: 讀取資料失敗: %v", err)
		}
		return false, fmt.Errorf("read %s: %w", remotePath, err)
	}

	// RAW 模式下保留大小差異提示，但不視為失敗
	if cfg.RawDownload && remoteSize > 0 && rawBytesRead != remoteSize {
		msg := fmt.Sprintf("下載大小與遠端不一致 (遠端: %d bytes, 下載: %d bytes)", remoteSize, rawBytesRead)
		if fileLogger != nil {
			fileLogger.Printf("注意: %s", msg)
		}
		logBoth("  ℹ️  %s", msg)
	}

	rawData := buf.Bytes()
	processed := processData(cfg, remotePath, rawData)

	// localPath 已在上面定義
	if err := os.WriteFile(localPath, processed, 0644); err != nil {
		if fileLogger != nil {
			fileLogger.Printf("錯誤: 寫入檔案失敗: %v", err)
		}
		return false, fmt.Errorf("write %s: %w", localPath, err)
	}

	// Verify written file
	writtenInfo, err := os.Stat(localPath)
	if err != nil {
		if fileLogger != nil {
			fileLogger.Printf("錯誤: 驗證檔案失敗: %v", err)
		}
		return false, fmt.Errorf("verify written file %s: %w", localPath, err)
	}

	logBoth("  ✅ 下載完成")
	if remoteInfoTimeOK {
		logBoth("     遠端修改時間: %s", remoteInfoTime.Format("2006-01-02 15:04:05"))
	}
	if remoteSize > 0 {
		logBoth("     遠端大小: %d bytes", remoteSize)
	}
	logBoth("     下載大小: %d bytes", rawBytesRead)
	if rawBytesRead != writtenInfo.Size() {
		logBoth("     處理後大小: %d bytes", writtenInfo.Size())
	}

	// TCD/TSC splitting logic
	if err := splitFileByPrefix(cfg, localName, processed); err != nil {
		logBoth("  ⚠️  檔案分割失敗: %v", err)
	}

	// 驗證下載結果
	if cfg.RawDownload {
		// RAW 模式：嚴格驗證
		if writtenInfo.Size() != rawBytesRead {
			if fileLogger != nil {
				fileLogger.Printf("錯誤: 驗證失敗 (寫入: %d bytes, 下載: %d bytes)", writtenInfo.Size(), rawBytesRead)
			}
			return false, fmt.Errorf("verification failed for %s: written size (%d) != downloaded size (%d)", localPath, writtenInfo.Size(), rawBytesRead)
		}
		if remoteSize > 0 && rawBytesRead != remoteSize {
			// 下載大小與遠端大小不符
			if fileLogger != nil {
				fileLogger.Printf("警告: 下載大小與遠端不符 (遠端: %d bytes, 下載: %d bytes)", remoteSize, rawBytesRead)
				fileLogger.Printf("這可能是 FTP 伺服器在 ASCII 模式下的轉換造成的")
			}
			logBoth("  ⚠️  警告: 下載大小與遠端不符 (遠端: %d, 下載: %d)", remoteSize, rawBytesRead)
			logBoth("     這可能是 FTP 伺服器在 ASCII 模式下的轉換造成的")
			logBoth("  ✓ 檔案已下載並寫入 (大小: %d bytes)", writtenInfo.Size())
		} else {
			logBoth("  ✓ 檔案驗證通過 (與遠端檔案完全一致)")
		}
	} else {
		// 非 RAW 模式：處理後的資料
		if remoteSize > 0 && rawBytesRead == remoteSize {
			logBoth("  ✓ 下載驗證通過 (原始資料符合遠端大小)")
		}
		if rawBytesRead != writtenInfo.Size() {
			logBoth("  ℹ️  資料已處理 (原始: %d bytes → 處理後: %d bytes)", rawBytesRead, writtenInfo.Size())
		}
	}

	status := "下載成功"
	statusDetail := ""

	if remoteInfoTimeOK {
		if err := os.Chtimes(localPath, remoteInfoTime, remoteInfoTime); err != nil {
			logBoth("  ⚠️  設定本地檔案時間失敗: %v", err)
			if fileLogger != nil {
				fileLogger.Printf("警告: 設定本地檔案時間失敗: %v", err)
			}
		} else {
			// 讀取更新後的本地檔案狀態
			if updatedInfo, err := os.Stat(localPath); err == nil {
				logBoth("  ✓ 本地檔案時間已更新")
				logBoth("     遠端時間: %s", remoteInfoTime.Format("2006-01-02 15:04:05"))
				logBoth("     本地時間: %s", updatedInfo.ModTime().Format("2006-01-02 15:04:05"))
				if fileLogger != nil {
					fileLogger.Printf("本地修改時間已更新")
					fileLogger.Printf("  遠端時間: %s", remoteInfoTime.Format("2006-01-02 15:04:05"))
					fileLogger.Printf("  本地時間: %s", updatedInfo.ModTime().Format("2006-01-02 15:04:05"))
				}
			} else {
				logBoth("  ✓ 本地檔案時間已更新為遠端時間")
				if fileLogger != nil {
					fileLogger.Printf("本地修改時間已更新為遠端時間")
				}
			}
		}
	}

	if remoteInfoSizeOK {
		if writtenInfo.Size() != remoteInfoSize {
			detail := fmt.Sprintf("下載後大小與遠端不一致 (本地: %d, 遠端: %d)", writtenInfo.Size(), remoteInfoSize)
			statusDetail = detail
			logBoth("  ℹ️  %s", detail)
			if fileLogger != nil {
				fileLogger.Printf("注意: %s", detail)
			}
		}
	}

	// 寫入獨立日誌的結束訊息
	if fileLogger != nil {
		fileLogger.Printf("════════════════════════════════════════════════")
		fileLogger.Printf("結束時間: %s", time.Now().Format("2006-01-02 15:04:05"))
		fileLogger.Printf("狀態: %s", status)
		if statusDetail != "" {
			if status == "下載成功" {
				fileLogger.Printf("備註: %s", statusDetail)
			} else {
				fileLogger.Printf("原因: %s", statusDetail)
			}
		}
		fileLogger.Printf("本地檔案: %s", localPath)
		fileLogger.Printf("最終大小: %d bytes", writtenInfo.Size())
		fileLogger.Printf("════════════════════════════════════════════════")
	}

	return true, nil
}

// fixFTPTimeZone 修正 FTP 函式庫錯誤標記為 UTC 的時間
// FTP 伺服器回傳的時間通常是伺服器本地時間，但函式庫用 UTC 解析
// 這個函數將時間值保持不變，只重新標記為本地時區
func fixFTPTimeZone(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	// 將 UTC 時間的數值重新標記為本地時間（不進行轉換）
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local)
}

// getRemoteFileInfo 取得遠端檔案的時間與大小
func getRemoteFileInfo(client *ftp.ServerConn, cfg *Config, remotePath string) (time.Time, int64, bool, bool) {
	var remoteSize int64
	var remoteModTime time.Time
	var sizeAvailable, timeAvailable bool

	remoteDir := ""
	remoteFileName := remotePath
	lastDot := strings.LastIndex(remotePath, ".")
	if lastDot > 0 {
		remoteDir = remotePath[:lastDot]
		remoteFileName = remotePath[lastDot+1:]
	}

	entries, listErr := client.List(remoteDir)
	if listErr == nil {
		for _, entry := range entries {
			if entry.Name == remoteFileName {
				remoteSize = int64(entry.Size)
				remoteModTime = fixFTPTimeZone(entry.Time) // 修正時區標記
				sizeAvailable = true
				if !remoteModTime.IsZero() {
					timeAvailable = true
				} else {
					if parsedTime, parsedSize, ok := parseNonStopListOutput(client, remoteDir, remoteFileName, cfg.DebugList); ok {
						remoteModTime = parsedTime
						if parsedSize > 0 {
							remoteSize = parsedSize
							sizeAvailable = true
						}
						timeAvailable = true
					}
				}
				break
			}
		}
	}

	if !sizeAvailable {
		var err error
		remoteSize, err = client.FileSize(remotePath)
		sizeAvailable = (err == nil)
	}

	if !timeAvailable {
		mdtmTime, err := client.GetTime(remotePath)
		if err == nil {
			remoteModTime = fixFTPTimeZone(mdtmTime) // 修正時區標記
			timeAvailable = true
		}
	}

	return remoteModTime, remoteSize, timeAvailable, sizeAvailable
}

// formatFileSize 格式化檔案大小為易讀格式
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// parseNonStopListOutput 透過原始 LIST 輸出解析 NonStop 檔案時間與大小
func parseNonStopListOutput(client *ftp.ServerConn, remoteDir, remoteFileName string, debug bool) (time.Time, int64, bool) {
	lines, err := client.RawList(remoteDir)
	if err != nil {
		if debug {
			log.Printf("  ⚠️  Raw LIST 失敗: %v", err)
		}
		return time.Time{}, 0, false
	}

	for i, line := range lines {
		if debug {
			log.Printf("     [RAW %d] %s", i, line)
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		name := fields[0]
		if name != remoteFileName {
			continue
		}

		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue
		}
		sizeValue, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}

		dateStr := fields[3]
		timeStr := fields[4]
		dateTimeStr := dateStr + " " + timeStr
		// FTP 伺服器回傳的是伺服器本地時間，直接用 Local 解析
		parsedTime, err := time.ParseInLocation("_2-Jan-06 15:04:05", dateTimeStr, time.Local)
		if err != nil {
			parsedTime, err = time.ParseInLocation("_2-Jan-2006 15:04:05", dateTimeStr, time.Local)
			if err != nil {
				if debug {
					log.Printf("  ⚠️  Raw LIST 解析失敗: %s", dateTimeStr)
				}
				continue
			}
		}

		return parsedTime, sizeValue, true
	}

	return time.Time{}, 0, false
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

func splitFileByPrefix(cfg *Config, localName string, data []byte) error {
	upperName := strings.ToUpper(localName)

	// 檢查檔名是否符合設定的任何一個前綴
	matchedPrefix := ""
	for _, p := range cfg.SplitFilePrefixes {
		if strings.HasPrefix(upperName, strings.ToUpper(p)) {
			matchedPrefix = strings.ToUpper(p)
			break
		}
	}

	// 如果沒有設定 SplitFilePrefixes，預設相容舊有的 TCD/TSC
	if matchedPrefix == "" && len(cfg.SplitFilePrefixes) == 0 {
		if strings.HasPrefix(upperName, "TCD") {
			matchedPrefix = "TCD"
		} else if strings.HasPrefix(upperName, "TSC") {
			matchedPrefix = "TSC"
		}
	}

	if matchedPrefix == "" {
		log.Printf("  ℹ️  檔案 %s 不符合分檔條件 (SplitFilePrefixes: %v)", localName, cfg.SplitFilePrefixes)
		return nil
	}

	log.Printf("  🔪 開始分檔 (matched prefix: %s, size: %d bytes)", matchedPrefix, len(data))

	// 檢查是否為空檔案
	if len(data) == 0 {
		log.Printf("  ℹ️  檔案為空 (0 bytes)，無需分檔")
		return nil
	}

	// 統一處理換行符號，將 \r\n 替換為 \n
	normalizedData := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalizedData, []byte("\n"))
	log.Printf("  🔎 總共 %d 行資料", len(lines))

	categoryFiles := make(map[string]*os.File)
	defer func() {
		for _, f := range categoryFiles {
			f.Close()
		}
	}()

	count := 0
	skippedShortLines := 0
	emptyLines := 0
	invalidLines := 0

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			emptyLines++
			continue
		}
		if len(line) < 4 {
			skippedShortLines++
			continue
		}

		// 取前四碼作為分類 (例如 TCD1, TCD2...)
		category := string(line[:4])

		// 檢查前四碼是否包含不合法字元 (如換行或控制碼)
		isValid := true
		for _, r := range category {
			if r < 32 || r > 126 || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
				isValid = false
				break
			}
		}

		if !isValid {
			invalidLines++
			continue
		}

		catFileName := matchedPrefix + "." + category
		catPath := filepath.Join(cfg.LocalDir, catFileName)

		f, ok := categoryFiles[category]
		if !ok {
			var err error
			// 每次執行時覆蓋舊的分類檔案
			f, err = os.OpenFile(catPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("[Split] Error opening category file %s: %v", catPath, err)
				continue
			}
			categoryFiles[category] = f
			log.Printf("[Split] Created/Opened category file: %s", catFileName)
		}

		f.Write(line)
		f.Write([]byte("\r\n"))
		count++
	}

	log.Printf("  📊 分檔統計:")
	log.Printf("     總行數: %d", len(lines))
	log.Printf("     空行: %d", emptyLines)
	log.Printf("     短記錄 (<4字元): %d", skippedShortLines)
	log.Printf("     無效記錄: %d", invalidLines)
	log.Printf("     有效記錄: %d", count)

	if count > 0 {
		log.Printf("  ✅ 檔案分割完成: %d 筆記錄分成 %d 個檔案", count, len(categoryFiles))
		for cat := range categoryFiles {
			log.Printf("     - %s.%s", matchedPrefix, cat)
		}
	} else {
		log.Printf("  ⚠️  未找到可分割的記錄")
	}

	if skippedShortLines > 0 || invalidLines > 0 {
		log.Printf("  ⚠️  警告: 跳過 %d 筆短記錄和 %d 筆無效記錄", skippedShortLines, invalidLines)
	}

	return nil
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

// setupConsoleForUTF8 確保控制台可以正確顯示 UTF-8
// Go 1.6+ 在 Windows 上會自動處理 UTF-8 輸出到控制台
// 此函數保留作為相容性檢查
func setupConsoleForUTF8() {
	// 在 Windows 上，Go 運行時會自動處理 UTF-8 到控制台的轉換
	// 只要確保 log 使用標準輸出即可
	if runtime.GOOS == "windows" {
		// Windows 10+ 支援 UTF-8，Go 運行時會自動處理
		// 無需額外設定
	}
}

// shouldDownloadFile 檢查是否需要下載檔案
// 根據設定選項決定下載策略
// 返回: (是否需要下載, 原因說明, 錯誤)
func shouldDownloadFile(client *ftp.ServerConn, cfg *Config, remotePath, localName string) (bool, string, error) {
	log.Printf("  🔎 正在檢查遠端檔案...")
	localPath := filepath.Join(cfg.LocalDir, localName)

	// 檢查本地檔案是否存在
	log.Printf("  🔎 檢查本地檔案...")
	localInfo, errLocal := os.Stat(localPath)

	// 情況1: 本地檔案不存在 → 總是下載
	if os.IsNotExist(errLocal) {
		log.Printf("  ℹ️  本地檔案不存在")
		return true, "本地檔案不存在，首次下載", nil
	}

	// 情況2: 本地檔案存在但無法讀取 → 重新下載
	if errLocal != nil {
		log.Printf("  ⚠️  無法讀取本地檔案: %v", errLocal)
		return true, fmt.Sprintf("無法檢查本地檔案: %v", errLocal), nil
	}

	// 情況3: force_download=true → 強制下載，跳過所有檢查
	if cfg.ForceDownload {
		log.Printf("  🔄 強制下載模式")
		return true, "設定為強制下載模式，忽略本地檔案", nil
	}

	// 情況4: skip_if_exists=true → 本地檔案存在就跳過
	if cfg.SkipIfExists {
		log.Printf("  ℹ️  本地檔案已存在 (%d bytes)", localInfo.Size())
		return false, fmt.Sprintf("本地檔案已存在，跳過下載 (大小: %d bytes)", localInfo.Size()), nil
	}

	// 情況5: 需要比對遠端與本地檔案的差異
	// 預設策略：優先使用修改時間比對，無法取得時才用大小比對
	var remoteSize int64
	var remoteModTime time.Time
	var sizeAvailable, timeAvailable bool

	// 嘗試使用 LIST 命令取得完整資訊（大小和修改時間）
	log.Printf("  ℹ️  取得遠端檔案詳細資訊...")

	// 處理 NonStop 路徑格式 (使用 . 分隔)
	remoteDir := ""
	remoteFileName := remotePath

	// 找到最後一個 . 來分離目錄和檔名
	lastDot := strings.LastIndex(remotePath, ".")
	if lastDot > 0 {
		remoteDir = remotePath[:lastDot]
		remoteFileName = remotePath[lastDot+1:]
	}

	log.Printf("  🔎 LIST 目錄: %s, 檔名: %s", remoteDir, remoteFileName)

	// 先取得原始 LIST 輸出用於調試
	if cfg.DebugList {
		log.Printf("  🔍 開始 LIST 命令...")
	}

	entries, listErr := client.List(remoteDir)
	if listErr == nil {
		if cfg.DebugList {
			log.Printf("  📋 LIST 回傳 %d 個項目", len(entries))
		}
		for i, entry := range entries {
			if cfg.DebugList {
				log.Printf("     [%d] Name=%s, Size=%d, Time=%v, Type=%s",
					i, entry.Name, entry.Size, entry.Time, entry.Type)
			}
			if entry.Name == remoteFileName {
				remoteSize = int64(entry.Size)
				remoteModTime = fixFTPTimeZone(entry.Time) // 修正時區標記
				sizeAvailable = true
				// 檢查時間是否為零值
				if !remoteModTime.IsZero() {
					timeAvailable = true
					log.Printf("  ✓  從 LIST 取得: 大小=%d bytes, 修改時間=%s",
						remoteSize, remoteModTime.Format("2006-01-02 15:04:05"))
				} else {
					log.Printf("  ⚠️  LIST 回傳的時間為零值")
					// 嘗試重新取得原始 LIST 資料並手動解析 NonStop 格式
					if parsedTime, parsedSize, ok := parseNonStopListOutput(client, remoteDir, remoteFileName, cfg.DebugList); ok {
						remoteModTime = parsedTime
						if parsedSize > 0 {
							remoteSize = parsedSize
						}
						timeAvailable = true
						log.Printf("  ✓  手動解析 NonStop 格式: 大小=%d bytes, 修改時間=%s",
							remoteSize, remoteModTime.Format("2006-01-02 15:04:05"))
					}
				}
				break
			}
		}
		if !sizeAvailable {
			log.Printf("  ⚠️  在目錄列表中找不到檔案: %s", remoteFileName)
		}
	} else {
		log.Printf("  ⚠️  LIST 命令失敗: %v", listErr)
	}

	// 如果 LIST 失敗或找不到，嘗試使用 SIZE 命令取得大小
	if !sizeAvailable {
		var err error
		remoteSize, err = client.FileSize(remotePath)
		sizeAvailable = (err == nil)
		if sizeAvailable {
			log.Printf("  ✓  從 SIZE 取得檔案大小: %d bytes", remoteSize)
		} else {
			log.Printf("  ⚠️  SIZE 命令失敗: %v", err)
		}
	}

	// 如果 LIST 沒有取得時間，嘗試使用 MDTM 命令
	if !timeAvailable {
		log.Printf("  🔎 嘗試使用 MDTM 命令取得修改時間...")
		mdtmTime, err := client.GetTime(remotePath)
		if err == nil {
			remoteModTime = fixFTPTimeZone(mdtmTime) // 修正時區標記
			timeAvailable = true
			log.Printf("  ✓  從 MDTM 取得修改時間: %s", remoteModTime.Format("2006-01-02 15:04:05"))
		} else {
			log.Printf("  ⚠️  MDTM 命令失敗: %v", err)
		}
	}

	// 情況6: 根據 compare_by_modtime 設定選擇比對方式
	if cfg.CompareByModTime {
		// 使用修改時間比對
		if !timeAvailable {
			errMsg := "無法取得遠端檔案修改時間"
			log.Printf("  ⚠️  %s", errMsg)
			log.Printf("  ➜  將繼續下載以確保檔案完整性")
			return true, fmt.Sprintf("%s，強制下載", errMsg), fmt.Errorf("%s: %s", errMsg, remotePath)
		}
		log.Printf("  🔎 比對修改時間")
		log.Printf("     遠端: %s", remoteModTime.Format("2006-01-02 15:04:05"))
		log.Printf("     本地: %s", localInfo.ModTime().Format("2006-01-02 15:04:05"))

		// 遠端檔案較新才下載
		if remoteModTime.After(localInfo.ModTime()) {
			timeDiff := remoteModTime.Sub(localInfo.ModTime())
			log.Printf("  ⚠️  遠端檔案較新 (相差 %v)", timeDiff)
			return true, fmt.Sprintf("遠端檔案較新，需要更新 (時間差: %v)", timeDiff), nil
		}

		log.Printf("  ✓  檔案修改時間相同或本地較新，跳過下載")
		return false, fmt.Sprintf("檔案修改時間相同或本地較新，無需下載 (時間: %s)",
			remoteModTime.Format("2006-01-02 15:04:05")), nil
	} else {
		// 使用檔案大小比對
		if !sizeAvailable {
			errMsg := "無法取得遠端檔案大小"
			log.Printf("  ⚠️  %s", errMsg)
			log.Printf("  ➜  將繼續下載以確保檔案完整性")
			return true, fmt.Sprintf("%s，強制下載", errMsg), fmt.Errorf("%s: %s", errMsg, remotePath)
		}
		log.Printf("  🔎 比對檔案大小")
		log.Printf("     遠端: %d bytes", remoteSize)
		log.Printf("     本地: %d bytes", localInfo.Size())

		// 大小不同才下載
		if remoteSize != localInfo.Size() {
			sizeDiff := remoteSize - localInfo.Size()
			log.Printf("  ⚠️  檔案大小不同 (相差 %d bytes)", sizeDiff)
			return true, fmt.Sprintf("檔案大小不同，需要更新 (大小差: %d bytes)", sizeDiff), nil
		}

		log.Printf("  ✓  檔案大小相同，跳過下載")
		return false, fmt.Sprintf("檔案大小相同，無需下載 (大小: %d bytes)", remoteSize), nil
	}
}

// connectWithRetry 嘗試連線並登入 FTP 伺服器，失敗時重試
func connectWithRetry(cfg *Config, addr string, dialOptions []ftp.DialOption, logWriter io.Writer) (*ftp.ServerConn, error) {
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1 // 至少嘗試一次
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("🔄 重試連線 (%d/%d)...", attempt, maxRetries)
		}

		client, err := ftp.Dial(addr, dialOptions...)
		if err != nil {
			lastErr = fmt.Errorf("connect to server: %w", err)
			if attempt < maxRetries {
				delay := time.Duration(cfg.RetryDelay) * time.Second
				log.Printf("⚠️  連線失敗: %v", err)
				log.Printf("⏳ 等待 %v 後重試...", delay)
				time.Sleep(delay)
				continue
			}
			break
		}

		// 連線成功，嘗試登入
		log.Println("Connected. Logging in...")
		if err := client.Login(cfg.User, cfg.Pass); err != nil {
			client.Quit()
			lastErr = fmt.Errorf("login: %w", err)
			if attempt < maxRetries {
				delay := time.Duration(cfg.RetryDelay) * time.Second
				log.Printf("⚠️  登入失敗: %v", err)
				log.Printf("⏳ 等待 %v 後重試...", delay)
				time.Sleep(delay)
				continue
			}
			break
		}

		log.Println("Logged in successfully.")
		return client, nil
	}

	return nil, fmt.Errorf("連線/登入失敗 (已重試 %d 次): %w", maxRetries, lastErr)
}

// shouldStopNow 檢查是否應該停止程式（根據 stop_time 設定）
func shouldStopNow(cfg *Config) (bool, string) {
	if cfg.StopTime == "" {
		return false, ""
	}

	now := time.Now()
	stopTimeParts := strings.Split(cfg.StopTime, ":")
	if len(stopTimeParts) != 2 {
		return false, ""
	}

	stopHour, err1 := strconv.Atoi(stopTimeParts[0])
	stopMin, err2 := strconv.Atoi(stopTimeParts[1])
	if err1 != nil || err2 != nil {
		return false, ""
	}

	// 計算今天的停止時間
	todayStopTime := time.Date(now.Year(), now.Month(), now.Day(), stopHour, stopMin, 0, 0, time.Local)

	// 檢查是否在停止時間的一個檢查間隔內
	if now.After(todayStopTime) {
		timeSinceStop := now.Sub(todayStopTime)
		if timeSinceStop < time.Duration(cfg.CheckInterval)*time.Minute {
			return true, fmt.Sprintf("已到達今日停止時間 %s", cfg.StopTime)
		}
	}

	return false, ""
}

// calculateNextCheckTime 計算下次檢查的時間（簡化版）
func calculateNextCheckTime(now time.Time, checkInterval int, isFirstRound bool) time.Time {
	if isFirstRound {
		// 第一次執行後，對齊到下一個整分鐘
		secondsToAlign := 60 - now.Second()
		if secondsToAlign > 0 {
			return now.Add(time.Duration(secondsToAlign) * time.Second)
		}
		return now.Add(time.Duration(checkInterval) * time.Minute)
	}

	// 後續執行：對齊到檢查間隔的倍數
	currentMinute := now.Minute()
	minutesUntilNext := checkInterval - (currentMinute % checkInterval)
	if minutesUntilNext == 0 {
		minutesUntilNext = checkInterval
	}

	// 使用 Add 而不是手動計算，避免跨小時問題
	alignedTime := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, time.Local)
	return alignedTime.Add(time.Duration(minutesUntilNext) * time.Minute)
}

func runDownload(cfg *Config, logWriter io.Writer) error {
	// 1. Check global time range
	if cfg.AllowedTimeRange != "" {
		within, err := isWithinTimeRange(cfg.AllowedTimeRange)
		if err != nil {
			return fmt.Errorf("check global time range: %w", err)
		}
		if !within {
			log.Printf("目前時間不在全域允許範圍內 (%s)，跳過所有任務任務", cfg.AllowedTimeRange)
			return nil
		}
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("Connecting to %s ...", addr)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.Host,
	}

	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(10 * time.Second),
		ftp.DialWithDebugOutput(logWriter),
	}
	if cfg.DisableMLSD {
		dialOptions = append(dialOptions, ftp.DialWithDisabledMLSD(true))
	}

	if cfg.UseImplicitTLS {
		dialOptions = append(dialOptions, ftp.DialWithTLS(tlsConfig))
	} else {
		dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
	}

	// 使用重試機制連線
	client, err := connectWithRetry(cfg, addr, dialOptions, logWriter)
	if err != nil {
		return err
	}
	defer func() {
		if quitErr := client.Quit(); quitErr != nil {
			log.Printf("Error closing FTP connection: %v", quitErr)
		}
	}()

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

	// 檢查旗標檔案（如果啟用）
	if cfg.CheckFlagFile && cfg.FlagFileName != "" {
		log.Printf("🚩 檢查旗標檔案: %s", cfg.FlagFileName)
		flagPath := cfg.FlagFileName
		if cfg.RemoteDir != "" {
			flagPath = combineRemotePath(cfg.RemoteDir, cfg.FlagFileName)
		}
		_, err := client.FileSize(flagPath)
		if err != nil {
			log.Printf("⚠️  旗標檔案 %s 不存在或無法存取，跳過所有下載", cfg.FlagFileName)
			log.Printf("   錯誤: %v", err)
			return nil
		}
		log.Printf("✓ 旗標檔案 %s 存在，繼續下載流程", cfg.FlagFileName)
	}

	entries, err := client.NameList("")
	if err != nil {
		return fmt.Errorf("list files: %w", err)
	}

	// 根據 debug_list 設定決定是否顯示檔案清單
	if cfg.DebugList {
		log.Printf("")
		log.Printf("════════════════════════════════════════════════")
		log.Printf("📂 遠端目錄檔案清單 (%d 個檔案):", len(entries))
		log.Printf("════════════════════════════════════════════════")
		for _, name := range entries {
			log.Printf("   %s", name)
		}
		log.Printf("════════════════════════════════════════════════")
		log.Printf("")
	} else {
		log.Printf("📂 遠端目錄檔案總數: %d 個", len(entries))
		log.Printf("")
	}

	downloadCount := 0
	skippedCount := 0
	errorCount := 0
	checkedCount := 0
	downloadedFiles := []string{} // 追蹤已下載的檔案名稱

	if len(cfg.FileNames) > 0 {
		log.Println("🔍 開始檢查設定檔中指定的檔案...")
		log.Println("")
		for i, mapping := range cfg.FileNames {
			// Check group level time range
			if mapping.AllowedTimeRange != "" {
				within, err := isWithinTimeRange(mapping.AllowedTimeRange)
				if err != nil {
					log.Printf("Warning: Error checking time range for group %d: %v", i, err)
					continue
				}
				if !within {
					log.Printf("⏰ 群組 %d: 目前時間不在允許範圍內 (%s)，跳過此群組任務", i, mapping.AllowedTimeRange)
					continue
				}
				log.Printf("✓ 群組 %d: 符合時間範圍 (%s)", i, mapping.AllowedTimeRange)
			}

			basePath := strings.TrimSpace(mapping.RemotePath)

			// 1. 處理明確指定的檔案 (Files)
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

				log.Printf("🔎 檢查檔案: %s", remoteFileName)
				checkedCount++

				// 套用篩選規則 (特定檔案僅檢查是否被排除)
				isExcluded := false
				for _, exclude := range mapping.ExcludeFiles {
					if strings.EqualFold(remoteFileName, exclude) {
						isExcluded = true
						break
					}
				}
				if isExcluded {
					log.Printf("Skipping %s: excluded by rules", remoteFileName)
					continue
				}

				// 套用批次改名 (如果沒有明確指定本地檔名)
				if remoteFileName == localFileName {
					localFileName = applyFileNameRename(remoteFileName, &mapping)
				}

				remotePath := combineRemotePath(basePath, remoteFileName)
				downloaded, err := downloadFile(client, cfg, remotePath, localFileName)
				if err != nil {
					log.Printf("Error downloading %s: %v", remotePath, err)
					errorCount++
					continue
				}
				if downloaded {
					downloadCount++
					downloadedFiles = append(downloadedFiles, localFileName)
				} else {
					skippedCount++
				}
			}

			// 2. 處理其它篩選方式 (Pattern, Prefix, Suffix)
			// 如果沒有指定單一檔案，或者指定了篩選模式，則掃描目錄
			if len(mapping.FilePatterns) > 0 || len(mapping.IncludePrefixes) > 0 || len(mapping.IncludeSuffixes) > 0 {
				currentEntries := entries
				// 如果該群組有指定 remote_path 且與全域不同，則試著重新取得該路徑的檔案清單
				if basePath != "" && basePath != cfg.RemoteDir {
					log.Printf("Fetching file list for group %d remote path: %s", i, basePath)
					newEntries, err := client.NameList(basePath)
					if err == nil {
						// 處理可能的路徑格式，只取最後一個名稱
						currentEntries = nil
						for _, e := range newEntries {
							e = strings.TrimSpace(e)
							if e == "" {
								continue
							}
							nameOnly := e
							if lastDot := strings.LastIndex(e, "."); lastDot >= 0 {
								nameOnly = e[lastDot+1:]
							} else if lastSlash := strings.LastIndex(e, "/"); lastSlash >= 0 {
								nameOnly = e[lastSlash+1:]
							}
							currentEntries = append(currentEntries, nameOnly)
						}
					} else {
						log.Printf("Warning: Cannot list files for %s: %v. Using global list.", basePath, err)
					}
				}

				for _, entryName := range currentEntries {
					if entryName == "." || entryName == ".." {
						continue
					}

					// 排除掉已經在 Files 清單中處理過的遠端檔案
					alreadyHandled := false
					for _, fs := range mapping.Files {
						rf := fs
						if idx := strings.Index(fs, ":"); idx >= 0 {
							rf = strings.TrimSpace(fs[:idx])
						}
						if strings.EqualFold(entryName, rf) {
							alreadyHandled = true
							break
						}
					}
					if alreadyHandled {
						continue
					}

					if matchFileName(entryName, &mapping) {
						log.Printf("🔎 檢查檔案: %s", entryName)
						checkedCount++
						localFileName := applyFileNameRename(entryName, &mapping)
						remotePath := combineRemotePath(basePath, entryName)
						downloaded, err := downloadFile(client, cfg, remotePath, localFileName)
						if err != nil {
							log.Printf("Error downloading %s: %v", remotePath, err)
							errorCount++
							continue
						}
						if downloaded {
							downloadCount++
							downloadedFiles = append(downloadedFiles, localFileName)
						} else {
							skippedCount++
						}
					}
				}
			}
		}
	} else {
		log.Println("🔍 掃描所有遠端檔案...")
		log.Println("")
		for _, name := range entries {
			if name == "." || name == ".." {
				continue
			}

			log.Printf("🔎 檢查檔案: %s", name)
			checkedCount++
			downloaded, err := downloadFile(client, cfg, name, name)
			if err != nil {
				log.Printf("Error downloading %s: %v", name, err)
				errorCount++
				continue
			}
			if downloaded {
				downloadCount++
				downloadedFiles = append(downloadedFiles, name)
			} else {
				skippedCount++
			}
		}
	}

	log.Printf("")
	log.Printf("════════════════════════════════════════════════")
	log.Printf("📊 本次檢查結果統計:")
	log.Printf("════════════════════════════════════════════════")
	log.Printf("  🔎 檢查檔案總數: %d 個", checkedCount)
	if downloadCount > 0 {
		log.Printf("  ✅ 新下載檔案: %d 個", downloadCount)
		log.Printf("")
		log.Printf("  📥 下載的檔案列表:")
		for i, fileName := range downloadedFiles {
			log.Printf("     %d. %s", i+1, fileName)
		}
	} else {
		log.Printf("  ℹ️  新下載檔案: 0 個 (無新檔)")
	}
	if skippedCount > 0 {
		log.Printf("  ⊘  檔案未更新 (已跳過): %d 個", skippedCount)
	}
	if errorCount > 0 {
		log.Printf("  ⚠️  下載失敗: %d 個", errorCount)
	}
	log.Printf("════════════════════════════════════════════════")

	return nil
}

func main() {
	configPath := flag.String("config", "config.properties", "Path to configuration file")
	hostFlag := flag.String("host", "", "FTP server host (direct mode or override)")
	portFlag := flag.String("port", "21", "FTP server port")
	userFlag := flag.String("user", "", "FTP username (direct mode or override)")
	passFlag := flag.String("pass", "", "FTP password (direct mode or override)")
	remoteDirFlag := flag.String("remote-dir", "", "Remote directory to change into before downloading")
	remoteBaseFlag := flag.String("remote-base", "", "Remote path prefix prepended to each -file entry (direct mode)")
	localDirFlag := flag.String("local-dir", "", "Local download directory override")
	logDirFlag := flag.String("log-dir", "", "Log directory override")
	implicitFlag := flag.Bool("implicit-tls", false, "Use implicit TLS")
	checkFlagFileFlag := flag.Bool("check-flag-file", false, "Check for existence of a flag file before downloading")
	flagFileNameFlag := flag.String("flag-file-name", "DATCLOSE", "Name of the flag file to check")
	insecureFlag := flag.Bool("insecure-skip-verify", false, "Skip TLS certificate verification")
	sourceEncFlag := flag.String("source-encoding", "", "Source encoding name")
	targetEncFlag := flag.String("target-encoding", "", "Target encoding name")
	debugEncodingFlag := flag.Bool("debug-encoding", false, "Enable encoding debug output")
	skipHeaderFlag := flag.Int("skip-header-bytes", 0, "Number of header bytes to skip (-1 filters control bytes)")
	guardianAddCRLFFlag := flag.Bool("guardian-add-crlf", true, "Append CRLF when stripping Guardian blocks")
	rawDownloadFlag := flag.Bool("raw-download", false, "Download files without any processing (preserve exact binary content)")
	splitPrefixesFlag := flag.String("split-prefixes", "", "Comma-separated list of file prefixes to split (e.g., TCD,TSC)")
	allowedTimeRangeFlag := flag.String("allowed-time-range", "", "Allowed time range for download (HH:mm-HH:mm)")
	monitorModeFlag := flag.Bool("monitor-mode", false, "Enable continuous monitor mode")
	checkIntervalFlag := flag.Int("check-interval", 30, "Check interval in minutes for monitor mode (default: 30)")
	stopTimeFlag := flag.String("stop-time", "", "Auto stop time for monitor mode (format: HH:mm, e.g., 18:00)")

	var filesFlag fileSpecList
	flag.Var(&filesFlag, "file", "Remote file specification remote[:local]; repeat for multiple files (direct mode)")

	flag.Parse()

	// 設置控制台以支援 UTF-8 輸出
	setupConsoleForUTF8()

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
			UseImplicitTLS:     *implicitFlag,
			InsecureSkipVerify: *insecureFlag,
			SourceEncoding:     strings.TrimSpace(*sourceEncFlag),
			TargetEncoding:     strings.TrimSpace(*targetEncFlag),
			DebugEncoding:      *debugEncodingFlag,
			SkipHeaderBytes:    *skipHeaderFlag,
			CheckFlagFile:      *checkFlagFileFlag,
			FlagFileName:       *flagFileNameFlag,
			GuardianAddCRLF:    *guardianAddCRLFFlag,
			RawDownload:        *rawDownloadFlag,
			AllowedTimeRange:   *allowedTimeRangeFlag,
		}

		if *splitPrefixesFlag != "" {
			prefixes := strings.Split(*splitPrefixesFlag, ",")
			for _, p := range prefixes {
				p = strings.TrimSpace(p)
				if p != "" {
					cfg.SplitFilePrefixes = append(cfg.SplitFilePrefixes, p)
				}
			}
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
	if overrides["check-flag-file"] {
		cfg.CheckFlagFile = *checkFlagFileFlag
	}
	if overrides["flag-file-name"] {
		cfg.FlagFileName = *flagFileNameFlag
	}
	if overrides["raw-download"] {
		cfg.RawDownload = *rawDownloadFlag
	}
	if overrides["allowed-time-range"] {
		cfg.AllowedTimeRange = *allowedTimeRangeFlag
	}
	if overrides["split-prefixes"] {
		cfg.SplitFilePrefixes = nil // Clear existing if overridden
		prefixes := strings.Split(*splitPrefixesFlag, ",")
		for _, p := range prefixes {
			p = strings.TrimSpace(p)
			if p != "" {
				cfg.SplitFilePrefixes = append(cfg.SplitFilePrefixes, p)
			}
		}
	}
	if overrides["monitor-mode"] {
		cfg.MonitorMode = *monitorModeFlag
	}
	if overrides["check-interval"] {
		cfg.CheckInterval = *checkIntervalFlag
	}
	if overrides["stop-time"] {
		cfg.StopTime = *stopTimeFlag
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\n下載失敗: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Port = strings.TrimSpace(cfg.Port)
	if cfg.Host == "" {
		return fmt.Errorf("host is not specified")
	}
	if cfg.Port == "" {
		cfg.Port = "21"
	}
	if cfg.LocalDir == "" {
		cfg.LocalDir = "./downloads"
	}

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
			file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("Error opening log file: %v", err)
			} else {
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

	// 監控模式
	if cfg.MonitorMode {
		log.Printf("=== 啟用監控模式 ===")
		log.Printf("檢查間隔: 每 %d 分鐘", cfg.CheckInterval)
		if cfg.StopTime != "" {
			log.Printf("自動停止時間: %s (每日)", cfg.StopTime)
		}
		if cfg.AllowedTimeRange != "" {
			log.Printf("允許下載時間範圍: %s", cfg.AllowedTimeRange)
		}
		log.Printf("==================")
		log.Printf("📌 第一次檢查將立即執行，之後的檢查將對齊到整分鐘")
		log.Printf("")

		round := 1
		for {
			// 檢查是否應該停止
			if shouldStop, reason := shouldStopNow(cfg); shouldStop {
				log.Printf(reason)
				return nil
			}

			log.Printf("\n╔════════════════════════════════════════════════════════════════╗")
			log.Printf("║ 監控循環 #%d - %s", round, time.Now().Format("2006-01-02 15:04:05"))
			log.Printf("╚════════════════════════════════════════════════════════════════╝")

			// 執行下載
			if err := runDownload(cfg, logWriter); err != nil {
				log.Printf("⚠ 下載過程發生錯誤: %v", err)
				log.Printf("將在 %d 分鐘後重試...", cfg.CheckInterval)
			} else {
				log.Printf("✓ 本次檢查完成")
			}

			// 再次檢查是否應該停止
			if shouldStop, reason := shouldStopNow(cfg); shouldStop {
				log.Printf(reason)
				return nil
			}

			// 計算下次檢查時間
			now := time.Now()
			nextCheck := calculateNextCheckTime(now, cfg.CheckInterval, round == 1)
			waitDuration := nextCheck.Sub(now)

			if round == 1 {
				log.Printf("⏰ 首次執行完成，對齊到整分鐘...")
				log.Printf("   目前時間: %s", now.Format("15:04:05"))
				log.Printf("   對齊時間: %s", nextCheck.Format("15:04:00"))
				log.Printf("   等待 %v 後開始週期性檢查", waitDuration.Round(time.Second))
			} else {
				log.Printf("⏰ 下次檢查時間: %s (等待 %v)",
					nextCheck.Format("2006-01-02 15:04:00"),
					waitDuration.Round(time.Second))
			}

			time.Sleep(waitDuration)
			round++
		}
	}

	return runDownload(cfg, logWriter)
}
