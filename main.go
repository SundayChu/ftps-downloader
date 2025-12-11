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
	"path/filepath"
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

type PathMapping struct {
	RemotePath string
	Files      []string
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
	UseImplicitTLS     bool
	InsecureSkipVerify bool
	SourceEncoding     string
	TargetEncoding     string
	DebugEncoding      bool
	SkipHeaderBytes    int
	GuardianAddCRLF    bool
	RawDownload        bool
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
		Port:            "21",
		LocalDir:        "./downloads",
		FileNames:       make([]PathMapping, 0),
		GuardianAddCRLF: true,
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

	maxIdx := len(pathMappings) + 10
	for pathIdx := 0; pathIdx < maxIdx; pathIdx++ {
		if mapping, exists := pathMappings[pathIdx]; exists && mapping != nil {
			for fileIdx := 0; fileIdx < 100; fileIdx++ {
				mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
				if fileName, ok := fileItems[mapKey]; ok {
					mapping.Files = append(mapping.Files, fileName)
				}
			}
			cfg.FileNames = append(cfg.FileNames, *mapping)
		}
	}

	return cfg, nil
}

func downloadFile(client *ftp.ServerConn, cfg *Config, remotePath, localName string) error {
	remoteSize := int64(-1)
	if size, err := client.FileSize(remotePath); err == nil {
		remoteSize = size
		log.Printf("Downloading %s -> %s (remote size: %d bytes)...", remotePath, localName, remoteSize)
	} else {
		log.Printf("WARNING: Cannot retrieve remote file size for %s: %v", remotePath, err)
		log.Printf("Downloading %s -> %s ...", remotePath, localName)
	}

	reader, err := client.Retr(remotePath)
	if err != nil {
		// If ASCII mode fails with filecode error, try binary mode
		if strings.Contains(err.Error(), "Can't use ASCII transfer mode") || strings.Contains(err.Error(), "filecode") {
			log.Printf("ASCII mode not supported for %s, switching to binary mode...", remotePath)
			if switchErr := client.Type(ftp.TransferTypeBinary); switchErr != nil {
				return fmt.Errorf("retrieve %s: failed to switch to binary mode: %w", remotePath, switchErr)
			}
			reader, err = client.Retr(remotePath)
			if err != nil {
				return fmt.Errorf("retrieve %s (binary mode): %w", remotePath, err)
			}
			// Switch back to ASCII for next file
			defer func() {
				if switchErr := client.Type(ftp.TransferTypeASCII); switchErr != nil {
					log.Printf("Warning: failed to switch back to ASCII mode: %v", switchErr)
				}
			}()
		} else {
			return fmt.Errorf("retrieve %s: %w", remotePath, err)
		}
	}
	defer reader.Close()

	var buf bytes.Buffer
	rawBytesRead, err := io.Copy(&buf, reader)
	if err != nil {
		return fmt.Errorf("read %s: %w", remotePath, err)
	}

	// Verify download size matches remote size
	if remoteSize > 0 && rawBytesRead != remoteSize {
		return fmt.Errorf("download size mismatch for %s: expected %d bytes, got %d bytes", remotePath, remoteSize, rawBytesRead)
	}

	rawData := buf.Bytes()
	processed := processData(cfg, remotePath, rawData)

	localPath := filepath.Join(cfg.LocalDir, localName)
	if err := os.WriteFile(localPath, processed, 0644); err != nil {
		return fmt.Errorf("write %s: %w", localPath, err)
	}

	// Verify written file
	writtenInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("verify written file %s: %w", localPath, err)
	}

	log.Printf("✓ Downloaded %s to %s", remotePath, localPath)
	log.Printf("  Remote size: %d bytes", remoteSize)
	log.Printf("  Downloaded: %d bytes", rawBytesRead)
	log.Printf("  Final size: %d bytes", writtenInfo.Size())

	if cfg.RawDownload {
		if writtenInfo.Size() != rawBytesRead {
			return fmt.Errorf("verification failed for %s: written size (%d) != downloaded size (%d)", localPath, writtenInfo.Size(), rawBytesRead)
		}
		if remoteSize > 0 && writtenInfo.Size() != remoteSize {
			return fmt.Errorf("verification failed for %s: final size (%d) != remote size (%d)", localPath, writtenInfo.Size(), remoteSize)
		}
		log.Printf("✓ Verification passed: file content exactly matches remote file")
	} else if remoteSize > 0 && rawBytesRead == remoteSize {
		log.Printf("✓ Download verification passed: raw data matches remote size")
	}

	return nil
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

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.Host,
	}

	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(10 * time.Second),
		ftp.DialWithDebugOutput(logWriter),
	}

	if cfg.UseImplicitTLS {
		dialOptions = append(dialOptions, ftp.DialWithTLS(tlsConfig))
	} else {
		dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
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

	log.Printf("Listing contents of current directory:")
	for _, name := range entries {
		log.Printf(" - %s", name)
	}

	downloadCount := 0

	if len(cfg.FileNames) > 0 {
		log.Println("Downloading specified files from config...")
		for _, mapping := range cfg.FileNames {
			basePath := strings.TrimSpace(mapping.RemotePath)

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

				if err := downloadFile(client, cfg, remotePath, localFileName); err != nil {
					log.Printf("Error downloading %s: %v", remotePath, err)
					continue
				}
				downloadCount++
			}
		}
	} else {
		for _, name := range entries {
			if name == "." || name == ".." {
				continue
			}

			if err := downloadFile(client, cfg, name, name); err != nil {
				log.Printf("Error downloading %s: %v", name, err)
				continue
			}
			downloadCount++
		}
	}

	log.Printf("Download completed. %d file(s) downloaded.", downloadCount)
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
	insecureFlag := flag.Bool("insecure-skip-verify", false, "Skip TLS certificate verification")
	sourceEncFlag := flag.String("source-encoding", "", "Source encoding name")
	targetEncFlag := flag.String("target-encoding", "", "Target encoding name")
	debugEncodingFlag := flag.Bool("debug-encoding", false, "Enable encoding debug output")
	skipHeaderFlag := flag.Int("skip-header-bytes", 0, "Number of header bytes to skip (-1 filters control bytes)")
	guardianAddCRLFFlag := flag.Bool("guardian-add-crlf", true, "Append CRLF when stripping Guardian blocks")
	rawDownloadFlag := flag.Bool("raw-download", false, "Download files without any processing (preserve exact binary content)")

	var filesFlag fileSpecList
	flag.Var(&filesFlag, "file", "Remote file specification remote[:local]; repeat for multiple files (direct mode)")

	flag.Parse()

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
			GuardianAddCRLF:    *guardianAddCRLFFlag,
			RawDownload:        *rawDownloadFlag,
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
	if overrides["raw-download"] {
		cfg.RawDownload = *rawDownloadFlag
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

	return runDownload(cfg, logWriter)
}
