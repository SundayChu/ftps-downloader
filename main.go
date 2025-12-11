package main

import (
	"bufio"
	"crypto/tls"
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
)

// PathMapping 定義路徑與檔案的對應關係
type PathMapping struct {
	RemotePath string
	Files      []string
}

// Config 定義設定檔結構
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
}

func pause() {
	fmt.Println("\nPress 'Enter' to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{
		FileNames: make([]PathMapping, 0),
	}
	
	// 用於臨時存儲解析的資料
	pathMappings := make(map[int]*PathMapping)
	fileItems := make(map[string]string) // key: "pathIndex.fileIndex"
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// 跳過空行和註解
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// 解析 key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// 解析基本設定
		switch key {
		case "host":
			config.Host = value
		case "port":
			config.Port = value
		case "user":
			config.User = value
		case "pass":
			config.Pass = value
		case "remote_dir":
			config.RemoteDir = value
		case "local_dir":
			config.LocalDir = value
		case "log_dir":
			config.LogDir = value
		case "use_implicit_tls":
			config.UseImplicitTLS = (value == "true")
		case "insecure_skip_verify":
			config.InsecureSkipVerify = (value == "true")
		default:
			// 解析 file_names 相關設定
			if strings.HasPrefix(key, "file_names.") {
				parts := strings.Split(key, ".")
				if len(parts) >= 3 {
					pathIdx, _ := strconv.Atoi(parts[1])
					
					if parts[2] == "remote_path" {
						if pathMappings[pathIdx] == nil {
							pathMappings[pathIdx] = &PathMapping{Files: make([]string, 0)}
						}
						pathMappings[pathIdx].RemotePath = value
					} else if parts[2] == "files" && len(parts) >= 4 {
						fileIdx, _ := strconv.Atoi(parts[3])
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
	
	// 組合 PathMapping 和檔案名稱
	for pathIdx := 0; pathIdx < len(pathMappings)+10; pathIdx++ {
		if pm, exists := pathMappings[pathIdx]; exists {
			for fileIdx := 0; fileIdx < 100; fileIdx++ {
				mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
				if fileName, exists := fileItems[mapKey]; exists {
					pm.Files = append(pm.Files, fileName)
				}
			}
			config.FileNames = append(config.FileNames, *pm)
		}
	}
	
	return config, nil
}

func main() {
	// 定義命令列參數，只保留設定檔路徑
	configFile := flag.String("config", "config.properties", "Path to configuration file")
	flag.Parse()

	// 讀取設定檔
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("Error loading config file '%s': %v", *configFile, err)
		log.Println("Please ensure config.json exists and is valid.")
		os.Exit(1)
	}

	// 設定預設下載目錄
	if config.LocalDir == "" {
		config.LocalDir = "./downloads"
	}

	// 設定日誌
	var logWriter io.Writer = os.Stdout
	if config.LogDir != "" {
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			log.Printf("Error creating log directory: %v", err)
		} else {
			logFileName := fmt.Sprintf("ftps-downloader-%s.log", time.Now().Format("2006-01-02"))
			logPath := filepath.Join(config.LogDir, logFileName)
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				log.Printf("Error opening log file: %v", err)
			} else {
				// 同時輸出到螢幕和檔案
				logWriter = io.MultiWriter(os.Stdout, logFile)
				log.SetOutput(logWriter)
				log.Printf("Logging to %s", logPath)
			}
		}
	}

	// 組合地址
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)
	log.Printf("Connecting to %s ...", addr)

	var c *ftp.ServerConn

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		ServerName:         config.Host,
	}

	// 連線設定
	// 準備連線選項，加入 Debug 輸出以便除錯
	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(10 * time.Second),
		ftp.DialWithDebugOutput(logWriter),
	}

	// 如果是 Implicit TLS (通常 Port 990)，直接建立 TLS 連線
	// 如果是 Explicit TLS (通常 Port 21)，先建立 TCP 連線再升級
	if config.UseImplicitTLS {
		dialOptions = append(dialOptions, ftp.DialWithTLS(tlsConfig))
	} else {
		dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
	}

	c, err = ftp.Dial(addr, dialOptions...)

	if err != nil {
		log.Printf("Error connecting to server: %v", err)
		os.Exit(1)
	}
	defer c.Quit()

	log.Println("Connected. Logging in...")

	// 登入
	if err := c.Login(config.User, config.Pass); err != nil {
		log.Printf("Error logging in: %v", err)
		os.Exit(1)
	}

	log.Println("Logged in successfully.")

	// 取得並顯示目前所在目錄
	if curDir, err := c.CurrentDir(); err == nil {
		log.Printf("Current remote directory: %s", curDir)
	} else {
		log.Printf("Error getting current directory: %v", err)
	}

	// 切換目錄
	if config.RemoteDir != "" {
		if err := c.ChangeDir(config.RemoteDir); err != nil {
			log.Printf("Error changing directory to %s: %v", config.RemoteDir, err)
			os.Exit(1)
		}
		log.Printf("Changed directory to %s", config.RemoteDir)
	}

	// 列出檔案 (使用 NameList 以提高相容性，特別是針對 Tandem/NonStop 系統)
	files, err := c.NameList("")
	if err != nil {
		log.Printf("Error listing files: %v", err)
		os.Exit(1)
	}

	// 顯示目錄內容
	log.Printf("Listing contents of current directory:")
	for _, name := range files {
		log.Printf(" - %s", name)
	}

	// 確保本地下載目錄存在
	if err := os.MkdirAll(config.LocalDir, 0755); err != nil {
		log.Printf("Error creating local directory: %v", err)
		os.Exit(1)
	}

	log.Printf("Found %d files. Starting download...", len(files))

	downloadCount := 0
	
	// 如果 config.FileNames 有指定檔案，優先下載這些檔案
	if len(config.FileNames) > 0 {
		log.Println("Downloading specified files from config...")
		for _, pathMap := range config.FileNames {
			basePath := strings.TrimSpace(pathMap.RemotePath)
			
			// 處理此路徑下的每個檔案
			for _, fileSpec := range pathMap.Files {
				fileSpec = strings.TrimSpace(fileSpec)
				if fileSpec == "" {
					continue
				}
				
				// 解析檔名格式: "遠端檔名:本地檔名" 或只有 "遠端檔名"
				var remoteFileName, localFileName string
				if idx := strings.Index(fileSpec, ":"); idx >= 0 {
					// 有指定本地檔名
					remoteFileName = strings.TrimSpace(fileSpec[:idx])
					localFileName = strings.TrimSpace(fileSpec[idx+1:])
					if localFileName == "" {
						// 如果本地檔名為空，使用遠端檔名
						localFileName = remoteFileName
					}
				} else {
					// 沒有指定本地檔名，使用遠端檔名
					remoteFileName = fileSpec
					localFileName = fileSpec
				}
				
				// 組合完整的遠端路徑（Guardian 系統使用點作為分隔符）
				var fullRemotePath string
				if basePath == "" {
					fullRemotePath = remoteFileName
				} else {
					// Guardian 系統使用點(.)作為路徑分隔符，不是反斜線
					if strings.HasSuffix(basePath, ".") {
						fullRemotePath = basePath + remoteFileName
					} else {
						fullRemotePath = basePath + "." + remoteFileName
					}
				}
				
				log.Printf("Downloading %s to %s ...", fullRemotePath, localFileName)
				
				// 下載檔案
				r, err := c.Retr(fullRemotePath)
				if err != nil {
					log.Printf("Error retrieving file %s: %v", fullRemotePath, err)
					continue
				}
				
				// 使用指定的本地檔名
				localPath := filepath.Join(config.LocalDir, localFileName)
				
				// 建立本地檔案
				f, err := os.Create(localPath)
				if err != nil {
					log.Printf("Error creating local file %s: %v", localPath, err)
					r.Close()
					continue
				}
				
				// 寫入內容
				n, err := io.Copy(f, r)
				r.Close()
				f.Close()
				
				if err != nil {
					log.Printf("Error writing file %s: %v", localPath, err)
				} else {
					log.Printf("Downloaded %s to %s (%d bytes)", fullRemotePath, localPath, n)
					downloadCount++
				}
			}
		}
	} else {
		// 原本的邏輯：從當前目錄下載所有檔案
		for _, name := range files {
			// 過濾掉 . 和 ..
			if name == "." || name == ".." {
				continue
			}

			log.Printf("Downloading %s ...", name)

			// 下載檔案
			r, err := c.Retr(name)
			if err != nil {
				log.Printf("Error retrieving file %s: %v", name, err)
				continue
			}

			// 建立本地檔案
			localPath := filepath.Join(config.LocalDir, name)
			f, err := os.Create(localPath)
			if err != nil {
				log.Printf("Error creating local file %s: %v", localPath, err)
				r.Close()
				continue
			}

			// 寫入內容
			n, err := io.Copy(f, r)
			r.Close()
			f.Close()

			if err != nil {
				log.Printf("Error writing file %s: %v", localPath, err)
			} else {
				log.Printf("Downloaded %s to %s (%d bytes)", name, localPath, n)
				downloadCount++
			}
		}
	}

	log.Printf("Download completed. %d file(s) downloaded.", downloadCount)
}
