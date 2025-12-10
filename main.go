package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jlaffaye/ftp"
)

// Config 定義設定檔結構
type Config struct {
	Host               string `json:"host"`
	Port               string `json:"port"`
	User               string `json:"user"`
	Pass               string `json:"pass"`
	RemoteDir          string `json:"remote_dir"`
	LocalDir           string `json:"local_dir"`
	LogDir             string `json:"log_dir"`
	UseImplicitTLS     bool   `json:"use_implicit_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
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

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	// 定義命令列參數，只保留設定檔路徑
	configFile := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// 讀取設定檔
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("Error loading config file '%s': %v", *configFile, err)
		log.Println("Please ensure config.json exists and is valid.")
		pause()
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
		pause()
		os.Exit(1)
	}
	defer c.Quit()

	log.Println("Connected. Logging in...")

	// 登入
	if err := c.Login(config.User, config.Pass); err != nil {
		log.Printf("Error logging in: %v", err)
		pause()
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
			pause()
			os.Exit(1)
		}
		log.Printf("Changed directory to %s", config.RemoteDir)
	}

	// 列出檔案 (使用 NameList 以提高相容性，特別是針對 Tandem/NonStop 系統)
	files, err := c.NameList("")
	if err != nil {
		log.Printf("Error listing files: %v", err)
		pause()
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
		pause()
		os.Exit(1)
	}

	log.Printf("Found %d files. Starting download...", len(files))

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
		}
	}

	log.Println("All tasks completed.")
	pause()
}
