//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex  = kernel32.NewProc("CreateMutexW")
	procGetLastError = kernel32.NewProc("GetLastError")
)

// ensureSingleInstance 確保只有一個程式實例在執行
// 使用 Windows Mutex 機制，如果檢測到已有實例在執行，會終止舊實例
func ensureSingleInstance() error {
	mutexName, err := syscall.UTF16PtrFromString("Local\\FTPSDownloader_Mutex_Singleton")
	if err != nil {
		return fmt.Errorf("建立 Mutex 名稱失敗: %w", err)
	}

	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(mutexName)),
	)

	if ret == 0 {
		return fmt.Errorf("建立 Mutex 失敗: %w", err)
	}

	lastErr, _, _ := procGetLastError.Call()

	const ERROR_ALREADY_EXISTS = 183

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("【執行實例檢查】")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if lastErr == ERROR_ALREADY_EXISTS {
		log.Printf("⚠️  偵測到已有執行中的下載程式實例")
		log.Printf("正在終止舊的執行實例...")

		if err := killExistingDownloaderProcess(); err != nil {
			log.Printf("❌ 無法終止舊實例: %v", err)
			log.Printf("請手動關閉其他執行中的下載程式後重試")
			return fmt.Errorf("已有程式實例在執行中，且無法自動終止")
		}

		log.Printf("✓ 舊實例已終止，繼續執行新程式")
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Println()

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
	currentPID := os.Getpid()

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

		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}

		pidStr := strings.Trim(fields[1], "\" ")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		if pid == currentPID {
			continue
		}

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
		log.Printf("ℹ️  未找到需要終止的程式實例")
		return nil
	}

	return nil
}
