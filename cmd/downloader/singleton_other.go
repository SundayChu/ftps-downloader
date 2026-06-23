//go:build !windows

package main

// ensureSingleInstance 在非 Windows 平台為空實作
// Linux/Unix 可改用 PID 檔案或 flock 實現，目前直接允許執行
func ensureSingleInstance() error {
	return nil
}
