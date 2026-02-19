package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// loadConfig 從指定路徑載入設定檔
func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{
		Port:               "21",
		LocalDir:           "./downloads",
		FileNames:          make([]PathMapping, 0),
		GuardianAddCRLF:    true,
		CheckFlagFile:      false,
		FlagFileName:       "DATCLOSE",
		FlagFilePath:       "",
		AutoDeleteFlagFile: true,
		CheckInterval:      30,
		DisableMLSD:        true,
		CompareByModTime:   true,
		MaxRetries:         3,
		RetryDelay:         5,

	scanner := bufio.NewScanner(file)
	fileItems := make(map[string]string)
	patternItems := make(map[string]string)
	prefixItems := make(map[string]string)
	suffixItems := make(map[string]string)
	excludeItems := make(map[string]string)
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

		// 移除行內註解 (空白 + # 或 空白 + //)
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		if idx := strings.Index(value, " //"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}

		// 移除 Windows 路徑不合法字元 (若剛好被當成檔名的一部分)
		if strings.ContainsAny(value, "#") && !strings.HasPrefix(key, "pass") {
			if idx := strings.Index(value, "#"); idx >= 0 {
				value = strings.TrimSpace(value[:idx])
			}
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
		case "check_flag_file":
			cfg.CheckFlagFile = (value == "true")
		case "flag_file_name":
			cfg.FlagFileName = value
		case "flag_file_path":
			cfg.FlagFilePath = value
		case "auto_delete_flag_file":
			cfg.AutoDeleteFlagFile = (value == "true")
		case "raw_download":
			cfg.RawDownload = (value == "true")
		case "allowed_time_range":
			cfg.AllowedTimeRange = value
		case "split_file_prefixes":
			prefixes := strings.Split(value, ",")
			for _, p := range prefixes {
				p = strings.TrimSpace(p)
				if p != "" {
					cfg.SplitFilePrefixes = append(cfg.SplitFilePrefixes, p)
				}
			}
		case "skip_if_exists":
			cfg.SkipIfExists = (value == "true")
		case "compare_by_modtime":
			cfg.CompareByModTime = (value == "true")
		case "force_download":
			cfg.ForceDownload = (value == "true")
		case "monitor_mode":
			cfg.MonitorMode = (value == "true")
		case "check_interval":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.CheckInterval = n
			}
		case "stop_time":
			cfg.StopTime = value
		case "debug_list":
			cfg.DebugList = (value == "true")
		case "separate_file_log":
			cfg.SeparateFileLog = (value == "true")
		case "disable_mlsd":
			cfg.DisableMLSD = (value == "true")
		case "max_retries":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.MaxRetries = n
			}
		case "retry_delay":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.RetryDelay = n
			}
		default:
			if strings.HasPrefix(key, "file_names.") {
				tokens := strings.Split(key, ".")
				if len(tokens) >= 3 {
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

					if tokens[2] == "remote_path" {
						pathMappings[pathIdx].RemotePath = value
					} else if tokens[2] == "local_path" {
						pathMappings[pathIdx].LocalPath = value
					} else if tokens[2] == "allowed_time_range" {
						pathMappings[pathIdx].AllowedTimeRange = value
					} else if tokens[2] == "check_flag_file" {
						pathMappings[pathIdx].CheckFlagFile = (value == "true")
					} else if tokens[2] == "flag_file_name" {
						pathMappings[pathIdx].FlagFileName = value
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
						// 格式: .5920:.txt (舊後綴:新後綴)
						parts := strings.SplitN(value, ":", 2)
						if len(parts) == 2 {
							oldSuffix := strings.TrimSpace(parts[0])
							newSuffix := strings.TrimSpace(parts[1])
							pathMappings[pathIdx].SuffixRename[oldSuffix] = newSuffix
						}
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	maxIdx := 100
	for pathIdx := 0; pathIdx < maxIdx; pathIdx++ {
		if mapping, exists := pathMappings[pathIdx]; exists && mapping != nil {
			for fileIdx := 0; fileIdx < 100; fileIdx++ {
				mapKey := fmt.Sprintf("%d.%d", pathIdx, fileIdx)
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

// isWithinTimeRange 檢查目前時間是否在指定的範圍內
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

	// 處理跨午夜的時間範圍 (例如: 22:00-04:00)
	if end.Before(start) {
		if now.Before(start) {
			start = start.AddDate(0, 0, -1)
		} else {
			end = end.AddDate(0, 0, 1)
		}
	}

	return now.After(start) && now.Before(end), nil
}

// matchFileName 檢查檔案名稱是否符合指定的規則
func matchFileName(fileName string, mapping *PathMapping) bool {
	// 如果在排除清單中，直接返回 false
	for _, exclude := range mapping.ExcludeFiles {
		if strings.EqualFold(fileName, exclude) {
			return false
		}
	}

	// 如果有指定 patterns，檢查是否符合
	if len(mapping.FilePatterns) > 0 {
		matched := false
		for _, pattern := range mapping.FilePatterns {
			// 使用 filepath.Match 進行萬用字元匹配
			if m, _ := filepath.Match(strings.ToUpper(pattern), strings.ToUpper(fileName)); m {
				matched = true
				break
			}
		}
		if !matched {
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
