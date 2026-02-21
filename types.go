package main

// PathMapping 定義遠端路徑與檔案的對應關係
type PathMapping struct {
	RemotePath       string
	LocalPath        string // uploader 使用
	Files            []string
	FilePatterns     []string          // 支援萬用字元，例如: *.txt, TCD*, RYM??
	IncludePrefixes  []string          // 只處理符合前綴的檔案
	IncludeSuffixes  []string          // 只處理符合後綴的檔案
	ExcludeFiles     []string          // 排除的檔案名稱
	PrefixRename     map[string]string // 批次前綴重命名: {"TCD": "DATA"}
	SuffixRename     map[string]string // 批次後綴重命名: {".txt": ".dat"}
	AllowedTimeRange string            // 格式: "HH:mm-HH:mm", 例如 "02:00-05:00"
	CheckFlagFile    bool              // 是否檢查結帳檔（此路徑專用）
	FlagFileName     string            // 結帳檔名稱（此路徑專用）
}

// Config 程式設定結構
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
	SourceEncoding     string   // downloader 使用
	TargetEncoding     string   // downloader 使用
	DebugEncoding      bool     // downloader 使用
	SkipHeaderBytes    int      // downloader 使用
	GuardianAddCRLF    bool     // downloader 使用
	RawDownload        bool     // downloader 使用
	CheckFlagFile      bool     // downloader 使用（全局，已棄用）
	FlagFileName       string   // downloader 使用
	FlagFilePath       string   // DATCLOSE 專用下載路徑
	AutoDeleteFlagFile bool     // 程式結束時自動刪除 DATCLOSE
	SplitFilePrefixes  []string // downloader 使用
	AllowedTimeRange   string   // 全域時間範圍
	SkipIfExists       bool     // 如果本地檔案存在且較新則跳過下載
	CompareByModTime   bool     // 使用修改時間比對（預設使用大小）
	ForceDownload      bool     // 強制下載，忽略本地檔案狀態
	MonitorMode        bool     // 啟用監控模式
	CheckInterval      int      // 檢查間隔（分鐘）
	StopTime           string   // 自動停止時間（HH:mm）
	DebugList          bool     // 顯示 LIST 命令的詳細輸出
	SeparateFileLog    bool     // 為每個下載檔案建立獨立的 log 檔案
	LogRetentionDays   int      // 日誌保留天數（包含分檔日誌）
	DisableMLSD        bool     // 停用 MLSD，強制使用 LIST
	MaxRetries         int      // 連線失敗重試次數
	RetryDelay         int      // 重試延遲秒數
}
