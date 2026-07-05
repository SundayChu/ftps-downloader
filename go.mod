module ftps-downloader

go 1.26

replace github.com/jlaffaye/ftp => ./third_party/ftp

require (
	github.com/jlaffaye/ftp v0.2.1
	github.com/pkg/sftp v1.13.10
	golang.org/x/crypto v0.41.0
	golang.org/x/text v0.32.0
)

require (
	github.com/kr/fs v0.1.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
