# Build FTPS Downloader without console window

Write-Host "Building ftps-downloader.exe without console window..." -ForegroundColor Cyan

# Build with -H=windowsgui flag to hide console window
go build -ldflags="-H=windowsgui" -o ftps-downloader.exe main.go

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful! ftps-downloader.exe created." -ForegroundColor Green
    Write-Host "This executable will run in background without showing a window." -ForegroundColor Green
} else {
    Write-Host "Build failed!" -ForegroundColor Red
}
