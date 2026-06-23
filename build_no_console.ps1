# Build FTPS Downloader without console window

$ExeName = "ftps-downloader.exe"

Write-Host "Building $ExeName without console window..." -ForegroundColor Cyan

function Build-Downloader {
    go build -ldflags="-H=windowsgui" -o $ExeName ./cmd/downloader
    return $LASTEXITCODE
}

# 嘗試編譯
$result = Build-Downloader

if ($result -eq 0) {
    Write-Host "Build successful! $ExeName created." -ForegroundColor Green
    Write-Host "This executable will run in background without showing a window." -ForegroundColor Green
} else {
    # 編譯失敗，嘗試刪除舊檔案
    Write-Host "Build failed, trying to remove old executable..." -ForegroundColor Yellow
    
    if (Test-Path $ExeName) {
        try {
            Remove-Item $ExeName -Force -ErrorAction Stop
            Write-Host "Old executable removed. Retrying build..." -ForegroundColor Yellow
            
            $result = Build-Downloader
            if ($result -eq 0) {
                Write-Host "Build successful! $ExeName created." -ForegroundColor Green
                Write-Host "This executable will run in background without showing a window." -ForegroundColor Green
            } else {
                Write-Host "Build failed!" -ForegroundColor Red
            }
        } catch {
            Write-Host "ERROR: Cannot delete $ExeName. The program may be running." -ForegroundColor Red
            Write-Host "Please close the program and try again." -ForegroundColor Red
        }
    } else {
        Write-Host "Build failed for other reasons." -ForegroundColor Red
    }
}
