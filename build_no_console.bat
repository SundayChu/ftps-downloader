@echo off
REM Build FTPS Downloader without console window

echo Building ftps-downloader.exe without console window...

REM Build with -H=windowsgui flag to hide console window
go build -ldflags="-H=windowsgui" -o ftps-downloader.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo Build successful! ftps-downloader.exe created.
    echo This executable will run in background without showing a window.
) else (
    echo Build failed!
)

pause
