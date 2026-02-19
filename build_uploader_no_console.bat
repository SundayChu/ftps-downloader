@echo off
REM Build FTPS Uploader without console window

echo Building ftps-uploader.exe without console window...

REM Build with -H=windowsgui flag to hide console window
go build -ldflags="-H=windowsgui" -o ftps-uploader-hidden.exe ./cmd/uploader

if %ERRORLEVEL% EQU 0 (
    echo Build successful! ftps-uploader-hidden.exe created.
    echo This executable will run in background without showing a window.
) else (
    echo Build failed!
)

pause
