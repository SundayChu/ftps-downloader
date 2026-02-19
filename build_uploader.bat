@echo off
REM Build FTPS Uploader

echo Building ftps-uploader.exe...

REM Build with -H=windowsgui flag if you want to hide console window
go build -o ftps-uploader.exe ./cmd/uploader

if %ERRORLEVEL% EQU 0 (
    echo Build successful! ftps-uploader.exe created.
) else (
    echo Build failed!
)

pause
