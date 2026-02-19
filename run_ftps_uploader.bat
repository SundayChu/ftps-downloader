@echo off
REM FTPS Uploader Batch Script
cd /d "%~dp0"

REM Check if executable exists, if not build it
if not exist ftps-uploader.exe (
    echo Executable not found, building...
    go build -o ftps-uploader.exe uploader.go
    if %ERRORLEVEL% NEQ 0 (
        echo Build failed!
        exit /b %ERRORLEVEL%
    )
)

REM Run the FTPS uploader (console version for bat script)
ftps-uploader.exe -config="config.uploader.properties"

REM Exit with the error code from the executable
exit /b %ERRORLEVEL%
