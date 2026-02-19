@echo off
REM FTPS Downloader Batch Script
REM This script is designed to be called by Windows Task Scheduler
REM Note: This will show a console window. Use run_ftps_downloader_hidden.vbs for no window.

REM Change to the directory where the source code resides
cd /d "%~dp0"

REM Check if executable exists, if not build it
if not exist ftps-downloader.exe (
	echo Executable not found, building...
	go build -o ftps-downloader.exe main.go
	if %ERRORLEVEL% NEQ 0 (
		echo Build failed!
		exit /b %ERRORLEVEL%
	)
)

REM Run the FTPS downloader
ftps-downloader.exe -config="config.properties"

REM Exit with the error code from the executable
exit /b %ERRORLEVEL%
