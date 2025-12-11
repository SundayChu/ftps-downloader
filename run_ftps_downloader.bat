@echo off
REM FTPS Downloader Batch Script
REM This script is designed to be called by Windows Task Scheduler
REM Note: This will show a console window. Use run_ftps_downloader_hidden.vbs for no window.

REM Change to the directory where the executable is located
cd /d "%~dp0"

REM Run the FTPS downloader
ftps-downloader.exe -config="config.properties"

REM Exit with the error code from the executable
exit /b %ERRORLEVEL%
