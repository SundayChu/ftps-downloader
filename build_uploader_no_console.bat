@echo off
REM Build FTPS Uploader without console window

setlocal
set EXE_NAME=ftps-uploader-hidden.exe

echo Building %EXE_NAME% without console window...

:TRY_BUILD
REM Build with -H=windowsgui flag to hide console window
go build -ldflags="-H=windowsgui" -o %EXE_NAME% ./cmd/uploader

if %ERRORLEVEL% EQU 0 (
    echo Build successful! %EXE_NAME% created.
    echo This executable will run in background without showing a window.
    goto END
)

REM 編譯失敗，檢查是否因為檔案被鎖定
echo Build failed, trying to remove old executable...

if exist %EXE_NAME% (
    del /F %EXE_NAME% 2>nul
    if exist %EXE_NAME% (
        echo ERROR: Cannot delete %EXE_NAME%. The program may be running.
        echo Please close the program and try again.
        goto END
    )
    echo Old executable removed. Retrying build...
    goto TRY_BUILD
) else (
    echo Build failed for other reasons.
)

:END
pause
