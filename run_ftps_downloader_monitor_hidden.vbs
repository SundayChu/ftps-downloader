Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Get the directory where this VBS file is located
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Change to the script directory
WshShell.CurrentDirectory = scriptDir

' Setup log file with date
logsDir = scriptDir & "\logs"
If Not fso.FolderExists(logsDir) Then
    fso.CreateFolder(logsDir)
End If

' Format: ftps-downloader-vbs-YYYY-MM-DD.log
logDate = Year(Now) & "-" & Right("0" & Month(Now), 2) & "-" & Right("0" & Day(Now), 2)
logFile = logsDir & "\ftps-downloader-vbs-" & logDate & ".log"

' Function to write log with timestamp
Sub WriteLog(message)
    Dim logStream
    Set logStream = fso.OpenTextFile(logFile, 8, True)
    logStream.WriteLine Now & " " & message
    logStream.Close
End Sub

WriteLog "=========================================="
WriteLog "Starting FTPS Downloader (Monitor / Hidden Mode)"
WriteLog "=========================================="

' Run ftps-downloader.exe directly (hidden window)
' The Go program handles single instance control and all logging internally
commandLine = """" & scriptDir & "\ftps-downloader.exe"" -config """ & scriptDir & "\config.properties"""
WriteLog "Command: " & commandLine

' Run with window style 0 (hidden), wait for completion (True)
returnCode = WshShell.Run(commandLine, 0, True)

If returnCode = 0 Then
    WriteLog "FTPS Downloader completed successfully (Exit code: 0)"
Else
    WriteLog "FTPS Downloader failed (Exit code: " & returnCode & ")"
End If

WriteLog "=========================================="
WriteLog "VBS Script finished"
WriteLog "=========================================="

WScript.Quit returnCode
