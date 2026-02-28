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
' Format: ftps-uploader-restart-YYYY-MM-DD.log
logDate = Year(Now) & "-" & Right("0" & Month(Now), 2) & "-" & Right("0" & Day(Now), 2)
logFile = logsDir & "\ftps-uploader-restart-" & logDate & ".log"

' Function to write log with timestamp
Sub WriteLog(message)
    Dim logStream
    Set logStream = fso.OpenTextFile(logFile, 8, True)
    logStream.WriteLine Now & " " & message
    logStream.Close
End Sub

' Clean up old log files (keep only last 3 days including today)
Sub CleanOldLogs()
    Dim file, cutoffDate
    ' Keep today and 2 days before (3 days total)
    cutoffDate = DateValue(DateAdd("d", -2, Now))
    
    For Each file In fso.GetFolder(logsDir).Files
        If LCase(fso.GetExtensionName(file.Name)) = "log" Then
            If file.DateLastModified < cutoffDate Then
                WriteLog "Deleting old log file: " & file.Name
                file.Delete
            End If
        End If
    Next
End Sub

' Check if ftps-uploader.exe is already running, terminate if so
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set colProcesses = objWMI.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'ftps-uploader.exe'")
processCount = 0
For Each objProcess In colProcesses
    processCount = processCount + 1
    WriteLog "Terminating existing ftps-uploader.exe (PID: " & objProcess.ProcessId & ")"
    objProcess.Terminate()
Next
Set colProcesses = Nothing
Set objWMI = Nothing

If processCount > 0 Then
    WriteLog "Terminated " & processCount & " running instance(s)"
    ' Wait a moment for process to fully terminate
    WScript.Sleep 500
End If

' Clean up old log files
CleanOldLogs

' Build and run via batch script (hidden window)
WriteLog "Starting ftps-uploader.exe..."
commandLine = "cmd.exe /c """ & scriptDir & "\run_ftps_uploader.bat"""
WshShell.Run commandLine, 0, True
WriteLog "ftps-uploader.exe execution completed"

' Exit code will be returned to Task Scheduler
