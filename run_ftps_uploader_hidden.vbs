Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Get the directory where this VBS file is located
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Change to the script directory
WshShell.CurrentDirectory = scriptDir

' Build and run via batch script (hidden window)
commandLine = "cmd.exe /c """ & scriptDir & "\run_ftps_uploader.bat"""
WshShell.Run commandLine, 0, True

' Exit code will be returned to Task Scheduler
