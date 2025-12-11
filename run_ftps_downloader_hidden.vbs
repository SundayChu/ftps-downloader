Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Get the directory where this VBS file is located
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Change to the script directory
WshShell.CurrentDirectory = scriptDir

' Run the executable in hidden mode (0 = hidden window)
WshShell.Run """" & scriptDir & "\ftps-downloader.exe"" -config=""config.properties""", 0, True

' Exit code will be returned to Task Scheduler
