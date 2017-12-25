:: %1 - path to store the log
@echo off
setlocal enableextensions
set log=%1
powershell .\test_live.ps1 -Log %log% -Exe ntkd.exe -Script wa_test_script_ntkd.txt
goto :eof