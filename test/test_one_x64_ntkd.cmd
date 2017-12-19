:: %1 - path to the dump file
:: %2 - path to store the log
@echo off
setlocal enableextensions
set log=%2\%~nx1.txt
powershell .\test_one_dump.ps1 -Dump %1 -Log %log% -Exe ntkd.exe -Script wa_test_script_ntkd.txt
goto :eof