:: %1 - path to the folder with dumps
@echo off
setlocal enableextensions
set output="result"
if not exist %output% mkdir %output%
@del /Q %output%\*.*
for /r %1 %%f in (*.dmp) do call :process "%%f" %output%
endlocal
goto :eof

:process
set log=%~dp0%~nx2\%~nx1.txt
powershell .\test_one_dump.ps1 -Dump %1 -Log %log% -Exe ntkd.exe -Script wa_test_script_ntkd.txt
goto :eof