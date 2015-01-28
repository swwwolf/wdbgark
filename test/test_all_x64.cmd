@echo off
set output="result"
if not exist %output% mkdir %output%
setlocal enableextensions
for /r %1 %%f in (*.dmp) do call :process "%%f" %output%
endlocal
goto :eof

:process
set log=%~nx2\%~nx1.txt
call test_one_dump.cmd x64 %1 %log%
goto :eof