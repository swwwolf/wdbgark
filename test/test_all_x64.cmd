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
set log=%~nx2\%~nx1.txt
call test_one_dump.cmd x64 %1 %log%
goto :eof