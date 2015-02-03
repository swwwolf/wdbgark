:: %1 - x64 or x86
:: %2 - path to dump file
:: %3 - log file name
@echo off
setlocal enableextensions
set command="$$>a<%~dp0wa_test_script.txt"
start %WDKDIR%\Debuggers\%1\windbg.exe -z %2 -logo %3 -c %command%
endlocal