:: %1 - x64 or x86
:: %2 - path to dump file
:: %3 - log file name
@echo off
set command="$$>a<%~dp0wa_test_script.txt %3"
start %WDKDIR%\Debuggers\%1\windbg.exe -z %2 -c %command%