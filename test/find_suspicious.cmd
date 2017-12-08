@echo off
setlocal enableextensions
set input=%~dp0result
@del /Q %input%\*.susp
for /r %input% %%f in (*.*) do call :process "%%f"
endlocal
goto :eof

:: finds suspicious records in log
:process
set filename=%~dp1%~n1.susp
findstr /E /L /N "Y|" %1 >%filename%
set size=0
call :filesize %filename%
:: remove suspicious file if it is empty
if %size% EQU 0 @del /Q %filename%
goto :eof

:: get file size
:filesize
set size=%~z1
goto :eof