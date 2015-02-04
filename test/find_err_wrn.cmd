@echo off
setlocal enableextensions
set input=%~dp0result
@del /Q %input%\*.err
for /r %input% %%f in (*.*) do call :process "%%f"
for /r %input% %%f in (*.tmp) do call :whitelist "%%f"
@del /Q %input%\*.tmp
if exist %input%\*.err (
    echo Errors found!
    dir /b %input%\*.err
) else (
    echo Success!
)
endlocal
goto :eof

:: finds warnings and errors in log
:process
set filename=%~dp1%~n1.tmp
findstr /B /L /N /I "[?] [-]" %1 >%filename%
goto :eof

:: whitelist error from the !wa_checkmsr, coz we're testing dumps
:whitelist
set filename=%~dp1%~n1.err
findstr /V /L /I /C:"live kernel-mode only" %1 >%filename%
set size=0
call :filesize %filename%
:: remove error file if it is empty
if %size% EQU 0 @del /Q %filename%
goto :eof

:: get file size
:filesize
set size=%~z1
goto :eof