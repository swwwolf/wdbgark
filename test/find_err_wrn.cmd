@echo off
set input=%~dp0result
@del /Q %input%\*.txt.err
setlocal enableextensions
for /r %input% %%f in (*.*) do call :process "%%f"
endlocal
goto :eof

:process
echo %1
findstr /B /L /N "[?] [-]" %1 >%~1.err
goto :eof