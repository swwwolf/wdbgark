@echo off
setlocal enableextensions
set input=%~dp0result
@del /Q %input%\*.txt.err
for /r %input% %%f in (*.*) do call :process "%%f"
endlocal
goto :eof

:process
echo %1
findstr /B /L /N "[?] [-]" %1 >%~1.err
goto :eof