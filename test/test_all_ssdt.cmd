:: %1 - path to the folder with logs
::@echo off
setlocal enableextensions
for /r %1 %%f in (*.dmp.txt) do call :process "%%f"
endlocal
goto :eof

:process
python pytest\check_ssdt_names.py %~1
goto :eof