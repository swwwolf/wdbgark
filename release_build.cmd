:: You should already have PowerShell installed. Minimum required version is 3.0.
:: Install Windows Management Framework.
:: %1 - version number (e.g. 1.5)
@echo off
:main
setlocal enableextensions
if [%1]==[] goto usage
set vs2012="c:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE\devenv.exe"
set output="%temp%\wdbgark.%1\"
set log="release_build.log"
call :create %output%

:: build using VS 2012 command line
:build
if exist %log% del /Q %log%
echo Cleaning Release-Win32
call %vs2012% wdbgark.sln /clean "Release|Win32" /out %log%
echo Cleaning Release-x64
call %vs2012% wdbgark.sln /clean "Release|x64" /out %log%
echo Building dummypdb Release-Win32
call %vs2012% wdbgark.sln /project dummypdb /rebuild "Release|Win32" /out %log%
echo Building dummypdb Release-x64
call %vs2012% wdbgark.sln /project dummypdb /rebuild "Release|x64" /out %log%
echo Building wdbgark Release-Win32
call %vs2012% wdbgark.sln /project wdbgark /rebuild "Release|Win32" /out %log%
echo Building wdbgark Release-x64
call %vs2012% wdbgark.sln /project wdbgark /rebuild "Release|x64" /out %log%
call :copy %output%
call :check %output%

:: zip copied files using PowerShell command
:zip
echo Zipping files
if exist wdbgark.%1.zip del /Q wdbgark.%1.zip
call :dequote output
set command="& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('%output%', 'wdbgark.%1.zip'); }"
powershell.exe -nologo -noprofile -command %command%
if not exist wdbgark.%1.zip (
    call :error
) else (
    echo Cleaning up temp files
    rmdir /Q /S %output%
    @echo Success!
)
endlocal
goto :eof

:: remove quotes
:dequote
for /f "delims=" %%A in ('echo %%%1%%') do set %1=%%~A
goto :eof

:: remove and recreate temp directory
:create
if exist %1 rmdir /Q /S %1
if not exist %1 mkdir %1
mkdir %1\x86\pdb
mkdir %1\x64\pdb
goto :eof

:: copy all files into temp directory
:copy
echo Copying files to %1
copy /A COPYING %1
copy /A README.md %1
copy /A README.html %1
copy /B Release\wdbgark.dll %1\x86
copy /B Release\wdbgark.pdb %1\x86\pdb
copy /B x64\Release\wdbgark.dll %1\x64
copy /B x64\Release\wdbgark.pdb %1\x64\pdb
goto :eof

:: check that copied files exists
:check
echo Checking files in %1
if not exist %1\COPYING call :error
if not exist %1\README.md call :error
if not exist %1\README.html call :error
if not exist %1\x86\wdbgark.dll call :error
if not exist %1\x86\pdb\wdbgark.pdb call :error
if not exist %1\x64\wdbgark.dll call :error
if not exist %1\x64\pdb\wdbgark.pdb call :error
goto :eof

:error
@echo Error!
exit 1

:usage
@echo Usage: %0 VersionNumber (e.g. "%~0 1.5")
exit 1