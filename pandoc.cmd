@echo off
@del /Q README.html
%LOCALAPPDATA%\Pandoc\pandoc.exe -o README.html -f markdown -t html README.md