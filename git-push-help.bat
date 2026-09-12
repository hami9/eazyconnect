@echo off
REM Usage: run from repository root. Edit commit message below or pass as arg.
set MSG=%1
if "%MSG%"=="" set MSG="Add eazyconnect prototype"
git add .
git commit -m %MSG%
git push origin HEAD
echo Done.
