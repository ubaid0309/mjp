@echo off
rem SecureMatrix: check (see README)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\check.ps1" %*
echo.
pause
