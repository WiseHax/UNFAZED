@echo off
chcp 65001 >nul
title UNFAZED - Live Logs

:loop
cls
echo [Live Logs - Press CTRL+C to stop]
echo.
if exist logs\unfazed.log (
    type logs\unfazed.log
) else (
    echo [!] logs\unfazed.log not found. Waiting...
)
timeout /t 2 >nul
goto loop
