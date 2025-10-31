@echo off

REM Change to the script's directory
cd /d "%~dp0"

REM Activate the Python virtual environment
call venv\Scripts\activate.bat

REM Run the main Python application
python main.py

pause