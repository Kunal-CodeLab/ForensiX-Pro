@echo off
title ForensiX Pro Setup
echo Checking for Python installation...

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python not found. Installing Python 3.11...
    curl -o python_installer.exe https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe
    start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    del python_installer.exe
    echo Python installed successfully.
) ELSE (
    echo Python is already installed.
)

echo Installing dependencies from requirements.txt...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo Setup completed successfully!
echo Launching ForensiX Pro...
python launch_gui.py

pause
