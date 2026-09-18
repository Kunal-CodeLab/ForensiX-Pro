@echo off
echo Starting ForensiX Pro...
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python and try again.
    pause
    exit /b 1
)

REM Run the GUI launcher
python launch_gui.py

REM If we get here, the application has closed
echo.
echo Application closed.
pause
