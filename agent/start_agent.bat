@echo off
REM Windows Security Log Collection Agent Launcher
REM This script starts the agent with proper error handling

echo ===============================================================
echo   Windows Security Log Collection Agent
echo ===============================================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This agent requires Administrator privileges!
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo Running with Administrator privileges... OK
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.8+ from: https://www.python.org
    echo.
    pause
    exit /b 1
)

echo Python found... OK
echo.

REM Check if dependencies are installed
python -c "import psutil; import watchdog" >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo.
)

echo Dependencies installed... OK
echo.

REM Start the agent
echo Starting agent...
echo.
python agent.py

REM If agent exits, pause to see any error messages
echo.
echo Agent stopped.
pause
