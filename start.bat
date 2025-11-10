@echo off
REM EDR Log Processing System - Windows Startup Script
REM This script starts all components of the system on Windows

echo ==================================
echo EDR Log Processing System
echo ==================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed. Please install Node.js 16 or higher.
    pause
    exit /b 1
)

echo [OK] Prerequisites check passed
echo.

REM Step 1: Process logs
echo ========================================
echo Step 1: Processing logs and applying rules...
echo ========================================
python app\server\enhanced_server.py

if errorlevel 1 (
    echo [ERROR] Log processing failed
    pause
    exit /b 1
)

echo.
echo [OK] Log processing completed
echo.

REM Step 2: Start FastAPI backend in a new window
echo ========================================
echo Step 2: Starting FastAPI backend...
echo ========================================
echo The API will start at http://localhost:8000
echo A new window will open for the API server
echo.

start "EDR API Server" cmd /k python app\server\api_server.py

REM Give API time to start
timeout /t 5 /nobreak >nul

REM Step 3: Start React frontend in a new window
echo.
echo ========================================
echo Step 3: Starting React frontend...
echo ========================================
echo The UI will open at http://localhost:3000
echo A new window will open for the React server
echo.

REM Check if node_modules exists
if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies...
    cd frontend
    call npm install
    cd ..
)

start "EDR React Frontend" cmd /k "cd frontend && npm start"

echo.
echo ========================================
echo All services started!
echo ========================================
echo.
echo API Server: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo React UI: http://localhost:3000
echo.
echo Close the API and React windows to stop the services.
echo.
pause
