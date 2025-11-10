#!/bin/bash

# EDR Log Processing System - Startup Script
# This script starts all components of the system

echo "=================================="
echo "EDR Log Processing System"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

# Check if Node.js is installed  
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js is not installed. Please install Node.js 16 or higher.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites check passed${NC}"
echo ""

# Step 1: Process logs
echo -e "${YELLOW}Step 1: Processing logs and applying rules...${NC}"
cd "$(dirname "$0")"
python3 app/server/enhanced_server.py

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Log processing completed${NC}"
else
    echo -e "${RED}✗ Log processing failed${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Starting FastAPI backend...${NC}"
echo "The API will start at http://localhost:8000"
echo "Press Ctrl+C in this terminal to stop the API server"
echo ""

# Start FastAPI in the background or foreground based on preference
python3 app/server/api_server.py &
API_PID=$!

# Give API time to start
sleep 3

echo ""
echo -e "${YELLOW}Step 3: Starting React frontend...${NC}"
echo "The UI will open at http://localhost:3000"
echo "Press Ctrl+C to stop all services"
echo ""

# Change to frontend directory and start React
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    npm install
fi

# Start React (this will block)
npm start

# Cleanup: When React stops, also stop the API
kill $API_PID 2>/dev/null

echo ""
echo -e "${GREEN}All services stopped${NC}"
