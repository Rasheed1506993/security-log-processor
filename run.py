#!/usr/bin/env python3
"""
Universal launcher for EDR Log Processing System
Works on Windows, Linux, and macOS
Can be run directly from PyCharm
"""
import os
import sys
import time
import subprocess
import platform
from pathlib import Path

def check_command_exists(command):
    """Check if a command exists in PATH"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['where', command], 
                                  capture_output=True, 
                                  text=True,
                                  shell=True)
        else:
            result = subprocess.run(['which', command], 
                                  capture_output=True, 
                                  text=True)
        return result.returncode == 0
    except:
        return False

def is_port_in_use(port):
    """Check if a port is already in use"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def run_step_1_processing():
    """Step 1: Process logs and apply rules"""
    print("=" * 80)
    print(" " * 20 + "STEP 1: PROCESSING LOGS")
    print("=" * 80)
    
    script_path = Path(__file__).parent / "app" / "server" / "enhanced_server.py"
    
    result = subprocess.run([sys.executable, str(script_path)])
    
    if result.returncode != 0:
        print("\n❌ Processing failed!")
        return False
    
    print("\n✅ Processing completed successfully!")
    return True

def start_api_server():
    """Step 2: Start API server"""
    print("\n" + "=" * 80)
    print(" " * 20 + "STEP 2: STARTING API SERVER")
    print("=" * 80)
    
    if is_port_in_use(8000):
        print("⚠️  Port 8000 is already in use!")
        print("   API server might already be running.")
        response = input("   Kill existing process and restart? (y/n): ")
        if response.lower() != 'y':
            print("   Skipping API server start...")
            return None
        
        # Kill process on port 8000
        if platform.system() == "Windows":
            os.system('for /f "tokens=5" %a in (\'netstat -aon ^| find "8000" ^| find "LISTENING"\') do taskkill /F /PID %a')
        else:
            os.system('lsof -ti:8000 | xargs kill -9 2>/dev/null')
        time.sleep(2)
    
    script_path = Path(__file__).parent / "app" / "server" / "api_server.py"
    
    print("\n🚀 Starting API server on http://localhost:8000")
    print("   API Docs: http://localhost:8000/docs")
    print("   Press Ctrl+C in the API window to stop\n")
    
    # Start in new window based on OS
    if platform.system() == "Windows":
        # Windows - use start command
        cmd = f'start "EDR API Server" cmd /k python "{script_path}"'
        subprocess.Popen(cmd, shell=True)
    elif platform.system() == "Darwin":
        # macOS
        cmd = f'osascript -e \'tell app "Terminal" to do script "cd {Path(__file__).parent} && python {script_path}"\''
        subprocess.Popen(cmd, shell=True)
    else:
        # Linux
        terminals = ['gnome-terminal', 'xterm', 'konsole']
        for term in terminals:
            try:
                subprocess.Popen([term, '--', 'python3', str(script_path)])
                break
            except FileNotFoundError:
                continue
    
    print("⏳ Waiting for API server to start...")
    time.sleep(5)
    
    if is_port_in_use(8000):
        print("✅ API server started successfully!")
        return True
    else:
        print("⚠️  API server may not have started properly")
        return False

def start_react_frontend():
    """Step 3: Start React frontend"""
    print("\n" + "=" * 80)
    print(" " * 20 + "STEP 3: STARTING REACT FRONTEND")
    print("=" * 80)
    
    # Check if npm exists
    if not check_command_exists('npm'):
        print("\n❌ npm not found!")
        print("\n   Node.js is not installed or not in PATH.")
        print("\n   Please install Node.js from: https://nodejs.org")
        print("   Then restart this script.")
        print("\n   For now, you can still use the API at http://localhost:8000/docs")
        return False
    
    frontend_path = Path(__file__).parent / "frontend"
    
    # Check if node_modules exists
    if not (frontend_path / "node_modules").exists():
        print("\n📦 Installing frontend dependencies...")
        print("   This may take a few minutes...\n")
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['npm.cmd', 'install'], cwd=frontend_path, shell=True)
            else:
                result = subprocess.run(['npm', 'install'], cwd=frontend_path)
                
            if result.returncode != 0:
                print("\n❌ Failed to install dependencies!")
                return False
        except Exception as e:
            print(f"\n❌ Error installing dependencies: {e}")
            return False
    
    print("\n🚀 Starting React frontend on http://localhost:3000")
    print("   Press Ctrl+C in the React window to stop\n")
    
    # Start in new window based on OS
    if platform.system() == "Windows":
        cmd = f'start "EDR React Frontend" cmd /k "cd /d {frontend_path} && npm start"'
        subprocess.Popen(cmd, shell=True)
    elif platform.system() == "Darwin":
        cmd = f'osascript -e \'tell app "Terminal" to do script "cd {frontend_path} && npm start"\''
        subprocess.Popen(cmd, shell=True)
    else:
        terminals = ['gnome-terminal', 'xterm', 'konsole']
        for term in terminals:
            try:
                subprocess.Popen([term, '--', 'bash', '-c', f'cd {frontend_path} && npm start'])
                break
            except FileNotFoundError:
                continue
    
    print("⏳ Waiting for React to compile...")
    time.sleep(10)
    
    if is_port_in_use(3000):
        print("✅ React frontend started successfully!")
        return True
    else:
        print("⚠️  React frontend may not have started properly")
        print("   Check the React window for errors")
        return False

def print_summary(api_started=True, react_started=True):
    """Print final summary"""
    print("\n" + "=" * 80)
    if api_started and react_started:
        print(" " * 25 + "ALL SERVICES STARTED!")
    else:
        print(" " * 25 + "SERVICES STARTED (PARTIAL)")
    print("=" * 80)
    
    print("\n📊 Access the system:")
    if react_started:
        print("   • React UI:    http://localhost:3000")
    if api_started:
        print("   • API Server:  http://localhost:8000")
        print("   • API Docs:    http://localhost:8000/docs")
    
    print("\n📁 Output files:")
    print("   • Context:     app/data/output/processed_context.json")
    print("   • Alerts:      app/data/output/alerts.json")
    print("   • Logs:        app/data/output/decoded_logs.json")
    
    if not react_started:
        print("\n⚠️  React frontend not started (npm not found)")
        print("   Install Node.js from: https://nodejs.org")
        print("   Then run: cd frontend && npm install && npm start")
    
    print("\n💡 Tips:")
    print("   • Close the terminal windows to stop services")
    print("   • Check WINDOWS_SETUP.md for PyCharm setup")
    print("   • Read README.md for detailed documentation")
    print("\n" + "=" * 80)

def main():
    """Main launcher function"""
    print("=" * 80)
    print(" " * 15 + "EDR LOG PROCESSING SYSTEM LAUNCHER")
    print("=" * 80)
    print(f"\nPlatform: {platform.system()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Working Directory: {Path(__file__).parent}")
    print()
    
    # Check prerequisites
    print("Checking prerequisites...")
    
    # Check Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required!")
        sys.exit(1)
    print("✅ Python version OK")
    
    # Check Node.js
    npm_available = check_command_exists('npm')
    if npm_available:
        try:
            result = subprocess.run(['npm', '--version'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print(f"✅ npm {result.stdout.strip()} found")
        except:
            npm_available = False
    
    if not npm_available:
        print("⚠️  npm not found - React frontend will not be available")
        print("   Install Node.js from: https://nodejs.org")
        print("   You can still use the API and process logs")
    
    print("\n" + "-" * 80 + "\n")
    
    # Step 1: Process logs
    if not run_step_1_processing():
        print("\n❌ Failed at Step 1. Please check errors above.")
        sys.exit(1)
    
    input("\n✅ Step 1 completed. Press Enter to continue to Step 2...")
    
    # Step 2: Start API server
    api_started = start_api_server()
    
    if not npm_available:
        print("\n⚠️  Skipping React frontend (npm not available)")
        print_summary(api_started=api_started, react_started=False)
        input("\nPress Enter to exit...")
        return
    
    input("\n✅ Step 2 completed. Press Enter to continue to Step 3...")
    
    # Step 3: Start React frontend
    react_started = start_react_frontend()
    
    # Print summary
    print_summary(api_started=api_started, react_started=react_started)
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
