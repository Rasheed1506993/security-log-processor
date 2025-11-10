#!/usr/bin/env python3
"""
Simple EDR Launcher - Without React Frontend
Just runs log processing and API server
"""
import sys
import subprocess
from pathlib import Path

def main():
    print("=" * 80)
    print(" " * 15 + "EDR LOG PROCESSING - SIMPLE LAUNCHER")
    print("=" * 80)
    print()
    
    # Step 1: Process logs
    print("Step 1: Processing logs...")
    print("-" * 80)
    script_path = Path(__file__).parent / "app" / "server" / "enhanced_server.py"
    result = subprocess.run([sys.executable, str(script_path)])
    
    if result.returncode != 0:
        print("\n❌ Processing failed!")
        input("Press Enter to exit...")
        return
    
    print("\n✅ Processing completed!")
    print()
    
    # Step 2: Start API
    print("Step 2: Starting API server...")
    print("-" * 80)
    print("\n🚀 API will start on http://localhost:8000")
    print("   API Docs: http://localhost:8000/docs")
    print("\n   Press Ctrl+C to stop the server")
    print()
    
    script_path = Path(__file__).parent / "app" / "server" / "api_server.py"
    
    try:
        subprocess.run([sys.executable, str(script_path)])
    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped")

if __name__ == "__main__":
    main()
