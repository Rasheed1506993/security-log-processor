#!/usr/bin/env python3
"""
Test script to verify EDR Log Processing System installation
"""
import sys
import os
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / 'app'))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from decoders.log_decoder import LogDecoder
        print("  ✓ LogDecoder imported")
    except Exception as e:
        print(f"  ✗ LogDecoder import failed: {e}")
        return False
    
    try:
        from decoders.windows_decoder import WindowsDecoder
        print("  ✓ WindowsDecoder imported")
    except Exception as e:
        print(f"  ✗ WindowsDecoder import failed: {e}")
        return False
    
    try:
        from rules.rules_engine import RulesEngine
        print("  ✓ RulesEngine imported")
    except Exception as e:
        print(f"  ✗ RulesEngine import failed: {e}")
        return False
    
    try:
        from context.context_builder import ContextBuilder
        print("  ✓ ContextBuilder imported")
    except Exception as e:
        print(f"  ✗ ContextBuilder import failed: {e}")
        return False
    
    return True

def test_rules_engine():
    """Test rules engine initialization"""
    print("\nTesting Rules Engine...")
    
    try:
        from rules.rules_engine import RulesEngine
        
        engine = RulesEngine()
        engine.load_rules()
        
        print(f"  ✓ Loaded {len(engine.rules)} rules")
        print(f"  ✓ Created {len(engine.rule_groups)} rule groups")
        
        # Test rule evaluation
        test_log = {
            'event_type': 'logon_attempt',
            'status': 'failed',
            'user': 'testuser'
        }
        
        matches = engine.evaluate_log(test_log)
        print(f"  ✓ Rule evaluation works (found {len(matches)} matches)")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Rules engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_decoders():
    """Test log decoders"""
    print("\nTesting Decoders...")
    
    try:
        from decoders.log_decoder import LogDecoder
        from decoders.windows_decoder import WindowsDecoder
        from decoders.generic_decoder import GenericDecoder
        
        # Test basic decoder
        basic = LogDecoder()
        test_log = "Nov 06 10:30:45 hostname process[1234]: User admin logged in successfully"
        result = basic.decode_log(test_log)
        if result:
            print("  ✓ Basic decoder works")
        else:
            print("  - Basic decoder (no match for test log)")
        
        # Test Windows decoder
        windows = WindowsDecoder()
        win_log = "DateTime: 2025-11-06 10:30:45\\nSource: Microsoft-Windows-Security-Auditing\\nEventID: 4624"
        result = windows.decode_windows_event(win_log)
        if result:
            print("  ✓ Windows decoder works")
        else:
            print("  - Windows decoder (no match for test log)")
        
        # Test generic decoder
        generic = GenericDecoder()
        json_log = '{"event": "test", "user": "admin"}'
        result = generic.decode_generic(json_log)
        if result:
            print("  ✓ Generic decoder works")
        else:
            print("  - Generic decoder (no match for test log)")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Decoder test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_file_structure():
    """Test that required directories and files exist"""
    print("\nTesting File Structure...")
    
    base_dir = Path(__file__).parent
    
    required_dirs = [
        'app/config',
        'app/context',
        'app/data/input',
        'app/data/output',
        'app/decoders',
        'app/rules',
        'app/rules/rule_sets',
        'app/server',
        'app/utils',
        'frontend/src',
        'frontend/public',
    ]
    
    for dir_path in required_dirs:
        full_path = base_dir / dir_path
        if full_path.exists():
            print(f"  ✓ {dir_path}")
        else:
            print(f"  ✗ Missing: {dir_path}")
            return False
    
    return True

def main():
    """Run all tests"""
    print("=" * 60)
    print("EDR Log Processing System - Installation Test")
    print("=" * 60)
    print()
    
    tests = [
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("Decoders", test_decoders),
        ("Rules Engine", test_rules_engine),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} - {test_name}")
    
    all_passed = all(result for _, result in results)
    
    print()
    if all_passed:
        print("✓ All tests passed! System is ready to use.")
        print()
        print("Next steps:")
        print("  1. Add logs to app/data/input/agent_logs.txt")
        print("  2. Run: python3 app/server/enhanced_server.py")
        print("  3. Run: python3 app/server/api_server.py")
        print("  4. Run: cd frontend && npm start")
        return 0
    else:
        print("✗ Some tests failed. Please review errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
