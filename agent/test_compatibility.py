"""
Compatibility Test - Verify Agent Output Works with Decoders
Tests that agent-generated logs can be successfully decoded by the main system
"""
import sys
from pathlib import Path
from datetime import datetime

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.formatters.basic_formatter import BasicFormatter
from agent.formatters.windows_formatter import WindowsFormatter
from agent.formatters.json_formatter import JSONFormatter

from app.decoders.log_decoder import LogDecoder
from app.decoders.windows_decoder import WindowsDecoder
from app.decoders.generic_decoder import GenericDecoder


def test_basic_formatter_compatibility():
    """Test that BasicFormatter output is compatible with LogDecoder."""
    print("\n" + "=" * 70)
    print("  Testing BasicFormatter <-> LogDecoder Compatibility")
    print("=" * 70)

    formatter = BasicFormatter()
    decoder = LogDecoder()

    tests = [
        {
            'name': 'FIM Log',
            'log': formatter.format_file_integrity("C:\\Windows\\System32\\test.dll", "modified"),
            'expected_type': 'file_integrity'
        },
        {
            'name': 'PROC Log',
            'log': formatter.format_process(1234, "admin", "powershell.exe -enc ABC123"),
            'expected_type': 'process'
        },
        {
            'name': 'NET Log',
            'log': formatter.format_network("TCP", "192.168.1.10", 5000, "8.8.8.8", 443),
            'expected_type': 'network'
        },
        {
            'name': 'AUTH Log',
            'log': formatter.format_authentication("failed", "admin", "192.168.1.100"),
            'expected_type': 'authentication'
        },
        {
            'name': 'REG Log',
            'log': formatter.format_registry("modified", "HKLM\\Software\\Run", "Malware=C:\\malware.exe"),
            'expected_type': 'registry'
        },
        {
            'name': 'SVC Log',
            'log': formatter.format_service("stopped", "WinDefend", "stopped"),
            'expected_type': 'service'
        }
    ]

    passed = 0
    failed = 0

    for test in tests:
        print(f"\n{test['name']}:")
        print(f"  Generated: {test['log']}")

        decoded = decoder.decode_log(test['log'])

        if decoded and decoded.get('log_type') == test['expected_type']:
            print(f"  ✅ PASS - Decoded as '{decoded['log_type']}'")
            passed += 1
        else:
            print(f"  ❌ FAIL - Expected '{test['expected_type']}', got {decoded}")
            failed += 1

    print("\n" + "-" * 70)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


def test_windows_formatter_compatibility():
    """Test that WindowsFormatter output is compatible with WindowsDecoder."""
    print("\n" + "=" * 70)
    print("  Testing WindowsFormatter <-> WindowsDecoder Compatibility")
    print("=" * 70)

    formatter = WindowsFormatter()
    decoder = WindowsDecoder()

    tests = [
        {
            'name': 'Security Logon Event (4625)',
            'log': formatter.format_security_logon(4625, 3, "Administrator", "192.168.1.200"),
            'expected_id': 4625
        },
        {
            'name': 'Defender Threat Event (1116)',
            'log': formatter.format_defender_threat(1116, "Trojan.Generic", "High", "Quarantine", "C:\\malware.exe"),
            'expected_id': 1116
        },
        {
            'name': 'Firewall Block Event (5157)',
            'log': formatter.format_firewall_block(5157, "chrome.exe", "192.168.1.10", "5000", "8.8.8.8", "443", "TCP"),
            'expected_id': 5157
        }
    ]

    passed = 0
    failed = 0

    for test in tests:
        print(f"\n{test['name']}:")
        print(f"  Generated: {test['log'][:100]}...")

        decoded = decoder.decode_windows_event(test['log'])

        if decoded and decoded.get('event_id') == test['expected_id']:
            print(f"  ✅ PASS - Decoded Event ID {decoded['event_id']}")
            passed += 1
        else:
            print(f"  ❌ FAIL - Expected Event ID {test['expected_id']}, got {decoded}")
            failed += 1

    print("\n" + "-" * 70)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


def test_json_formatter_compatibility():
    """Test that JSONFormatter output is compatible with GenericDecoder."""
    print("\n" + "=" * 70)
    print("  Testing JSONFormatter <-> GenericDecoder Compatibility")
    print("=" * 70)

    formatter = JSONFormatter()
    decoder = GenericDecoder()

    tests = [
        {
            'name': 'Authentication Event',
            'log': formatter.format_authentication_event("admin", "failed", "192.168.1.100", "invalid_password", 3),
            'expected_type': 'generic_json'
        },
        {
            'name': 'Process Execution Event',
            'log': formatter.format_process_execution("powershell.exe", 1234, 5678, "explorer.exe", "powershell.exe -enc ABC", "admin"),
            'expected_type': 'generic_json'
        },
        {
            'name': 'Network Connection Event',
            'log': formatter.format_network_connection("192.168.1.10", 5000, "workstation-01", "8.8.8.8", 443, "TCP"),
            'expected_type': 'generic_json'
        }
    ]

    passed = 0
    failed = 0

    for test in tests:
        print(f"\n{test['name']}:")
        print(f"  Generated: {test['log'][:100]}...")

        decoded = decoder.decode_generic(test['log'])

        if decoded and decoded.get('log_type') == test['expected_type']:
            print(f"  ✅ PASS - Decoded as '{decoded['log_type']}'")
            print(f"  Extracted fields: {list(decoded.get('extracted_fields', {}).keys())}")
            passed += 1
        else:
            print(f"  ❌ FAIL - Expected '{test['expected_type']}', got {decoded}")
            failed += 1

    print("\n" + "-" * 70)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


def test_mixed_format_compatibility():
    """Test that all three decoders can work together on mixed logs."""
    print("\n" + "=" * 70)
    print("  Testing Mixed Format Compatibility (Full Pipeline)")
    print("=" * 70)

    basic_fmt = BasicFormatter()
    windows_fmt = WindowsFormatter()
    json_fmt = JSONFormatter()

    log_decoder = LogDecoder()
    windows_decoder = WindowsDecoder()
    generic_decoder = GenericDecoder()

    # Generate mixed logs
    logs = [
        basic_fmt.format_file_integrity("C:\\Windows\\System32\\test.dll", "modified"),
        windows_fmt.format_security_logon(4625, 3, "Administrator", "192.168.1.200"),
        json_fmt.format_authentication_event("admin", "failed", "192.168.1.100"),
        basic_fmt.format_process(1234, "admin", "cmd.exe /c whoami"),
        windows_fmt.format_defender_threat(1116, "Trojan", "High", "Quarantine", "C:\\malware.exe"),
        json_fmt.format_network_connection("192.168.1.10", 5000, "host1", "8.8.8.8", 443, "TCP")
    ]

    print(f"\nProcessing {len(logs)} mixed format logs...\n")

    decoded_count = 0
    failed_count = 0

    for i, log in enumerate(logs, 1):
        print(f"Log {i}: {log[:60]}...")

        # Try each decoder in sequence (mimicking the main system)
        decoded = None

        # Try basic decoder
        decoded = log_decoder.decode_log(log)
        if decoded:
            print(f"  ✅ Decoded by LogDecoder as '{decoded['log_type']}'")
            decoded_count += 1
            continue

        # Try Windows decoder
        decoded = windows_decoder.decode_windows_event(log)
        if decoded:
            print(f"  ✅ Decoded by WindowsDecoder (Event ID {decoded['event_id']})")
            decoded_count += 1
            continue

        # Try generic decoder
        decoded = generic_decoder.decode_generic(log)
        if decoded:
            print(f"  ✅ Decoded by GenericDecoder as '{decoded['log_type']}'")
            decoded_count += 1
            continue

        # Failed to decode
        print(f"  ❌ FAILED to decode")
        failed_count += 1

    print("\n" + "-" * 70)
    print(f"Results: {decoded_count}/{len(logs)} logs decoded successfully")
    print(f"Success Rate: {(decoded_count/len(logs)*100):.1f}%")

    return failed_count == 0


def main():
    """Run all compatibility tests."""
    print("\n" + "=" * 70)
    print("  Agent <-> Decoder Compatibility Test Suite")
    print("=" * 70)

    all_passed = True

    try:
        # Test each formatter/decoder pair
        if not test_basic_formatter_compatibility():
            all_passed = False

        if not test_windows_formatter_compatibility():
            all_passed = False

        if not test_json_formatter_compatibility():
            all_passed = False

        # Test mixed format (full pipeline)
        if not test_mixed_format_compatibility():
            all_passed = False

        # Final result
        print("\n" + "=" * 70)
        if all_passed:
            print("  ✅ ALL COMPATIBILITY TESTS PASSED!")
            print("  The agent output is fully compatible with the decoders.")
        else:
            print("  ❌ SOME TESTS FAILED!")
            print("  Check the output above for details.")
        print("=" * 70 + "\n")

        return 0 if all_passed else 1

    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
