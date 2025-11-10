"""
Quick compatibility test for fixed Windows Event format
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.decoders.windows_decoder import WindowsDecoder


def test_fixed_windows_format():
    """Test that the fixed Windows Event format works with WindowsDecoder."""
    print("\n" + "=" * 70)
    print("  Testing Fixed Windows Event Format")
    print("=" * 70)

    decoder = WindowsDecoder()

    # Test samples with proper property names
    test_logs = [
        # PowerShell Event 4104 with ScriptBlockText
        "Event ID: 4104 TimeCreated: 2025-11-10T08:25:31 ScriptBlockText: Write-Host 'Hello World' Path: C:\\test.ps1",

        # Security Logon Failed 4625
        "Event ID: 4625 TimeCreated: 2025-11-10T08:25:31 LogonType: 3 TargetUserName: Administrator IpAddress: 192.168.1.200 FailureReason: Unknown_user_name",

        # Security Logon Success 4624
        "Event ID: 4624 TimeCreated: 2025-11-10T08:25:31 LogonType: 2 TargetUserName: User IpAddress: 127.0.0.1",

        # Defender Threat 1116
        "Event ID: 1116 TimeCreated: 2025-11-10T08:25:31 ThreatName: Trojan.Generic Severity: High Action: Quarantine ResourcePath: C:\\malware.exe",

        # Firewall Block 5157
        "Event ID: 5157 TimeCreated: 2025-11-10T08:25:31 Application: chrome.exe SourceAddress: 192.168.1.10 SourcePort: 5000 DestAddress: 8.8.8.8 DestPort: 443 Protocol: TCP"
    ]

    passed = 0
    failed = 0

    for i, log in enumerate(test_logs, 1):
        print(f"\nTest {i}:")
        print(f"  Input: {log[:80]}...")

        decoded = decoder.decode_windows_event(log)

        if decoded:
            print(f"  ✅ PASS")
            print(f"     Event ID: {decoded.get('event_id')}")
            print(f"     Log Type: {decoded.get('log_type')}")
            print(f"     Category: {decoded.get('event_category')}")
            print(f"     Severity: {decoded.get('severity')}")

            # Show enriched fields
            enriched_keys = [k for k in decoded.keys() if k not in ['log_type', 'event_id', 'event_category', 'provider', 'timestamp', 'computer', 'event_data', 'severity']]
            if enriched_keys:
                print(f"     Enriched: {', '.join(enriched_keys)}")

            passed += 1
        else:
            print(f"  ❌ FAIL - Could not decode")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Results: {passed}/{len(test_logs)} passed")
    print("=" * 70)

    return failed == 0


if __name__ == "__main__":
    success = test_fixed_windows_format()
    sys.exit(0 if success else 1)
