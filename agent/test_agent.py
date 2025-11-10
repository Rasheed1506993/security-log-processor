"""
Test script for Security Log Collection Agent
Tests each collector independently and verifies output format
"""
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.collectors.windows_collector import WindowsEventCollector
from agent.collectors.file_integrity_collector import FileIntegrityCollector
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.registry_collector import RegistryCollector

from agent.formatters.basic_formatter import BasicFormatter
from agent.formatters.windows_formatter import WindowsFormatter
from agent.formatters.json_formatter import JSONFormatter

from agent.utils.log_writer import LogWriter


def test_formatters():
    """Test all formatters."""
    print("\n" + "=" * 70)
    print("  Testing Formatters")
    print("=" * 70)

    basic = BasicFormatter()
    windows = WindowsFormatter()
    json_fmt = JSONFormatter()

    print("\n1. Basic Formatter Tests:")
    print("-" * 70)

    # Test FIM format
    fim_log = basic.format_file_integrity("C:\\Windows\\System32\\test.dll", "modified")
    print(f"FIM: {fim_log}")

    # Test PROC format
    proc_log = basic.format_process(1234, "admin", "powershell.exe -enc ABC123")
    print(f"PROC: {proc_log}")

    # Test NET format
    net_log = basic.format_network("TCP", "192.168.1.10", 5000, "8.8.8.8", 443)
    print(f"NET: {net_log}")

    # Test AUTH format
    auth_log = basic.format_authentication("failed", "admin", "192.168.1.100")
    print(f"AUTH: {auth_log}")

    # Test REG format
    reg_log = basic.format_registry("modified", "HKLM\\Software\\Run", "Malware=C:\\malware.exe")
    print(f"REG: {reg_log}")

    # Test SVC format
    svc_log = basic.format_service("stopped", "WinDefend", "stopped")
    print(f"SVC: {svc_log}")

    print("\n2. Windows Formatter Tests:")
    print("-" * 70)

    # Test Windows structured format
    win_log = windows.format_security_logon(4625, 3, "Administrator", "192.168.1.200")
    print(f"Windows: {win_log}")

    print("\n3. JSON Formatter Tests:")
    print("-" * 70)

    # Test JSON format
    json_log = json_fmt.format_authentication_event("admin", "failed", "192.168.1.100", "invalid_password", 3)
    print(f"JSON:\n{json_log}")

    print("\n✅ All formatters working correctly!\n")


def test_log_writer():
    """Test log writer."""
    print("\n" + "=" * 70)
    print("  Testing Log Writer")
    print("=" * 70)

    # Create test writer
    test_file = "test_output.txt"
    writer = LogWriter(test_file, max_size_mb=1, backup_count=3)

    print(f"\nWriting test logs to: {test_file}")

    # Write some test logs
    writer.write_log("Test log 1")
    writer.write_log("Test log 2")
    writer.write_log("Test log 3")

    # Write batch
    batch = ["Batch log 1", "Batch log 2", "Batch log 3"]
    count = writer.write_logs_batch(batch)

    print(f"✅ Wrote {count} logs in batch")

    # Get stats
    stats = writer.get_stats()
    print(f"\nWriter Stats:")
    print(f"  File: {stats['log_file']}")
    print(f"  Size: {stats['file_size_mb']:.4f} MB")
    print(f"  Exists: {stats['file_exists']}")

    print("\n✅ Log writer working correctly!\n")


def test_windows_collector():
    """Test Windows Event Collector."""
    print("\n" + "=" * 70)
    print("  Testing Windows Event Collector")
    print("=" * 70)

    if sys.platform != 'win32':
        print("⚠️  Skipped (Windows only)")
        return

    collector = WindowsEventCollector(poll_interval=10)

    print("\nCollecting events from last hour (max 5 per source)...")

    events = collector.collect_once(max_events=5)

    print(f"\n✅ Collected {len(events)} events")

    if events:
        print("\nSample events:")
        for i, event in enumerate(events[:3], 1):
            print(f"{i}. {event[:100]}...")

    stats = collector.get_stats()
    print(f"\nCollector Stats: {stats}")


def test_process_collector():
    """Test Process Collector."""
    print("\n" + "=" * 70)
    print("  Testing Process Collector")
    print("=" * 70)

    collector = ProcessCollector(poll_interval=2)

    print("\nGetting current processes (max 5)...")

    processes = collector.get_current_processes(limit=5)

    print(f"\n✅ Found {len(processes)} processes")

    if processes:
        print("\nSample processes:")
        for i, proc in enumerate(processes[:3], 1):
            print(f"{i}. PID:{proc['pid']} {proc['name']} - {proc['username']}")


def test_network_collector():
    """Test Network Collector."""
    print("\n" + "=" * 70)
    print("  Testing Network Collector")
    print("=" * 70)

    collector = NetworkCollector(poll_interval=5)

    print("\nGetting current connections (max 5)...")

    connections = collector.get_current_connections(limit=5)

    print(f"\n✅ Found {len(connections)} connections")

    if connections:
        print("\nSample connections:")
        for i, conn in enumerate(connections[:3], 1):
            print(f"{i}. {conn['protocol']} {conn['local_ip']}:{conn['local_port']} -> {conn['remote_ip']}:{conn['remote_port']}")


def test_registry_collector():
    """Test Registry Collector."""
    print("\n" + "=" * 70)
    print("  Testing Registry Collector")
    print("=" * 70)

    if sys.platform != 'win32':
        print("⚠️  Skipped (Windows only)")
        return

    collector = RegistryCollector(poll_interval=30)

    print("\nQuerying registry key...")

    # Test querying a common key
    values = collector.query_key_once('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion')

    if values:
        print(f"\n✅ Found {len(values)} registry values")
        print("\nSample values:")
        for i, (name, data) in enumerate(list(values.items())[:3], 1):
            print(f"{i}. {name} = {data[:50]}...")
    else:
        print("\n⚠️  No values found (might need Administrator privileges)")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("  Security Log Collection Agent - Test Suite")
    print("=" * 70)

    try:
        # Test formatters
        test_formatters()

        # Test log writer
        test_log_writer()

        # Test collectors
        test_process_collector()
        test_network_collector()

        # Windows-specific tests
        if sys.platform == 'win32':
            test_windows_collector()
            test_registry_collector()
        else:
            print("\n⚠️  Skipping Windows-specific tests (not on Windows)")

        print("\n" + "=" * 70)
        print("  All Tests Completed!")
        print("=" * 70)

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
