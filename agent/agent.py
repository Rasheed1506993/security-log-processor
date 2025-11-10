"""
Windows Security Log Collection Agent
Main agent that coordinates all collectors and writes logs
"""
import sys
import os
import time
import json
import signal
from datetime import datetime
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


class SecurityAgent:
    """
    Main security log collection agent.
    Coordinates all collectors and writes logs to file.
    """

    def __init__(self, config_path: str = None):
        """
        Initialize Security Agent

        Args:
            config_path: Path to configuration file
        """
        self.running = False
        self.collectors = {}

        # Load configuration
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self._default_config()

        # Initialize formatters
        self.basic_formatter = BasicFormatter()
        self.windows_formatter = WindowsFormatter()
        self.json_formatter = JSONFormatter()

        # Initialize log writer
        output_path = self.config['output']['log_file']
        max_size_mb = self.config['output'].get('max_size_mb', 100)
        backup_count = self.config['output'].get('backup_count', 5)

        self.log_writer = LogWriter(output_path, max_size_mb, backup_count)

        print(f"[SecurityAgent] Initialized")
        print(f"[SecurityAgent] Output: {output_path}")
        print(f"[SecurityAgent] Max size: {max_size_mb} MB")

    def _default_config(self) -> dict:
        """Generate default configuration."""
        return {
            'collectors': {
                'windows_events': {
                    'enabled': True,
                    'poll_interval': 10
                },
                'file_integrity': {
                    'enabled': True,
                    'watch_paths': [
                        'C:\\Windows\\System32',
                        'C:\\Windows\\System32\\drivers'
                    ],
                    'recursive': False
                },
                'process_monitoring': {
                    'enabled': True,
                    'poll_interval': 2
                },
                'network_monitoring': {
                    'enabled': True,
                    'poll_interval': 5
                },
                'registry_monitoring': {
                    'enabled': True,
                    'poll_interval': 30
                }
            },
            'output': {
                'log_file': '../app/data/input/agent_logs.txt',
                'max_size_mb': 100,
                'backup_count': 5,
                'format': 'mixed'  # mixed, basic, windows, json
            }
        }

    def start(self):
        """Start the agent and all enabled collectors."""
        if self.running:
            print("[SecurityAgent] Already running")
            return

        self.running = True
        print("\n" + "=" * 70)
        print("  Windows Security Log Collection Agent")
        print("=" * 70)

        # Start Windows Event Collector
        if self.config['collectors']['windows_events']['enabled']:
            print("\n[SecurityAgent] Starting Windows Event Collector...")
            poll_interval = self.config['collectors']['windows_events']['poll_interval']
            collector = WindowsEventCollector(poll_interval=poll_interval)
            collector.start(self._on_windows_event)
            self.collectors['windows_events'] = collector

        # Start File Integrity Monitoring
        if self.config['collectors']['file_integrity']['enabled']:
            print("\n[SecurityAgent] Starting File Integrity Monitoring...")
            watch_paths = self.config['collectors']['file_integrity'].get('watch_paths')
            recursive = self.config['collectors']['file_integrity'].get('recursive', True)
            collector = FileIntegrityCollector(watch_paths=watch_paths, recursive=recursive)
            collector.start(self._on_file_event)
            self.collectors['file_integrity'] = collector

        # Start Process Monitoring
        if self.config['collectors']['process_monitoring']['enabled']:
            print("\n[SecurityAgent] Starting Process Monitoring...")
            poll_interval = self.config['collectors']['process_monitoring']['poll_interval']
            collector = ProcessCollector(poll_interval=poll_interval)
            collector.start(self._on_process_event)
            self.collectors['process_monitoring'] = collector

        # Start Network Monitoring
        if self.config['collectors']['network_monitoring']['enabled']:
            print("\n[SecurityAgent] Starting Network Monitoring...")
            poll_interval = self.config['collectors']['network_monitoring']['poll_interval']
            collector = NetworkCollector(poll_interval=poll_interval)
            collector.start(self._on_network_event)
            self.collectors['network_monitoring'] = collector

        # Start Registry Monitoring
        if self.config['collectors']['registry_monitoring']['enabled']:
            print("\n[SecurityAgent] Starting Registry Monitoring...")
            poll_interval = self.config['collectors']['registry_monitoring']['poll_interval']
            collector = RegistryCollector(poll_interval=poll_interval)
            collector.start(self._on_registry_event)
            self.collectors['registry_monitoring'] = collector

        print("\n" + "=" * 70)
        print(f"  Agent Started - {len(self.collectors)} collectors active")
        print("=" * 70)
        print("\nPress Ctrl+C to stop...\n")

    def stop(self):
        """Stop the agent and all collectors."""
        if not self.running:
            return

        print("\n[SecurityAgent] Stopping agent...")
        self.running = False

        # Stop all collectors
        for name, collector in self.collectors.items():
            print(f"[SecurityAgent] Stopping {name}...")
            collector.stop()

        print("[SecurityAgent] Agent stopped")

    def _on_windows_event(self, event_log: str):
        """Handle Windows event (already formatted)."""
        try:
            # Windows events come pre-formatted from the collector
            self.log_writer.write_log(event_log)

        except Exception as e:
            print(f"[SecurityAgent] Error handling Windows event: {e}")

    def _on_file_event(self, action: str, file_path: str):
        """Handle file integrity event."""
        try:
            # Format as FIM log
            log_entry = self.basic_formatter.format_file_integrity(
                file_path=file_path,
                action=action
            )

            self.log_writer.write_log(log_entry)

        except Exception as e:
            print(f"[SecurityAgent] Error handling file event: {e}")

    def _on_process_event(self, process_info: dict):
        """Handle process creation event."""
        try:
            # Filter out agent's own PowerShell processes
            cmdline = process_info.get('cmdline', '').lower()
            if 'powershell' in cmdline and 'get-winevent' in cmdline:
                # Skip agent's own event collection processes
                return

            # Format depending on configuration
            if self.config['output']['format'] == 'json':
                # JSON format
                log_entry = self.json_formatter.format_process_execution(
                    process_name=process_info['name'],
                    pid=process_info['pid'],
                    parent_pid=process_info['parent_pid'],
                    parent_name=process_info['parent_name'],
                    command_line=process_info['cmdline'],
                    user=process_info['username'],
                    file_path=process_info.get('exe', 'Unknown'),
                    timestamp=process_info['create_time']
                )
            else:
                # Basic format
                log_entry = self.basic_formatter.format_process(
                    pid=process_info['pid'],
                    user=process_info['username'],
                    command=process_info['cmdline'] if process_info['cmdline'] else process_info['name'],
                    timestamp=process_info['create_time']
                )

            self.log_writer.write_log(log_entry)

        except Exception as e:
            print(f"[SecurityAgent] Error handling process event: {e}")

    def _on_network_event(self, conn_info: dict):
        """Handle network connection event."""
        try:
            # Format depending on configuration
            if self.config['output']['format'] == 'json':
                # JSON format
                threat_indicators = []
                if not conn_info['is_internal']:
                    threat_indicators.append('external_connection')
                if conn_info['remote_port'] in [4444, 31337, 1337]:
                    threat_indicators.append('suspicious_port')

                log_entry = self.json_formatter.format_network_connection(
                    source_ip=conn_info['local_ip'],
                    source_port=conn_info['local_port'],
                    source_hostname='localhost',
                    dest_ip=conn_info['remote_ip'],
                    dest_port=conn_info['remote_port'],
                    protocol=conn_info['protocol'],
                    threat_indicators=threat_indicators if threat_indicators else None,
                    timestamp=conn_info['timestamp']
                )
            else:
                # Basic format
                log_entry = self.basic_formatter.format_network(
                    protocol=conn_info['protocol'],
                    src_ip=conn_info['local_ip'],
                    src_port=conn_info['local_port'],
                    dst_ip=conn_info['remote_ip'],
                    dst_port=conn_info['remote_port'],
                    timestamp=conn_info['timestamp']
                )

            self.log_writer.write_log(log_entry)

        except Exception as e:
            print(f"[SecurityAgent] Error handling network event: {e}")

    def _on_registry_event(self, change_info: dict):
        """Handle registry change event."""
        try:
            # Format depending on configuration
            if self.config['output']['format'] == 'json':
                # JSON format
                log_entry = self.json_formatter.format_registry_event(
                    action=change_info['action'],
                    key_path=change_info['key_path'],
                    value_name=change_info['value_name'],
                    value_data=change_info.get('value_data', ''),
                    timestamp=change_info['timestamp']
                )
            else:
                # Basic format
                full_value = change_info.get('value_data', '')
                log_entry = self.basic_formatter.format_registry(
                    action=change_info['action'],
                    key=change_info['key_path'],
                    value=f"{change_info['value_name']}={full_value}",
                    timestamp=change_info['timestamp']
                )

            self.log_writer.write_log(log_entry)

        except Exception as e:
            print(f"[SecurityAgent] Error handling registry event: {e}")

    def get_stats(self) -> dict:
        """Get statistics from all collectors."""
        stats = {
            'agent_running': self.running,
            'active_collectors': len(self.collectors),
            'log_writer': self.log_writer.get_stats(),
            'collectors': {}
        }

        for name, collector in self.collectors.items():
            stats['collectors'][name] = collector.get_stats()

        return stats

    def print_stats(self):
        """Print statistics to console."""
        stats = self.get_stats()

        print("\n" + "=" * 70)
        print("  Agent Statistics")
        print("=" * 70)

        print(f"\nAgent Status: {'Running' if stats['agent_running'] else 'Stopped'}")
        print(f"Active Collectors: {stats['active_collectors']}")

        print(f"\nLog Writer:")
        writer_stats = stats['log_writer']
        print(f"  File: {writer_stats['log_file']}")
        print(f"  Size: {writer_stats['file_size_mb']:.2f} MB")
        print(f"  Backups: {len(writer_stats.get('backups', []))}")

        print(f"\nCollectors:")
        for name, collector_stats in stats['collectors'].items():
            print(f"\n  {name}:")
            for key, value in collector_stats.items():
                if key != 'watch_paths' and not isinstance(value, (list, dict)):
                    print(f"    {key}: {value}")

        print("\n" + "=" * 70)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n[SecurityAgent] Received stop signal...")
    if 'agent' in globals():
        agent.stop()
    sys.exit(0)


def main():
    """Main entry point."""
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Check if running on Windows
    if sys.platform != 'win32':
        print("[SecurityAgent] ERROR: This agent is designed for Windows only")
        sys.exit(1)

    # Parse command line arguments
    config_path = None
    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    # Create and start agent
    global agent
    agent = SecurityAgent(config_path=config_path)

    try:
        agent.start()

        # Main loop - print stats every 60 seconds
        while agent.running:
            time.sleep(60)
            agent.print_stats()

    except KeyboardInterrupt:
        print("\n[SecurityAgent] Interrupted")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
