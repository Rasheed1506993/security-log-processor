"""
Registry Monitoring Collector (Windows Only)
Monitors Windows Registry changes in critical keys
"""
import time
import threading
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional
import subprocess
import re


class RegistryCollector:
    """
    Monitors Windows Registry changes by polling critical registry keys.
    Tracks changes in Run keys, Services, and other security-critical locations.
    """

    def __init__(self, poll_interval: int = 30):
        """
        Initialize Registry Collector

        Args:
            poll_interval: How often to check registry keys (in seconds)
        """
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.callback = None

        # Critical registry keys to monitor
        self.monitored_keys = [
            # Auto-start locations
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',

            # Services
            'HKLM\\SYSTEM\\CurrentControlSet\\Services',

            # Windows Defender
            'HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions',
            'HKLM\\Software\\Policies\\Microsoft\\Windows Defender',

            # Firewall
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy',

            # Security policies
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies'
        ]

        # Store current state of monitored keys
        self.key_states: Dict[str, Dict[str, str]] = {}

        self.stats = {
            'events_collected': 0,
            'keys_monitored': len(self.monitored_keys),
            'changes_detected': 0,
            'errors': 0
        }

        print(f"[RegistryCollector] Initialized with {len(self.monitored_keys)} monitored keys")

    def start(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Start monitoring registry.

        Args:
            callback: Function to call with registry change info dict
        """
        if self.running:
            print("[RegistryCollector] Already running")
            return

        self.callback = callback
        self.running = True

        # Initialize current state
        self._initialize_states()

        # Start monitoring thread
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print(f"[RegistryCollector] Started (polling every {self.poll_interval}s)")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[RegistryCollector] Stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Check each monitored key
                for key_path in self.monitored_keys:
                    if not self.running:
                        break

                    changes = self._check_key_changes(key_path)

                    # Report each change
                    for change in changes:
                        if self.callback:
                            self.callback(change)
                            self.stats['events_collected'] += 1
                            self.stats['changes_detected'] += 1

                # Sleep until next poll
                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"[RegistryCollector] Error in monitoring loop: {e}")
                self.stats['errors'] += 1
                time.sleep(self.poll_interval)

    def _initialize_states(self):
        """Initialize current state of all monitored keys."""
        print("[RegistryCollector] Initializing registry states...")

        for key_path in self.monitored_keys:
            try:
                values = self._query_registry_key(key_path)
                if values:
                    self.key_states[key_path] = values
            except Exception as e:
                print(f"[RegistryCollector] Error initializing {key_path}: {e}")

        print(f"[RegistryCollector] Initialized {len(self.key_states)} keys")

    def _check_key_changes(self, key_path: str) -> List[Dict[str, Any]]:
        """
        Check for changes in a registry key.

        Args:
            key_path: Registry key path

        Returns:
            List of change dictionaries
        """
        changes = []

        try:
            # Get current values
            current_values = self._query_registry_key(key_path)

            if current_values is None:
                # Key might have been deleted or inaccessible
                if key_path in self.key_states:
                    changes.append({
                        'action': 'deleted',
                        'key_path': key_path,
                        'value_name': '',
                        'value_data': '',
                        'timestamp': datetime.now()
                    })
                    del self.key_states[key_path]
                return changes

            # Get previous state
            previous_values = self.key_states.get(key_path, {})

            # Check for new or modified values
            for value_name, value_data in current_values.items():
                if value_name not in previous_values:
                    # New value
                    changes.append({
                        'action': 'created',
                        'key_path': key_path,
                        'value_name': value_name,
                        'value_data': value_data,
                        'timestamp': datetime.now()
                    })
                elif previous_values[value_name] != value_data:
                    # Modified value
                    changes.append({
                        'action': 'modified',
                        'key_path': key_path,
                        'value_name': value_name,
                        'value_data': value_data,
                        'previous_data': previous_values[value_name],
                        'timestamp': datetime.now()
                    })

            # Check for deleted values
            for value_name in previous_values:
                if value_name not in current_values:
                    changes.append({
                        'action': 'deleted',
                        'key_path': key_path,
                        'value_name': value_name,
                        'value_data': previous_values[value_name],
                        'timestamp': datetime.now()
                    })

            # Update state
            self.key_states[key_path] = current_values

        except Exception as e:
            print(f"[RegistryCollector] Error checking key {key_path}: {e}")
            self.stats['errors'] += 1

        return changes

    def _query_registry_key(self, key_path: str) -> Optional[Dict[str, str]]:
        """
        Query a registry key and return its values.

        Args:
            key_path: Registry key path (e.g., 'HKLM\\Software\\...')

        Returns:
            Dictionary of {value_name: value_data} or None if error
        """
        try:
            # Use reg query command
            result = subprocess.run(
                ['reg', 'query', key_path],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )

            if result.returncode != 0:
                return None

            # Parse output
            values = {}
            lines = result.stdout.strip().split('\n')

            for line in lines:
                line = line.strip()
                if not line or line.startswith('HKEY_') or line.startswith('(Default)'):
                    continue

                # Parse line: NAME    TYPE    DATA
                parts = re.split(r'\s{2,}', line)
                if len(parts) >= 3:
                    value_name = parts[0].strip()
                    value_type = parts[1].strip()
                    value_data = parts[2].strip() if len(parts) > 2 else ''

                    values[value_name] = value_data

            return values

        except subprocess.TimeoutExpired:
            print(f"[RegistryCollector] Timeout querying {key_path}")
            return None
        except Exception as e:
            # Silently ignore errors (key might not exist or no access)
            return None

    def query_key_once(self, key_path: str) -> Optional[Dict[str, str]]:
        """
        Query a registry key once (for testing).

        Args:
            key_path: Registry key path

        Returns:
            Dictionary of values or None
        """
        return self._query_registry_key(key_path)

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'keys_monitored': len(self.monitored_keys),
            'keys_tracked': len(self.key_states),
            **self.stats
        }
