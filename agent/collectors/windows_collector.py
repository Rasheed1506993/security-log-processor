"""
Windows Event Log Collector
Collects events from Windows Event Logs (Security, Defender, Firewall, PowerShell, etc.)
"""
import subprocess
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import threading
import time


class WindowsEventCollector:
    """
    Collects Windows Event Logs using PowerShell/wevtutil.
    Monitors Security, Defender, Firewall, PowerShell, and other event sources.
    """

    def __init__(self, poll_interval: int = 10):
        """
        Initialize Windows Event Collector

        Args:
            poll_interval: How often to check for new events (in seconds)
        """
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.last_check_time = {}
        self.stats = {
            'events_collected': 0,
            'security_events': 0,
            'defender_events': 0,
            'firewall_events': 0,
            'powershell_events': 0,
            'errors': 0
        }

        # Event log sources and their important Event IDs
        self.event_sources = {
            'Security': {
                'event_ids': [4624, 4625, 4634, 4672, 4673, 4720, 4722, 4724, 4726, 4728, 4732],
                'description': 'Authentication and privilege events'
            },
            'Microsoft-Windows-Windows Defender/Operational': {
                'event_ids': [1116, 1117, 1118, 1119, 2000, 2001, 5001],
                'description': 'Windows Defender threat detection'
            },
            'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall': {
                'event_ids': [5031, 5152, 5154, 5156, 5157],
                'description': 'Windows Firewall events'
            },
            'Microsoft-Windows-PowerShell/Operational': {
                'event_ids': [4103, 4104, 4105, 4106],
                'description': 'PowerShell execution and script block logging'
            }
        }

    def start(self, callback):
        """
        Start collecting events in background thread.

        Args:
            callback: Function to call with each collected event (signature: callback(log_entry: str))
        """
        if self.running:
            print("[WindowsEventCollector] Already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, args=(callback,), daemon=True)
        self.thread.start()
        print(f"[WindowsEventCollector] Started (polling every {self.poll_interval}s)")

    def stop(self):
        """Stop collecting events."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[WindowsEventCollector] Stopped")

    def _collect_loop(self, callback):
        """Main collection loop running in background thread."""
        while self.running:
            try:
                # Collect from each event source
                for source_name in self.event_sources.keys():
                    if not self.running:
                        break

                    events = self._collect_from_source(source_name)

                    # Send each event to callback
                    for event in events:
                        callback(event)
                        self.stats['events_collected'] += 1

                        # Update category stats
                        if 'Security' in source_name:
                            self.stats['security_events'] += 1
                        elif 'Defender' in source_name:
                            self.stats['defender_events'] += 1
                        elif 'Firewall' in source_name:
                            self.stats['firewall_events'] += 1
                        elif 'PowerShell' in source_name:
                            self.stats['powershell_events'] += 1

                # Sleep until next poll
                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"[WindowsEventCollector] Error in collection loop: {e}")
                self.stats['errors'] += 1
                time.sleep(self.poll_interval)

    def _collect_from_source(self, source_name: str) -> List[str]:
        """
        Collect events from a specific Windows Event Log source.

        Args:
            source_name: Name of the event log (e.g., 'Security')

        Returns:
            List of formatted log entries
        """
        try:
            # Get time range (events since last check)
            if source_name not in self.last_check_time:
                # First run: get events from last 1 minute
                start_time = datetime.now() - timedelta(minutes=1)
            else:
                start_time = self.last_check_time[source_name]

            # Update last check time
            self.last_check_time[source_name] = datetime.now()

            # Get event IDs to filter
            event_ids = self.event_sources[source_name]['event_ids']

            # Query events using PowerShell (more reliable than wevtutil)
            events = self._query_events_powershell(source_name, event_ids, start_time)

            return events

        except Exception as e:
            print(f"[WindowsEventCollector] Error collecting from {source_name}: {e}")
            return []

    def _query_events_powershell(self, log_name: str, event_ids: List[int],
                                 start_time: datetime) -> List[str]:
        """
        Query Windows Event Log using PowerShell Get-WinEvent.

        Args:
            log_name: Event log name
            event_ids: List of event IDs to filter
            start_time: Start time for event query

        Returns:
            List of formatted events (structured format)
        """
        try:
            # Format start time for PowerShell
            start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S')

            # Build event ID filter
            event_id_filter = ','.join(str(eid) for eid in event_ids)

            # PowerShell command to get events
            # Using structured output for easier parsing
            ps_command = f"""
$StartTime = [datetime]::Parse('{start_time_str}')
$EventIDs = @({event_id_filter})

try {{
    $Events = Get-WinEvent -FilterHashtable @{{
        LogName = '{log_name}'
        ID = $EventIDs
        StartTime = $StartTime
    }} -ErrorAction SilentlyContinue

    foreach ($Event in $Events) {{
        $Output = "Event ID: $($Event.Id) TimeCreated: $($Event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss'))"

        # Convert event to XML to get property names
        $EventXml = [xml]$Event.ToXml()
        $EventData = $EventXml.Event.EventData

        if ($EventData -and $EventData.Data) {{
            foreach ($Data in $EventData.Data) {{
                $Name = $Data.Name
                $Value = $Data.'#text'

                if ($Value -and $Name) {{
                    # Escape special characters in value
                    $Value = $Value.ToString().Replace('"', '""')
                    $Output += " $Name`: $Value"
                }}
            }}
        }}

        Write-Output $Output
    }}
}} catch {{
    # Silently ignore errors (log might not exist or no events found)
}}
"""

            # Execute PowerShell command
            result = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )

            if result.returncode != 0 or not result.stdout.strip():
                return []

            # Parse output lines
            events = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and line.startswith('Event ID:'):
                    events.append(line)

            return events

        except subprocess.TimeoutExpired:
            print(f"[WindowsEventCollector] PowerShell query timeout for {log_name}")
            return []
        except Exception as e:
            print(f"[WindowsEventCollector] PowerShell query error for {log_name}: {e}")
            return []

    def collect_once(self, source_name: str = None, max_events: int = 10) -> List[str]:
        """
        Collect events once (for testing/manual collection).

        Args:
            source_name: Specific source to collect from (None = all sources)
            max_events: Maximum events to collect per source

        Returns:
            List of formatted log entries
        """
        all_events = []

        sources_to_query = [source_name] if source_name else list(self.event_sources.keys())

        for source in sources_to_query:
            try:
                event_ids = self.event_sources[source]['event_ids']
                start_time = datetime.now() - timedelta(hours=1)  # Last 1 hour

                events = self._query_events_powershell(source, event_ids, start_time)
                all_events.extend(events[:max_events])

            except Exception as e:
                print(f"[WindowsEventCollector] Error collecting from {source}: {e}")

        return all_events

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'sources_monitored': len(self.event_sources),
            **self.stats
        }
