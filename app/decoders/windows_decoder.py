import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime


class WindowsDecoder:
    """
    Specialized decoder for Windows security logs including Windows Defender,
    Windows Security Events, Sysmon, PowerShell, Windows Firewall, and AppLocker.
    """

    def __init__(self):
        self.event_id_mapping = {
            # Windows Defender
            1116: 'defender_threat_detected',
            1117: 'defender_action_taken',
            1118: 'defender_full_scan_started',
            1119: 'defender_full_scan_finished',
            2000: 'defender_signature_updated',
            2001: 'defender_signature_update_failed',
            5001: 'defender_realtime_disabled',

            # Windows Security - Authentication
            4624: 'security_logon_success',
            4625: 'security_logon_failed',
            4634: 'security_logoff',
            4648: 'security_explicit_credentials',

            # Windows Security - Privilege
            4672: 'security_special_privileges',
            4673: 'security_privileged_service',
            4674: 'security_privileged_operation',

            # Windows Security - Account Management
            4720: 'security_user_created',
            4722: 'security_user_enabled',
            4724: 'security_password_reset',
            4726: 'security_user_deleted',
            4728: 'security_user_added_to_group',
            4732: 'security_member_added_to_local_group',

            # Windows Firewall
            5031: 'firewall_blocked_application',
            5152: 'firewall_blocked_packet',
            5154: 'firewall_permit_listen',
            5156: 'firewall_permit_connection',
            5157: 'firewall_blocked_connection',

            # AppLocker
            8003: 'applocker_allowed',
            8004: 'applocker_blocked',
            8006: 'applocker_script_allowed',
            8007: 'applocker_script_blocked',

            # PowerShell
            4103: 'powershell_module_logging',
            4104: 'powershell_script_block',
            4105: 'powershell_script_start',
            4106: 'powershell_script_stop',

            # Sysmon
            1: 'sysmon_process_create',
            3: 'sysmon_network_connect',
            7: 'sysmon_image_loaded',
            8: 'sysmon_create_remote_thread',
            10: 'sysmon_process_access',
            11: 'sysmon_file_create',
            12: 'sysmon_registry_event',
            13: 'sysmon_registry_value_set',
            22: 'sysmon_dns_query'
        }

        self.stats = {
            'windows_events_decoded': 0,
            'defender_events': 0,
            'security_events': 0,
            'sysmon_events': 0,
            'powershell_events': 0,
            'firewall_events': 0,
            'applocker_events': 0
        }

    def decode_windows_event(self, log_line: str) -> Optional[Dict[str, Any]]:
        """
        Main entry point for decoding Windows events.
        Attempts to parse as Windows Event Log format first.
        """
        result = None

        # Try Windows Event XML format
        if '<Event xmlns=' in log_line or '<Event>' in log_line:
            result = self._decode_xml_event(log_line)
        # Try structured Windows Event format
        elif 'EventID' in log_line or 'Event ID' in log_line:
            result = self._decode_structured_event(log_line)

        if result:
            self.stats['windows_events_decoded'] += 1
            self._update_category_stats(result.get('log_type', ''))

        return result

    def _decode_xml_event(self, xml_string: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Event Log XML format."""
        try:
            root = ET.fromstring(xml_string)

            # Extract System section
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is None:
                system = root.find('.//System')

            if system is None:
                return None

            event_id_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
            if event_id_elem is None:
                event_id_elem = system.find('.//EventID')

            if event_id_elem is None:
                return None

            event_id = int(event_id_elem.text)

            # Extract basic fields
            provider = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Provider')
            if provider is None:
                provider = system.find('.//Provider')

            time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
            if time_created is None:
                time_created = system.find('.//TimeCreated')

            computer = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer')
            if computer is None:
                computer = system.find('.//Computer')

            # Extract EventData
            event_data = {}
            event_data_section = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            if event_data_section is None:
                event_data_section = root.find('.//EventData')

            if event_data_section is not None:
                for data in event_data_section:
                    name = data.get('Name', data.tag)
                    event_data[name] = data.text or ''

            # Build decoded log
            decoded = {
                'log_type': self._get_log_type_from_event_id(event_id),
                'event_id': event_id,
                'event_category': self._categorize_event(event_id),
                'provider': provider.get('Name') if provider is not None else 'Unknown',
                'timestamp': time_created.get('SystemTime') if time_created is not None else datetime.now().isoformat(),
                'computer': computer.text if computer is not None else 'Unknown',
                'event_data': event_data,
                'severity': self._assess_windows_event_severity(event_id, event_data)
            }

            # Add specialized fields based on event type
            self._enrich_windows_event(decoded, event_id, event_data)

            return decoded

        except ET.ParseError:
            return None
        except Exception as e:
            return None

    def _decode_structured_event(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse structured Windows Event format (key-value pairs)."""
        try:
            # Extract Event ID
            event_id_match = re.search(r'Event(?:\s+)?ID[:\s]+?(\d+)', log_line, re.IGNORECASE)
            if not event_id_match:
                return None

            event_id = int(event_id_match.group(1))

            # Extract timestamp
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', log_line)
            timestamp = timestamp_match.group(1) if timestamp_match else datetime.now().isoformat()

            # Extract key-value pairs
            event_data = {}
            kv_pattern = r'(\w+)[:\s=]+((?:[^,;\n]|(?<=\\),)+)'
            for match in re.finditer(kv_pattern, log_line):
                key = match.group(1)
                value = match.group(2).strip()
                if key.lower() not in ['event', 'id', 'eventid']:
                    event_data[key] = value

            decoded = {
                'log_type': self._get_log_type_from_event_id(event_id),
                'event_id': event_id,
                'event_category': self._categorize_event(event_id),
                'timestamp': timestamp,
                'event_data': event_data,
                'severity': self._assess_windows_event_severity(event_id, event_data)
            }

            self._enrich_windows_event(decoded, event_id, event_data)

            return decoded

        except Exception:
            return None

    def _get_log_type_from_event_id(self, event_id: int) -> str:
        """Map event ID to specific log type."""
        return self.event_id_mapping.get(event_id, f'windows_event_{event_id}')

    def _categorize_event(self, event_id: int) -> str:
        """Categorize event into major groups."""
        if event_id in [1116, 1117, 1118, 1119, 2000, 2001, 5001]:
            return 'windows_defender'
        elif event_id in range(4624, 4750):
            return 'windows_security'
        elif event_id in [5031, 5152, 5154, 5156, 5157]:
            return 'windows_firewall'
        elif event_id in [8003, 8004, 8006, 8007]:
            return 'applocker'
        elif event_id in [4103, 4104, 4105, 4106]:
            return 'powershell'
        elif event_id in range(1, 30):
            return 'sysmon'
        else:
            return 'windows_generic'

    def _enrich_windows_event(self, decoded: Dict[str, Any], event_id: int, event_data: Dict[str, Any]):
        """Add specialized fields based on event type."""

        # Windows Defender enrichment
        if event_id in [1116, 1117]:
            decoded['threat_name'] = event_data.get('Threat Name', event_data.get('ThreatName', 'Unknown'))
            decoded['threat_severity'] = event_data.get('Severity', 'Unknown')
            decoded['action_taken'] = event_data.get('Action', event_data.get('ActionTaken', 'Unknown'))
            decoded['resource_path'] = event_data.get('Path', event_data.get('ResourcePath', 'Unknown'))

        # Security Logon enrichment
        elif event_id in [4624, 4625]:
            decoded['logon_type'] = event_data.get('LogonType', 'Unknown')
            decoded['target_user'] = event_data.get('TargetUserName', event_data.get('TargetUser', 'Unknown'))
            decoded['source_ip'] = event_data.get('IpAddress', event_data.get('SourceIP', 'Unknown'))
            decoded['logon_process'] = event_data.get('LogonProcess', 'Unknown')
            decoded['authentication_package'] = event_data.get('AuthenticationPackageName', 'Unknown')

        # Sysmon Process Creation enrichment
        elif event_id == 1:
            decoded['process_name'] = event_data.get('Image', 'Unknown')
            decoded['command_line'] = event_data.get('CommandLine', 'Unknown')
            decoded['parent_process'] = event_data.get('ParentImage', 'Unknown')
            decoded['parent_command_line'] = event_data.get('ParentCommandLine', 'Unknown')
            decoded['user'] = event_data.get('User', 'Unknown')
            decoded['process_id'] = event_data.get('ProcessId', 'Unknown')
            decoded['parent_process_id'] = event_data.get('ParentProcessId', 'Unknown')
            decoded['hashes'] = event_data.get('Hashes', 'Unknown')

        # Sysmon Network Connection enrichment
        elif event_id == 3:
            decoded['process_name'] = event_data.get('Image', 'Unknown')
            decoded['source_ip'] = event_data.get('SourceIp', 'Unknown')
            decoded['source_port'] = event_data.get('SourcePort', 'Unknown')
            decoded['destination_ip'] = event_data.get('DestinationIp', 'Unknown')
            decoded['destination_port'] = event_data.get('DestinationPort', 'Unknown')
            decoded['protocol'] = event_data.get('Protocol', 'Unknown')
            decoded['user'] = event_data.get('User', 'Unknown')

        # PowerShell Script Block enrichment
        elif event_id == 4104:
            decoded['script_block_text'] = event_data.get('ScriptBlockText', '')
            decoded['script_block_id'] = event_data.get('ScriptBlockId', 'Unknown')
            decoded['path'] = event_data.get('Path', 'Unknown')

        # Windows Firewall enrichment
        elif event_id in [5152, 5154, 5156, 5157]:
            decoded['application'] = event_data.get('Application', 'Unknown')
            decoded['source_address'] = event_data.get('SourceAddress', 'Unknown')
            decoded['source_port'] = event_data.get('SourcePort', 'Unknown')
            decoded['dest_address'] = event_data.get('DestAddress', 'Unknown')
            decoded['dest_port'] = event_data.get('DestPort', 'Unknown')
            decoded['protocol'] = event_data.get('Protocol', 'Unknown')
            decoded['filter_run_time_id'] = event_data.get('FilterRTID', 'Unknown')

        # AppLocker enrichment
        elif event_id in [8003, 8004, 8006, 8007]:
            decoded['file_path'] = event_data.get('FilePath', event_data.get('FullFilePath', 'Unknown'))
            decoded['file_hash'] = event_data.get('FileHash', 'Unknown')
            decoded['user'] = event_data.get('User', 'Unknown')
            decoded['rule_name'] = event_data.get('RuleName', 'Unknown')

    def _assess_windows_event_severity(self, event_id: int, event_data: Dict[str, Any]) -> str:
        """Assess severity of Windows events."""

        # High severity events
        high_severity_events = [
            1116, 1117,  # Defender threats
            4625,  # Failed logon
            4672,  # Special privileges assigned
            4720, 4726,  # User created/deleted
            5001,  # Defender disabled
            5157,  # Firewall blocked connection
            8004, 8007  # AppLocker blocked
        ]

        # Medium severity events
        medium_severity_events = [
            4624,  # Successful logon
            4648,  # Explicit credentials
            4104,  # PowerShell script block
            1,  # Sysmon process creation
            3,  # Sysmon network connection
            5152,  # Firewall blocked packet
            8003, 8006  # AppLocker allowed
        ]

        if event_id in high_severity_events:
            return 'high'
        elif event_id in medium_severity_events:
            return 'medium'
        else:
            return 'low'

    def _update_category_stats(self, log_type: str):
        """Update statistics for event categories."""
        if 'defender' in log_type:
            self.stats['defender_events'] += 1
        elif 'security' in log_type:
            self.stats['security_events'] += 1
        elif 'sysmon' in log_type:
            self.stats['sysmon_events'] += 1
        elif 'powershell' in log_type:
            self.stats['powershell_events'] += 1
        elif 'firewall' in log_type:
            self.stats['firewall_events'] += 1
        elif 'applocker' in log_type:
            self.stats['applocker_events'] += 1

    def get_statistics(self) -> Dict[str, int]:
        return self.stats.copy()