"""
Windows Event Log Formatter
Formats Windows events into structured format compatible with WindowsDecoder
"""
from datetime import datetime
from typing import Dict, Any


class WindowsFormatter:
    """
    Formats Windows events into structured format compatible with WindowsDecoder.
    Supports two formats: structured key-value and XML.
    """

    @staticmethod
    def format_structured_event(event_id: int, event_data: Dict[str, Any],
                                 timestamp: datetime = None) -> str:
        """
        Format: Event ID: XXX TimeCreated: TIMESTAMP KEY1: VALUE1 KEY2: VALUE2 ...
        Example: Event ID: 4625 TimeCreated: 2025-11-05T10:17:00 LogonType: 3 TargetUserName: Administrator IpAddress: 192.168.1.200
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%dT%H:%M:%S')

        # Build the event data string
        event_data_str = ' '.join([f"{key}: {value}" for key, value in event_data.items()])

        return f"Event ID: {event_id} TimeCreated: {timestamp_str} {event_data_str}"

    @staticmethod
    def format_xml_event(event_id: int, provider: str, computer: str,
                        event_data: Dict[str, Any], timestamp: datetime = None) -> str:
        """
        Format: Full Windows Event Log XML format
        This is more complex and provides full compatibility with Windows Event Viewer
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%dT%H:%M:%S')

        # Build EventData section
        event_data_xml = '\n'.join([
            f'    <Data Name="{key}">{value}</Data>'
            for key, value in event_data.items()
        ])

        xml = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp_str}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
{event_data_xml}
  </EventData>
</Event>"""

        return xml

    @staticmethod
    def format_security_logon(event_id: int, logon_type: int, target_user: str,
                              source_ip: str, timestamp: datetime = None) -> str:
        """Quick format for security logon events (4624, 4625)"""
        event_data = {
            'LogonType': logon_type,
            'TargetUserName': target_user,
            'IpAddress': source_ip
        }
        return WindowsFormatter.format_structured_event(event_id, event_data, timestamp)

    @staticmethod
    def format_defender_threat(event_id: int, threat_name: str, severity: str,
                               action: str, resource_path: str, timestamp: datetime = None) -> str:
        """Quick format for Windows Defender events (1116, 1117)"""
        event_data = {
            'ThreatName': threat_name,
            'Severity': severity,
            'Action': action,
            'ResourcePath': resource_path
        }
        return WindowsFormatter.format_structured_event(event_id, event_data, timestamp)

    @staticmethod
    def format_firewall_block(event_id: int, application: str, source_address: str,
                              source_port: str, dest_address: str, dest_port: str,
                              protocol: str, timestamp: datetime = None) -> str:
        """Quick format for Windows Firewall events (5152, 5157)"""
        event_data = {
            'Application': application,
            'SourceAddress': source_address,
            'SourcePort': source_port,
            'DestAddress': dest_address,
            'DestPort': dest_port,
            'Protocol': protocol
        }
        return WindowsFormatter.format_structured_event(event_id, event_data, timestamp)

    @staticmethod
    def format_powershell_script(event_id: int, script_block_text: str,
                                 script_block_id: str, path: str = 'Unknown',
                                 timestamp: datetime = None) -> str:
        """Quick format for PowerShell events (4104)"""
        event_data = {
            'ScriptBlockText': script_block_text,
            'ScriptBlockId': script_block_id,
            'Path': path
        }
        return WindowsFormatter.format_structured_event(event_id, event_data, timestamp)
