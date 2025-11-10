"""
JSON Log Formatter
Formats logs into JSON format compatible with GenericDecoder
"""
import json
from datetime import datetime
from typing import Dict, Any


class JSONFormatter:
    """
    Formats security events into JSON format compatible with GenericDecoder.
    This provides the most flexible and rich format with nested data support.
    """

    @staticmethod
    def format_authentication_event(user: str, result: str, source_ip: str,
                                     reason: str = None, attempts: int = 1,
                                     timestamp: datetime = None) -> str:
        """Format authentication event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': 'authentication',
            'user': user,
            'source_ip': source_ip,
            'result': result,
            'severity': 'high' if result == 'failed' else 'low',
            'details': {
                'attempts': attempts,
                'locked': False
            }
        }

        if reason:
            event['reason'] = reason

        return json.dumps(event, indent=2)

    @staticmethod
    def format_file_access_event(user: str, file_path: str, action: str,
                                  result: str, process_name: str = None,
                                  pid: int = None, parent: str = None,
                                  timestamp: datetime = None) -> str:
        """Format file access event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': 'file_access',
            'user': user,
            'file_path': file_path,
            'action': action,
            'result': result,
            'severity': 'high' if result == 'denied' or 'sensitive' in file_path.lower() else 'medium'
        }

        if process_name or pid or parent:
            event['process'] = {}
            if process_name:
                event['process']['name'] = process_name
            if pid:
                event['process']['pid'] = pid
            if parent:
                event['process']['parent'] = parent

        return json.dumps(event, indent=2)

    @staticmethod
    def format_network_connection(source_ip: str, source_port: int, source_hostname: str,
                                  dest_ip: str, dest_port: int, protocol: str,
                                  bytes_transferred: int = 0, duration: int = 0,
                                  threat_indicators: list = None,
                                  timestamp: datetime = None) -> str:
        """Format network connection event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': 'network_connection',
            'source': {
                'ip': source_ip,
                'port': source_port,
                'hostname': source_hostname
            },
            'destination': {
                'ip': dest_ip,
                'port': dest_port,
                'country': 'unknown'
            },
            'protocol': protocol,
            'bytes_transferred': bytes_transferred,
            'duration_seconds': duration,
            'severity': 'high' if threat_indicators else 'medium'
        }

        if threat_indicators:
            event['threat_indicators'] = threat_indicators

        return json.dumps(event, indent=2)

    @staticmethod
    def format_process_execution(process_name: str, pid: int, parent_pid: int,
                                 parent_name: str, command_line: str, user: str,
                                 file_path: str = None, file_hash: str = None,
                                 signed: bool = None, signer: str = None,
                                 integrity_level: str = 'medium',
                                 flags: list = None,
                                 timestamp: datetime = None) -> str:
        """Format process execution event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': 'process_execution',
            'process': {
                'name': process_name,
                'pid': pid,
                'parent_pid': parent_pid,
                'parent_name': parent_name,
                'command_line': command_line,
                'user': user,
                'integrity_level': integrity_level
            },
            'severity': 'high' if flags else 'medium'
        }

        if file_path or file_hash or signed is not None:
            event['file_info'] = {}
            if file_path:
                event['file_info']['path'] = file_path
            if file_hash:
                event['file_info']['hash'] = file_hash
            if signed is not None:
                event['file_info']['signed'] = signed
            if signer:
                event['file_info']['signer'] = signer

        if flags:
            event['flags'] = flags

        return json.dumps(event, indent=2)

    @staticmethod
    def format_registry_event(action: str, key_path: str, value_name: str,
                              value_data: str = None, user: str = None,
                              process_name: str = None, pid: int = None,
                              timestamp: datetime = None) -> str:
        """Format registry event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': 'registry_change',
            'action': action,
            'registry': {
                'key_path': key_path,
                'value_name': value_name
            },
            'severity': 'high' if 'Run' in key_path or 'Services' in key_path else 'medium'
        }

        if value_data:
            event['registry']['value_data'] = value_data

        if user:
            event['user'] = user

        if process_name or pid:
            event['process'] = {}
            if process_name:
                event['process']['name'] = process_name
            if pid:
                event['process']['pid'] = pid

        return json.dumps(event, indent=2)

    @staticmethod
    def format_custom_event(event_type: str, data: Dict[str, Any],
                           severity: str = 'medium',
                           timestamp: datetime = None) -> str:
        """Format custom event as JSON"""
        if timestamp is None:
            timestamp = datetime.now()

        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': event_type,
            'severity': severity
        }

        event.update(data)

        return json.dumps(event, indent=2)
