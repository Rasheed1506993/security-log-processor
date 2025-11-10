import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class LogDecoder:
    """
    Main decoder for basic security agent logs.
    Handles standard log formats for common security events.
    """

    def __init__(self):
        self.log_patterns = {
            'file_integrity': r'FIM\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+):\s+(.+)',
            'process': r'PROC\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+PID:(\d+)\s+User:(\w+)\s+Cmd:(.+)',
            'network': r'NET\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)',
            'authentication': r'AUTH\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+)\s+User:(\w+)\s+From:(.+)',
            'registry': r'REG\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+):\s+Key:(.+)\s+Value:(.+)',
            'service': r'SVC\s+\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+):\s+Service:(.+)\s+Status:(\w+)'
        }
        self.stats = {
            'total_processed': 0,
            'successful_decodes': 0,
            'failed_decodes': 0
        }

    def decode_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Decode a single log line based on its type."""
        self.stats['total_processed'] += 1

        for log_type, pattern in self.log_patterns.items():
            match = re.match(pattern, log_line.strip())
            if match:
                decoder_method = getattr(self, f'decode_{log_type}_log')
                decoded = decoder_method(match.groups())
                self.stats['successful_decodes'] += 1
                return decoded

        self.stats['failed_decodes'] += 1
        return None

    def decode_file_integrity_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, action, filepath = match
        return {
            'log_type': 'file_integrity',
            'timestamp': timestamp,
            'action': action,
            'file_path': filepath,
            'file_name': Path(filepath).name,
            'file_extension': Path(filepath).suffix,
            'directory': str(Path(filepath).parent),
            'severity': self._assess_file_severity(filepath, action)
        }

    def decode_process_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, pid, user, command = match
        return {
            'log_type': 'process',
            'timestamp': timestamp,
            'process_id': int(pid),
            'user': user,
            'command': command,
            'process_name': command.split()[0] if command else '',
            'arguments': ' '.join(command.split()[1:]) if len(command.split()) > 1 else '',
            'severity': self._assess_process_severity(command, user)
        }

    def decode_network_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, protocol, src_ip, src_port, dst_ip, dst_port = match
        return {
            'log_type': 'network',
            'timestamp': timestamp,
            'protocol': protocol,
            'source_ip': src_ip,
            'source_port': int(src_port),
            'destination_ip': dst_ip,
            'destination_port': int(dst_port),
            'direction': 'outbound',
            'is_internal': self._is_internal_ip(dst_ip),
            'severity': self._assess_network_severity(dst_ip, int(dst_port))
        }

    def decode_authentication_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, result, user, source = match
        return {
            'log_type': 'authentication',
            'timestamp': timestamp,
            'result': result,
            'user': user,
            'source': source,
            'is_success': result.lower() == 'success',
            'severity': 'high' if result.lower() == 'failed' else 'low'}

    def decode_registry_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, action, key, value = match
        return {
            'log_type': 'registry',
            'timestamp': timestamp,
            'action': action,
            'registry_key': key,
            'registry_value': value,
            'is_sensitive': self._is_sensitive_registry(key),
            'severity': self._assess_registry_severity(key, action)
        }

    def decode_service_log(self, match: tuple) -> Dict[str, Any]:
        timestamp, action, service_name, status = match
        return {
            'log_type': 'service',
            'timestamp': timestamp,
            'action': action,
            'service_name': service_name,
            'status': status,
            'severity': self._assess_service_severity(service_name, action)
        }

    def _assess_file_severity(self, filepath: str, action: str) -> str:
        sensitive_paths = ['/etc/', '/bin/', '/usr/bin/', 'C:\\Windows\\System32']
        sensitive_extensions = ['.exe', '.dll', '.sys', '.bat', '.ps1', '.sh']

        if any(path in filepath for path in sensitive_paths):
            return 'high'
        if any(filepath.endswith(ext) for ext in sensitive_extensions):
            return 'medium'
        if action.lower() in ['deleted', 'modified']:
            return 'medium'
        return 'low'

    def _assess_process_severity(self, command: str, user: str) -> str:
        suspicious_commands = ['powershell', 'cmd.exe', 'bash', 'nc', 'netcat', 'wget', 'curl']
        if any(cmd in command.lower() for cmd in suspicious_commands):
            return 'high'
        return 'medium'

    def _assess_network_severity(self, dst_ip: str, dst_port: int) -> str:
        high_risk_ports = [22, 23, 3389, 445, 135]
        if not self._is_internal_ip(dst_ip):
            if dst_port in high_risk_ports:
                return 'high'
            return 'medium'
        return 'low'

    def _assess_registry_severity(self, key: str, action: str) -> str:
        critical_keys = ['CurrentVersion\\Run', 'CurrentVersion\\RunOnce', 'Services']
        if any(critical in key for critical in critical_keys):
            return 'high'
        return 'medium'

    def _assess_service_severity(self, service_name: str, action: str) -> str:
        critical_services = ['firewall', 'antivirus', 'security', 'defender']
        if any(svc in service_name.lower() for svc in critical_services):
            return 'high'
        return 'medium'

    def _is_internal_ip(self, ip: str) -> bool:
        internal_patterns = [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', r'^192\.168\.']
        return any(re.match(pattern, ip) for pattern in internal_patterns)

    def _is_sensitive_registry(self, key: str) -> bool:
        sensitive_patterns = ['Run', 'Services', 'Policies', 'Security']
        return any(pattern in key for pattern in sensitive_patterns)

    def get_statistics(self) -> Dict[str, int]:
        return self.stats.copy()