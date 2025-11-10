from datetime import datetime
from typing import Dict, List, Any


class ContextBuilder:
    """
    Builds comprehensive contextual information from decoded logs.

    Generates multiple analytical perspectives including:
    - Summary statistics
    - User activity profiles
    - Process hierarchies
    - File operations analysis
    - Network activity breakdown
    - Authentication events
    - System changes tracking
    - Risk assessment
    - Temporal analysis
    - Correlation indicators
    """

    def __init__(self):
        self.context_cache = {
            'users': {},
            'processes': {},
            'files': {},
            'networks': {},
            'timeline': []
        }

    def build_context(self, decoded_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build comprehensive context from decoded logs.

        Args:
            decoded_logs: List of decoded log dictionaries

        Returns:
            Complete context dictionary with all analytical perspectives
        """
        context = {
            'summary': self._build_summary(decoded_logs),
            'user_activity': self._build_user_activity(decoded_logs),
            'process_hierarchy': self._build_process_hierarchy(decoded_logs),
            'file_operations': self._build_file_operations(decoded_logs),
            'network_activity': self._build_network_activity(decoded_logs),
            'authentication_events': self._build_authentication_events(decoded_logs),
            'system_changes': self._build_system_changes(decoded_logs),
            'risk_assessment': self._build_risk_assessment(decoded_logs),
            'temporal_analysis': self._build_temporal_analysis(decoded_logs),
            'correlation_indicators': self._build_correlation_indicators(decoded_logs)
        }
        return context

    def _build_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build summary statistics."""
        log_types = {}
        severity_counts = {'low': 0, 'medium': 0, 'high': 0}

        for log in logs:
            log_type = log.get('log_type', 'unknown')
            log_types[log_type] = log_types.get(log_type, 0) + 1
            severity = log.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_events': len(logs),
            'event_types': log_types,
            'severity_distribution': severity_counts,
            'time_range': self._get_time_range(logs),
            'unique_users': len(set(log.get('user') for log in logs if 'user' in log))
        }

    def _build_user_activity(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build user activity context."""
        user_activities = {}
        for log in logs:
            if 'user' in log:
                user = log['user']
                if user not in user_activities:
                    user_activities[user] = {
                        'event_count': 0,
                        'log_types': set(),
                        'high_severity_count': 0,
                        'first_seen': log.get('timestamp', ''),
                        'last_seen': log.get('timestamp', '')
                    }
                user_activities[user]['event_count'] += 1
                user_activities[user]['log_types'].add(log['log_type'])
                if log.get('severity') == 'high':
                    user_activities[user]['high_severity_count'] += 1
                user_activities[user]['last_seen'] = log.get('timestamp', '')

        for user in user_activities:
            user_activities[user]['log_types'] = list(user_activities[user]['log_types'])

        return user_activities

    def _build_process_hierarchy(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build process execution context."""
        processes = [log for log in logs if log.get('log_type') == 'process' or 'process_name' in log]
        return [{
            'process_id': p.get('process_id', 'Unknown'),
            'process_name': p.get('process_name', 'Unknown'),
            'user': p.get('user', 'Unknown'),
            'command': p.get('command', p.get('command_line', 'Unknown')),
            'timestamp': p.get('timestamp', ''),
            'severity': p.get('severity', 'medium')
        } for p in processes]

    def _build_file_operations(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build file operation context."""
        file_ops = [log for log in logs if log.get('log_type') == 'file_integrity']

        files_by_action = {'created': [], 'modified': [], 'deleted': []}
        sensitive_files = []

        for op in file_ops:
            action = op.get('action', '').lower()
            if action in files_by_action:
                files_by_action[action].append({
                    'path': op.get('file_path', ''),
                    'timestamp': op.get('timestamp', ''),
                    'severity': op.get('severity', 'low')
                })
            if op.get('severity') == 'high':
                sensitive_files.append(op.get('file_path', ''))

        return {
            'operations_by_type': files_by_action,
            'sensitive_files_affected': sensitive_files,
            'total_operations': len(file_ops)
        }

    def _build_network_activity(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build network activity context."""
        network_logs = [log for log in logs if log.get('log_type') == 'network' or 'destination_ip' in log]

        external_connections = []
        internal_connections = []
        unique_destinations = set()

        for net in network_logs:
            dest_ip = net.get('destination_ip', net.get('dest_address', ''))
            unique_destinations.add(dest_ip)

            dest_port = net.get('destination_port', net.get('dest_port', ''))
            conn_info = {
                'destination': f"{dest_ip}:{dest_port}",
                'protocol': net.get('protocol', 'Unknown'),
                'timestamp': net.get('timestamp', ''),
                'severity': net.get('severity', 'medium')
            }

            if net.get('is_internal', False):
                internal_connections.append(conn_info)
            else:
                external_connections.append(conn_info)

        return {
            'external_connections': external_connections,
            'internal_connections': internal_connections,
            'unique_destinations': len(unique_destinations),
            'total_connections': len(network_logs)
        }

    def _build_authentication_events(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build authentication context."""
        auth_logs = [log for log in logs if log.get('log_type') == 'authentication' or
                     log.get('event_category') == 'windows_security']

        failed_attempts = {}
        successful_logins = []

        for auth in auth_logs:
            is_success = auth.get('is_success', True)
            if auth.get('event_id') == 4625:  # Windows failed logon
                is_success = False
            elif auth.get('event_id') == 4624:  # Windows successful logon
                is_success = True

            user = auth.get('user', auth.get('target_user', 'Unknown'))

            if not is_success:
                failed_attempts[user] = failed_attempts.get(user, 0) + 1
            else:
                successful_logins.append({
                    'user': user,
                    'source': auth.get('source', auth.get('source_ip', 'Unknown')),
                    'timestamp': auth.get('timestamp', '')
                })

        return {
            'failed_attempts_by_user': failed_attempts,
            'successful_logins': successful_logins,
            'brute_force_indicators': [user for user, count in failed_attempts.items() if count > 5]
        }

    def _build_system_changes(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build system changes context."""
        registry_changes = [log for log in logs if log.get('log_type') == 'registry']
        service_changes = [log for log in logs if log.get('log_type') == 'service']

        return {
            'registry_modifications': len(registry_changes),
            'sensitive_registry_changes': [r for r in registry_changes if r.get('is_sensitive', False)],
            'service_changes': [{
                'service': s.get('service_name', 'Unknown'),
                'action': s.get('action', 'Unknown'),
                'status': s.get('status', 'Unknown'),
                'timestamp': s.get('timestamp', '')
            } for s in service_changes]
        }

    def _build_risk_assessment(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build risk assessment based on log patterns."""
        high_severity = len([l for l in logs if l.get('severity') == 'high'])
        total = len(logs)
        risk_score = (high_severity / total * 100) if total > 0 else 0

        risk_level = 'low'
        if risk_score > 30:
            risk_level = 'high'
        elif risk_score > 10:
            risk_level = 'medium'

        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'high_severity_events': high_severity,
            'indicators': self._identify_risk_indicators(logs)
        }

    def _build_temporal_analysis(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build temporal analysis of events."""
        if not logs:
            return {'events_per_hour': {}, 'peak_activity_hour': None}

        events_by_hour = {}
        for log in logs:
            try:
                timestamp = log.get('timestamp', '')
                if 'T' in timestamp:
                    hour = datetime.fromisoformat(timestamp.replace('Z', '')).hour
                else:
                    hour = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').hour
                events_by_hour[hour] = events_by_hour.get(hour, 0) + 1
            except:
                continue

        peak_hour = max(events_by_hour.items(), key=lambda x: x[1])[0] if events_by_hour else None

        return {
            'events_per_hour': events_by_hour,
            'peak_activity_hour': peak_hour
        }

    def _build_correlation_indicators(self, logs: List[Dict[str, Any]]) -> List[str]:
        """Identify correlation indicators across different log types."""
        indicators = []

        process_logs = [l for l in logs if 'process' in l.get('log_type', '')]
        network_logs = [l for l in logs if 'network' in l.get('log_type', '') or 'destination_ip' in l]
        file_logs = [l for l in logs if l.get('log_type') == 'file_integrity']
        defender_logs = [l for l in logs if 'defender' in l.get('log_type', '')]

        if len(process_logs) > 0 and len(network_logs) > 0:
            indicators.append('Process execution followed by network activity detected')

        if len(file_logs) > 5 and any(l.get('severity') == 'high' for l in file_logs):
            indicators.append('Multiple file modifications in sensitive locations')

        auth_failures = len([l for l in logs if not l.get('is_success', True) or l.get('event_id') == 4625])
        if auth_failures > 5:
            indicators.append('Multiple authentication failures detected - potential brute force')

        if len(defender_logs) > 0:
            indicators.append('Windows Defender threat detection events present')

        powershell_logs = [l for l in logs if 'powershell' in l.get('log_type', '')]
        if len(powershell_logs) > 3:
            indicators.append('Elevated PowerShell activity detected')

        return indicators

    def _identify_risk_indicators(self, logs: List[Dict[str, Any]]) -> List[str]:
        """Identify specific risk indicators."""
        indicators = []

        suspicious_processes = ['powershell', 'cmd.exe', 'bash', 'nc']
        for log in logs:
            if 'process' in log.get('log_type', ''):
                command = log.get('command', log.get('command_line', '')).lower()
                if any(sp in command for sp in suspicious_processes):
                    indicators.append(f"Suspicious process execution: {log.get('process_name', 'Unknown')}")

        for log in logs:
            if 'network' in log.get('log_type', '') and not log.get('is_internal', True):
                dest = log.get('destination_ip', log.get('dest_address', 'Unknown'))
                indicators.append(f"External network connection to {dest}")

        defender_threats = [l for l in logs if l.get('event_id') in [1116, 1117]]
        for threat in defender_threats:
            threat_name = threat.get('threat_name', 'Unknown')
            indicators.append(f"Malware detected: {threat_name}")

        return list(set(indicators))[:10]

    def _get_time_range(self, logs: List[Dict[str, Any]]) -> Dict[str, str]:
        """Get time range of logs."""
        if not logs:
            return {'start': None, 'end': None}

        timestamps = [log.get('timestamp', '') for log in logs if log.get('timestamp')]
        if not timestamps:
            return {'start': None, 'end': None}

        return {'start': min(timestamps), 'end': max(timestamps)}