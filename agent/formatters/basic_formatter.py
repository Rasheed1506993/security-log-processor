"""
Basic Log Formatter
Formats logs into FIM, PROC, NET, AUTH, REG, SVC formats
Compatible with LogDecoder from the main system
"""
from datetime import datetime
from typing import Dict, Any


class BasicFormatter:
    """
    Formats security events into basic log format compatible with LogDecoder.
    Supported formats: FIM, PROC, NET, AUTH, REG, SVC
    """

    @staticmethod
    def format_file_integrity(file_path: str, action: str, timestamp: datetime = None) -> str:
        """
        Format: FIM [YYYY-MM-DD HH:MM:SS] ACTION: FILE_PATH
        Example: FIM [2025-11-05 10:19:00] modified: C:\Windows\System32\drivers\etc\hosts
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"FIM [{timestamp_str}] {action}: {file_path}"

    @staticmethod
    def format_process(pid: int, user: str, command: str, timestamp: datetime = None) -> str:
        """
        Format: PROC [YYYY-MM-DD HH:MM:SS] PID:XXX User:USER Cmd:COMMAND
        Example: PROC [2025-11-05 10:20:00] PID:1234 User:admin Cmd:powershell.exe -enc XXX
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"PROC [{timestamp_str}] PID:{pid} User:{user} Cmd:{command}"

    @staticmethod
    def format_network(protocol: str, src_ip: str, src_port: int,
                       dst_ip: str, dst_port: int, timestamp: datetime = None) -> str:
        """
        Format: NET [YYYY-MM-DD HH:MM:SS] PROTOCOL SRC_IP:SRC_PORT -> DST_IP:DST_PORT
        Example: NET [2025-11-05 10:21:00] TCP 192.168.1.10:5000 -> 8.8.8.8:443
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"NET [{timestamp_str}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    @staticmethod
    def format_authentication(result: str, user: str, source: str, timestamp: datetime = None) -> str:
        """
        Format: AUTH [YYYY-MM-DD HH:MM:SS] RESULT User:USER From:SOURCE
        Example: AUTH [2025-11-05 10:22:00] failed User:admin From:192.168.1.100
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"AUTH [{timestamp_str}] {result} User:{user} From:{source}"

    @staticmethod
    def format_registry(action: str, key: str, value: str, timestamp: datetime = None) -> str:
        """
        Format: REG [YYYY-MM-DD HH:MM:SS] ACTION: Key:KEY_PATH Value:VALUE
        Example: REG [2025-11-05 10:23:00] modified: Key:HKLM\Software\Run Value:malware.exe
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"REG [{timestamp_str}] {action}: Key:{key} Value:{value}"

    @staticmethod
    def format_service(action: str, service_name: str, status: str, timestamp: datetime = None) -> str:
        """
        Format: SVC [YYYY-MM-DD HH:MM:SS] ACTION: Service:SERVICE_NAME Status:STATUS
        Example: SVC [2025-11-05 10:24:00] stopped: Service:WinDefend Status:stopped
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"SVC [{timestamp_str}] {action}: Service:{service_name} Status:{status}"
