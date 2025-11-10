"""
Thread-safe Log Writer
Writes logs to file with rotation support and thread safety
"""
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional


class LogWriter:
    """
    Thread-safe log writer with rotation support.
    Ensures multiple collectors can write simultaneously without conflicts.
    """

    def __init__(self, log_file_path: str, max_size_mb: int = 100, backup_count: int = 5):
        """
        Initialize LogWriter

        Args:
            log_file_path: Path to the output log file
            max_size_mb: Maximum size of log file before rotation (in MB)
            backup_count: Number of backup files to keep
        """
        self.log_file_path = Path(log_file_path)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.lock = threading.Lock()

        # Ensure directory exists
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Create file if it doesn't exist
        if not self.log_file_path.exists():
            self.log_file_path.touch()

    def write_log(self, log_message: str) -> bool:
        """
        Write a log message to file in a thread-safe manner.

        Args:
            log_message: The log message to write

        Returns:
            True if write was successful, False otherwise
        """
        try:
            with self.lock:
                # Check if rotation is needed
                if self._should_rotate():
                    self._rotate_logs()

                # Write the log
                with open(self.log_file_path, 'a', encoding='utf-8') as f:
                    f.write(log_message + '\n')

                return True

        except Exception as e:
            print(f"[LogWriter] Error writing log: {e}")
            return False

    def write_logs_batch(self, log_messages: list) -> int:
        """
        Write multiple log messages in a single operation (more efficient).

        Args:
            log_messages: List of log messages to write

        Returns:
            Number of messages successfully written
        """
        if not log_messages:
            return 0

        try:
            with self.lock:
                # Check if rotation is needed
                if self._should_rotate():
                    self._rotate_logs()

                # Write all logs
                with open(self.log_file_path, 'a', encoding='utf-8') as f:
                    for message in log_messages:
                        f.write(message + '\n')

                return len(log_messages)

        except Exception as e:
            print(f"[LogWriter] Error writing batch logs: {e}")
            return 0

    def _should_rotate(self) -> bool:
        """Check if log file should be rotated based on size."""
        try:
            if not self.log_file_path.exists():
                return False

            file_size = self.log_file_path.stat().st_size
            return file_size >= self.max_size_bytes

        except Exception:
            return False

    def _rotate_logs(self):
        """
        Rotate log files:
        - agent_logs.txt -> agent_logs.txt.1
        - agent_logs.txt.1 -> agent_logs.txt.2
        - etc.
        """
        try:
            # Delete oldest backup if it exists
            oldest_backup = Path(f"{self.log_file_path}.{self.backup_count}")
            if oldest_backup.exists():
                oldest_backup.unlink()

            # Rotate existing backups
            for i in range(self.backup_count - 1, 0, -1):
                old_backup = Path(f"{self.log_file_path}.{i}")
                new_backup = Path(f"{self.log_file_path}.{i + 1}")

                if old_backup.exists():
                    old_backup.rename(new_backup)

            # Rotate current log file
            if self.log_file_path.exists():
                backup_path = Path(f"{self.log_file_path}.1")
                self.log_file_path.rename(backup_path)

            # Create new empty log file
            self.log_file_path.touch()

            print(f"[LogWriter] Log file rotated: {self.log_file_path}")

        except Exception as e:
            print(f"[LogWriter] Error rotating logs: {e}")

    def get_file_size_mb(self) -> float:
        """Get current log file size in MB."""
        try:
            if self.log_file_path.exists():
                return self.log_file_path.stat().st_size / (1024 * 1024)
            return 0.0
        except Exception:
            return 0.0

    def get_stats(self) -> dict:
        """Get writer statistics."""
        try:
            stats = {
                'log_file': str(self.log_file_path),
                'file_exists': self.log_file_path.exists(),
                'file_size_mb': self.get_file_size_mb(),
                'max_size_mb': self.max_size_bytes / (1024 * 1024),
                'backup_count': self.backup_count
            }

            if self.log_file_path.exists():
                stats['modified_time'] = datetime.fromtimestamp(
                    self.log_file_path.stat().st_mtime
                ).strftime('%Y-%m-%d %H:%M:%S')

            # Count backup files
            backup_files = []
            for i in range(1, self.backup_count + 1):
                backup_path = Path(f"{self.log_file_path}.{i}")
                if backup_path.exists():
                    backup_files.append({
                        'name': backup_path.name,
                        'size_mb': backup_path.stat().st_size / (1024 * 1024)
                    })

            stats['backups'] = backup_files

            return stats

        except Exception as e:
            return {'error': str(e)}
