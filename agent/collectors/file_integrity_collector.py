"""
File Integrity Monitoring Collector
Monitors file system changes in specified directories
"""
import os
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Callable, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class FileIntegrityCollector:
    """
    Monitors file system changes using watchdog library.
    Watches specified directories for file creation, modification, deletion, and moves.
    """

    def __init__(self, watch_paths: List[str] = None, recursive: bool = True):
        """
        Initialize File Integrity Collector

        Args:
            watch_paths: List of directories to monitor
            recursive: Whether to monitor subdirectories
        """
        self.recursive = recursive
        self.observer = None
        self.callback = None
        self.running = False

        # Default Windows critical paths
        if watch_paths is None:
            watch_paths = [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                'C:\\Windows\\System32\\drivers',
                'C:\\Windows\\System32\\config',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
                'C:\\Users\\Public'
            ]

        # Filter to only existing paths
        self.watch_paths = [path for path in watch_paths if os.path.exists(path)]

        self.stats = {
            'events_collected': 0,
            'files_created': 0,
            'files_modified': 0,
            'files_deleted': 0,
            'files_moved': 0,
            'errors': 0
        }

        print(f"[FileIntegrityCollector] Initialized with {len(self.watch_paths)} watch paths")

    def start(self, callback: Callable[[str], None]):
        """
        Start monitoring file system changes.

        Args:
            callback: Function to call with each event (signature: callback(log_entry: str))
        """
        if self.running:
            print("[FileIntegrityCollector] Already running")
            return

        self.callback = callback
        self.running = True

        # Create observer
        self.observer = Observer()

        # Create event handler
        event_handler = FIMEventHandler(self._on_file_event)

        # Schedule monitoring for each watch path
        for watch_path in self.watch_paths:
            try:
                self.observer.schedule(event_handler, watch_path, recursive=self.recursive)
                print(f"[FileIntegrityCollector] Watching: {watch_path}")
            except Exception as e:
                print(f"[FileIntegrityCollector] Error watching {watch_path}: {e}")
                self.stats['errors'] += 1

        # Start observer thread
        self.observer.start()
        print("[FileIntegrityCollector] Started")

    def stop(self):
        """Stop monitoring."""
        if not self.running:
            return

        self.running = False

        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)

        print("[FileIntegrityCollector] Stopped")

    def _on_file_event(self, event_type: str, file_path: str):
        """
        Handle file system event.

        Args:
            event_type: Type of event (created, modified, deleted, moved)
            file_path: Path to the affected file
        """
        try:
            if self.callback:
                self.callback(event_type, file_path)

            self.stats['events_collected'] += 1

            # Update specific counters
            if event_type == 'created':
                self.stats['files_created'] += 1
            elif event_type == 'modified':
                self.stats['files_modified'] += 1
            elif event_type == 'deleted':
                self.stats['files_deleted'] += 1
            elif event_type == 'moved':
                self.stats['files_moved'] += 1

        except Exception as e:
            print(f"[FileIntegrityCollector] Error handling event: {e}")
            self.stats['errors'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            'running': self.running,
            'watch_paths': self.watch_paths,
            'watch_count': len(self.watch_paths),
            'recursive': self.recursive,
            **self.stats
        }


class FIMEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler for file integrity monitoring.
    Converts watchdog events into FIM events.
    """

    def __init__(self, callback: Callable[[str, str], None]):
        """
        Initialize event handler.

        Args:
            callback: Function to call with (event_type, file_path)
        """
        super().__init__()
        self.callback = callback

        # Ignore temporary and system files
        self.ignore_patterns = [
            '.tmp', '.temp', '~$', '.swp', '.swo',
            'Thumbs.db', 'desktop.ini', '.DS_Store',
            '.git', '.svn', '__pycache__',
            '.log', '.bak'
        ]

    def _should_ignore(self, path: str) -> bool:
        """Check if file should be ignored."""
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in self.ignore_patterns)

    def on_created(self, event: FileSystemEvent):
        """Handle file/directory creation."""
        if not event.is_directory and not self._should_ignore(event.src_path):
            self.callback('created', event.src_path)

    def on_modified(self, event: FileSystemEvent):
        """Handle file/directory modification."""
        if not event.is_directory and not self._should_ignore(event.src_path):
            self.callback('modified', event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        """Handle file/directory deletion."""
        if not event.is_directory and not self._should_ignore(event.src_path):
            self.callback('deleted', event.src_path)

    def on_moved(self, event: FileSystemEvent):
        """Handle file/directory move."""
        if not event.is_directory and not self._should_ignore(event.dest_path):
            self.callback('moved', f"{event.src_path} -> {event.dest_path}")
