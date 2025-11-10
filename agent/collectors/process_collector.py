"""
Process Monitoring Collector
Monitors process creation and tracks running processes
"""
import psutil
import time
import threading
from datetime import datetime
from typing import Set, Callable, Dict, Any, Optional


class ProcessCollector:
    """
    Monitors process creation by tracking active PIDs.
    Detects new processes and collects their information.
    """

    def __init__(self, poll_interval: int = 2):
        """
        Initialize Process Collector

        Args:
            poll_interval: How often to check for new processes (in seconds)
        """
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.known_pids: Set[int] = set()
        self.callback = None

        self.stats = {
            'events_collected': 0,
            'processes_detected': 0,
            'errors': 0
        }

        # Initialize with currently running processes
        try:
            self.known_pids = {p.pid for p in psutil.process_iter()}
            print(f"[ProcessCollector] Initialized with {len(self.known_pids)} existing processes")
        except Exception as e:
            print(f"[ProcessCollector] Error during initialization: {e}")

    def start(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Start monitoring processes.

        Args:
            callback: Function to call with process info dict
        """
        if self.running:
            print("[ProcessCollector] Already running")
            return

        self.callback = callback
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print(f"[ProcessCollector] Started (polling every {self.poll_interval}s)")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[ProcessCollector] Stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Get current PIDs
                current_pids = {p.pid for p in psutil.process_iter()}

                # Find new PIDs
                new_pids = current_pids - self.known_pids

                # Process each new PID
                for pid in new_pids:
                    try:
                        process_info = self._get_process_info(pid)
                        if process_info and self.callback:
                            self.callback(process_info)
                            self.stats['events_collected'] += 1
                            self.stats['processes_detected'] += 1

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process might have already exited or we don't have permission
                        pass
                    except Exception as e:
                        print(f"[ProcessCollector] Error processing PID {pid}: {e}")
                        self.stats['errors'] += 1

                # Update known PIDs
                self.known_pids = current_pids

                # Sleep until next poll
                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"[ProcessCollector] Error in monitoring loop: {e}")
                self.stats['errors'] += 1
                time.sleep(self.poll_interval)

    def _get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a process.

        Args:
            pid: Process ID

        Returns:
            Dictionary with process information
        """
        try:
            proc = psutil.Process(pid)

            # Get process details
            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe() if proc.exe() else 'Unknown',
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'cwd': proc.cwd() if proc.cwd() else 'Unknown',
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()),
                'status': proc.status()
            }

            # Get parent process info
            try:
                parent = proc.parent()
                if parent:
                    info['parent_pid'] = parent.pid
                    info['parent_name'] = parent.name()
                else:
                    info['parent_pid'] = 0
                    info['parent_name'] = 'Unknown'
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['parent_pid'] = 0
                info['parent_name'] = 'Unknown'

            # Get memory and CPU info (optional)
            try:
                mem_info = proc.memory_info()
                info['memory_mb'] = mem_info.rss / (1024 * 1024)
            except Exception:
                info['memory_mb'] = 0

            return info

        except psutil.NoSuchProcess:
            # Process exited before we could get info
            return None
        except psutil.AccessDenied:
            # Don't have permission to access this process
            return None
        except Exception as e:
            print(f"[ProcessCollector] Error getting info for PID {pid}: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'tracked_processes': len(self.known_pids),
            **self.stats
        }

    def get_current_processes(self, limit: int = 10) -> list:
        """
        Get information about current running processes (for testing).

        Args:
            limit: Maximum number of processes to return

        Returns:
            List of process info dictionaries
        """
        processes = []

        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    info = self._get_process_info(proc.pid)
                    if info:
                        processes.append(info)

                    if len(processes) >= limit:
                        break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            print(f"[ProcessCollector] Error getting current processes: {e}")

        return processes
