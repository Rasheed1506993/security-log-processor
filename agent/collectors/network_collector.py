"""
Network Monitoring Collector
Monitors network connections and tracks new connections
"""
import psutil
import time
import threading
from datetime import datetime
from typing import Set, Tuple, Callable, Dict, Any, Optional


class NetworkCollector:
    """
    Monitors network connections by tracking active connections.
    Detects new network connections and collects their information.
    """

    def __init__(self, poll_interval: int = 5):
        """
        Initialize Network Collector

        Args:
            poll_interval: How often to check for new connections (in seconds)
        """
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.known_connections: Set[Tuple] = set()
        self.callback = None

        self.stats = {
            'events_collected': 0,
            'connections_detected': 0,
            'tcp_connections': 0,
            'udp_connections': 0,
            'errors': 0
        }

        # Initialize with current connections
        try:
            self._update_known_connections()
            print(f"[NetworkCollector] Initialized with {len(self.known_connections)} existing connections")
        except Exception as e:
            print(f"[NetworkCollector] Error during initialization: {e}")

    def start(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Start monitoring network connections.

        Args:
            callback: Function to call with connection info dict
        """
        if self.running:
            print("[NetworkCollector] Already running")
            return

        self.callback = callback
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print(f"[NetworkCollector] Started (polling every {self.poll_interval}s)")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[NetworkCollector] Stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Get current connections
                current_connections = self._get_current_connections()

                # Find new connections
                new_connections = current_connections - self.known_connections

                # Process each new connection
                for conn_tuple in new_connections:
                    try:
                        conn_info = self._parse_connection_tuple(conn_tuple)
                        if conn_info and self.callback:
                            self.callback(conn_info)
                            self.stats['events_collected'] += 1
                            self.stats['connections_detected'] += 1

                            # Update protocol stats
                            if conn_info['protocol'] == 'TCP':
                                self.stats['tcp_connections'] += 1
                            elif conn_info['protocol'] == 'UDP':
                                self.stats['udp_connections'] += 1

                    except Exception as e:
                        print(f"[NetworkCollector] Error processing connection: {e}")
                        self.stats['errors'] += 1

                # Update known connections
                self.known_connections = current_connections

                # Sleep until next poll
                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"[NetworkCollector] Error in monitoring loop: {e}")
                self.stats['errors'] += 1
                time.sleep(self.poll_interval)

    def _get_current_connections(self) -> Set[Tuple]:
        """
        Get all current network connections.

        Returns:
            Set of connection tuples (protocol, laddr, raddr, status, pid)
        """
        connections = set()

        try:
            # Get all connections (TCP and UDP)
            for conn in psutil.net_connections(kind='inet'):
                # Only track ESTABLISHED connections and UDP
                if conn.status == psutil.CONN_ESTABLISHED or conn.type == 2:  # type 2 = UDP
                    # Create unique tuple for this connection
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:0"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:0"

                    conn_tuple = (
                        'TCP' if conn.type == 1 else 'UDP',
                        laddr,
                        raddr,
                        conn.status if hasattr(conn, 'status') else 'NONE',
                        conn.pid if conn.pid else 0
                    )

                    connections.add(conn_tuple)

        except (psutil.AccessDenied, PermissionError):
            print("[NetworkCollector] Access denied - requires administrator privileges")
        except Exception as e:
            print(f"[NetworkCollector] Error getting connections: {e}")

        return connections

    def _update_known_connections(self):
        """Update the set of known connections."""
        self.known_connections = self._get_current_connections()

    def _parse_connection_tuple(self, conn_tuple: Tuple) -> Optional[Dict[str, Any]]:
        """
        Parse connection tuple into a dictionary.

        Args:
            conn_tuple: (protocol, laddr, raddr, status, pid)

        Returns:
            Dictionary with connection information
        """
        try:
            protocol, laddr, raddr, status, pid = conn_tuple

            # Parse local address
            laddr_parts = laddr.split(':')
            local_ip = laddr_parts[0]
            local_port = int(laddr_parts[1]) if len(laddr_parts) > 1 else 0

            # Parse remote address
            raddr_parts = raddr.split(':')
            remote_ip = raddr_parts[0]
            remote_port = int(raddr_parts[1]) if len(raddr_parts) > 1 else 0

            # Get process name if available
            process_name = 'Unknown'
            try:
                if pid and pid > 0:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Determine if connection is internal or external
            is_internal = self._is_internal_ip(remote_ip)

            info = {
                'protocol': protocol,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'status': status,
                'pid': pid,
                'process_name': process_name,
                'is_internal': is_internal,
                'timestamp': datetime.now()
            }

            return info

        except Exception as e:
            print(f"[NetworkCollector] Error parsing connection tuple: {e}")
            return None

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private."""
        if ip in ['0.0.0.0', '127.0.0.1', 'localhost', '::1']:
            return True

        # Check private IP ranges
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])

            # 10.0.0.0/8
            if first_octet == 10:
                return True

            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True

            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True

        except ValueError:
            pass

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'tracked_connections': len(self.known_connections),
            **self.stats
        }

    def get_current_connections(self, limit: int = 10) -> list:
        """
        Get information about current connections (for testing).

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection info dictionaries
        """
        connections = []

        try:
            conn_tuples = list(self._get_current_connections())[:limit]

            for conn_tuple in conn_tuples:
                info = self._parse_connection_tuple(conn_tuple)
                if info:
                    connections.append(info)

        except Exception as e:
            print(f"[NetworkCollector] Error getting current connections: {e}")

        return connections
