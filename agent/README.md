# Windows Security Log Collection Agent

A comprehensive security log collection agent for Windows systems that monitors and collects security events in real-time.

## 🎯 Overview

This agent collects security logs from multiple sources and formats them for analysis by the Security Log Processor system. It runs continuously in the background, monitoring:

- **Windows Event Logs** (Security, Defender, Firewall, PowerShell, Sysmon)
- **File Integrity** (file creation, modification, deletion in critical directories)
- **Process Creation** (new process detection with full details)
- **Network Connections** (new network connections with process information)
- **Registry Changes** (modifications to critical registry keys)

## 📋 Features

### ✅ Multi-Source Collection
- **5 different collectors** working simultaneously
- Thread-safe operation with no conflicts
- Low system overhead

### ✅ Multiple Output Formats
- **Basic Format**: FIM, PROC, NET, AUTH, REG, SVC
- **Windows Format**: Structured Windows Event Log format
- **JSON Format**: Rich structured JSON logs
- **Mixed Format**: Automatic format selection based on event type

### ✅ Smart Log Management
- Thread-safe log writing
- Automatic log rotation (configurable size limits)
- Backup file management
- No data loss

### ✅ Full Compatibility
- 100% compatible with existing decoders (LogDecoder, WindowsDecoder, GenericDecoder)
- Output directly consumable by the main processing system
- No additional parsing required

---

## 🚀 Quick Start

### Prerequisites

- **Windows 10/11** or **Windows Server 2016+**
- **Python 3.8+**
- **Administrator privileges** (required for some collectors)

### Installation

1. **Install Python dependencies:**
```bash
cd agent
pip install -r requirements.txt
```

2. **Configure the agent (optional):**
Edit `config/agent_config.json` to customize:
- Which collectors to enable
- Poll intervals
- Watch paths
- Output format

3. **Run the agent:**
```bash
# With default configuration
python agent.py

# With custom configuration
python agent.py config/agent_config.json
```

4. **Run as Administrator (recommended):**
```powershell
# Right-click PowerShell -> Run as Administrator
python agent.py
```

---

## ⚙️ Configuration

### Configuration File Structure

```json
{
  "collectors": {
    "windows_events": {
      "enabled": true,
      "poll_interval": 10
    },
    "file_integrity": {
      "enabled": true,
      "recursive": false,
      "watch_paths": [
        "C:\\Windows\\System32",
        "C:\\Program Files"
      ]
    },
    "process_monitoring": {
      "enabled": true,
      "poll_interval": 2
    },
    "network_monitoring": {
      "enabled": true,
      "poll_interval": 5
    },
    "registry_monitoring": {
      "enabled": true,
      "poll_interval": 30
    }
  },
  "output": {
    "log_file": "../app/data/input/agent_logs.txt",
    "max_size_mb": 100,
    "backup_count": 5,
    "format": "mixed"
  }
}
```

### Configuration Options

#### Collectors

| Collector | Description | Poll Interval | Admin Required |
|-----------|-------------|---------------|----------------|
| `windows_events` | Windows Event Logs | 10s | ✅ Yes |
| `file_integrity` | File system monitoring | Real-time | ⚠️ Partial |
| `process_monitoring` | Process creation | 2s | ⚠️ Partial |
| `network_monitoring` | Network connections | 5s | ✅ Yes |
| `registry_monitoring` | Registry changes | 30s | ✅ Yes |

#### Output Formats

- **`mixed`**: (Default) Uses appropriate format for each event type
- **`basic`**: All events in FIM/PROC/NET/AUTH/REG/SVC format
- **`windows`**: All events in Windows Event Log structured format
- **`json`**: All events in rich JSON format

---

## 📊 Collectors Detail

### 1. Windows Event Collector

**Sources:**
- `Security` - Authentication and privilege events (Event IDs: 4624, 4625, 4672, etc.)
- `Microsoft-Windows-Windows Defender/Operational` - Threat detection (1116, 1117, etc.)
- `Microsoft-Windows-Windows Firewall` - Firewall events (5031, 5152, 5157, etc.)
- `Microsoft-Windows-PowerShell/Operational` - PowerShell execution (4103, 4104, etc.)

**Output Example:**
```
Event ID: 4625 TimeCreated: 2025-11-05T10:17:00 LogonType: 3 TargetUserName: Administrator IpAddress: 192.168.1.200
```

### 2. File Integrity Monitoring

**Monitored Paths:**
- `C:\Windows\System32` - System binaries
- `C:\Windows\SysWOW64` - 32-bit system binaries
- `C:\Windows\System32\drivers` - Device drivers
- `C:\Program Files` - Installed applications

**Output Example:**
```
FIM [2025-11-05 10:19:00] modified: C:\Windows\System32\drivers\etc\hosts
```

### 3. Process Monitoring

**Captured Information:**
- Process ID (PID)
- Process name and executable path
- Command line arguments
- Parent process information
- User account
- Creation time

**Output Example:**
```
PROC [2025-11-05 10:20:00] PID:1234 User:admin Cmd:powershell.exe -ExecutionPolicy Bypass
```

### 4. Network Monitoring

**Captured Information:**
- Protocol (TCP/UDP)
- Local and remote IP addresses
- Local and remote ports
- Process name and PID
- Internal vs external classification

**Output Example:**
```
NET [2025-11-05 10:21:00] TCP 192.168.1.10:5000 -> 8.8.8.8:443
```

### 5. Registry Monitoring

**Monitored Keys:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Auto-start programs
- `HKLM\SYSTEM\CurrentControlSet\Services` - Windows services
- `HKLM\Software\Microsoft\Windows Defender` - Defender settings
- Windows Firewall and Security Policy keys

**Output Example:**
```
REG [2025-11-05 10:23:00] modified: Key:HKLM\Software\Microsoft\Windows\CurrentVersion\Run Value:SuspiciousApp=C:\malware.exe
```

---

## 🔧 Usage Examples

### Basic Usage

```bash
# Start agent with default config
python agent.py

# Start with custom config
python agent.py my_config.json
```

### Running as a Service

To run the agent as a Windows service, you can use tools like:
- **NSSM** (Non-Sucking Service Manager)
- **Windows Task Scheduler** (run at startup)

**Example with Task Scheduler:**
1. Open Task Scheduler
2. Create Task -> Run whether user is logged on or not
3. Trigger: At startup
4. Action: Start program -> `python.exe` with argument: `C:\path\to\agent.py`
5. Check "Run with highest privileges"

---

## 📈 Monitoring and Statistics

The agent prints statistics every 60 seconds:

```
======================================================================
  Agent Statistics
======================================================================

Agent Status: Running
Active Collectors: 5

Log Writer:
  File: ../app/data/input/agent_logs.txt
  Size: 45.32 MB
  Backups: 2

Collectors:

  windows_events:
    running: True
    events_collected: 1523
    security_events: 892
    defender_events: 45
    firewall_events: 234
    powershell_events: 352

  file_integrity:
    running: True
    events_collected: 67
    files_created: 12
    files_modified: 45
    files_deleted: 10

  process_monitoring:
    running: True
    events_collected: 234
    processes_detected: 234

  network_monitoring:
    running: True
    events_collected: 456
    connections_detected: 456
    tcp_connections: 398
    udp_connections: 58

  registry_monitoring:
    running: True
    events_collected: 12
    changes_detected: 12

======================================================================
```

---

## 🔍 Troubleshooting

### Common Issues

**1. "Access Denied" errors**
- **Solution**: Run as Administrator
- Some collectors (Windows Events, Registry, Network) require elevated privileges

**2. No Windows events collected**
- **Solution**: Check Event Log service is running: `Get-Service EventLog`
- Verify you have permissions to read event logs

**3. File integrity monitoring not working**
- **Solution**: Check watch paths exist
- Verify you have read permissions on monitored directories
- Some paths may require Administrator access

**4. High CPU usage**
- **Solution**: Increase poll intervals in config
- Disable recursive file monitoring
- Reduce number of monitored paths

**5. Log file growing too fast**
- **Solution**: Adjust `max_size_mb` in config
- Increase rotation threshold
- Disable verbose collectors

### Debug Mode

To enable verbose logging, modify the code to set `log_level` to `DEBUG`.

---

## 🏗️ Architecture

```
agent.py (Main Orchestrator)
├── collectors/
│   ├── windows_collector.py      (PowerShell + wevtutil)
│   ├── file_integrity_collector.py  (watchdog)
│   ├── process_collector.py      (psutil)
│   ├── network_collector.py      (psutil)
│   └── registry_collector.py     (reg query)
├── formatters/
│   ├── basic_formatter.py        (FIM/PROC/NET/AUTH/REG/SVC)
│   ├── windows_formatter.py      (Windows Event format)
│   └── json_formatter.py         (JSON format)
└── utils/
    └── log_writer.py              (Thread-safe writer + rotation)
```

---

## 🔐 Security Considerations

1. **Run with least privilege**: Only use Administrator when necessary
2. **Protect log files**: Logs contain sensitive security information
3. **Secure configuration**: Protect `agent_config.json` from unauthorized access
4. **Monitor agent**: Ensure agent is running and hasn't been tampered with
5. **Log rotation**: Prevent disk space exhaustion

---

## 📝 Integration with Main System

The agent outputs logs to `app/data/input/agent_logs.txt` which is automatically consumed by the main processing system:

```bash
# The main system will process these logs
cd ..
python run.py
```

The processing pipeline:
1. **Agent** → Collects logs → Writes to `agent_logs.txt`
2. **Enhanced Server** → Reads `agent_logs.txt` → Decodes with 3 decoders
3. **Rules Engine** → Applies security rules → Generates alerts
4. **API Server** → Exposes data via REST API
5. **React Frontend** → Displays in web interface

---

## 🛠️ Development

### Adding a New Collector

1. Create new collector in `collectors/` directory
2. Implement `start()`, `stop()`, and `get_stats()` methods
3. Add to agent.py initialization
4. Update configuration schema

### Adding a New Format

1. Create new formatter in `formatters/` directory
2. Implement formatting methods
3. Add to agent.py format mapping
4. Test compatibility with decoders

---

## 📊 Performance

**Resource Usage (typical):**
- CPU: 1-3%
- RAM: 50-100 MB
- Disk I/O: Minimal (buffered writes)
- Network: None (local only)

**Event Collection Rate:**
- Windows Events: 10-100 events/minute
- File Changes: Variable (depends on activity)
- Process Creation: 5-20 processes/minute
- Network Connections: 10-50 connections/minute
- Registry Changes: 1-5 changes/minute

---

## 📄 License

Part of the Security Log Processor system.

---

## 🤝 Support

For issues or questions, check:
1. This README
2. Configuration file comments
3. Code comments and docstrings
4. Main system documentation

---

## ✅ Checklist for Deployment

- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Configuration customized (`config/agent_config.json`)
- [ ] Running as Administrator
- [ ] Output path accessible
- [ ] Sufficient disk space for logs
- [ ] Main processing system configured to read agent logs
- [ ] Monitoring/alerting configured for agent health

---

**Note**: This agent is designed specifically for Windows systems and requires appropriate permissions to access security-sensitive information.
