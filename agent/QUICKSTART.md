# Quick Start Guide - Windows Security Agent

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies

```bash
cd agent
pip install -r requirements.txt
```

**Required packages:**
- `psutil` - Process and network monitoring
- `watchdog` - File system monitoring

### Step 2: Run the Agent

**Option A: Using the Batch File (Easiest)**

1. Right-click `start_agent.bat`
2. Select "Run as Administrator"
3. Done! The agent is now running.

**Option B: Using Command Line**

```bash
# Open PowerShell as Administrator
python agent.py
```

**Option C: With Custom Config**

```bash
python agent.py config/agent_config.json
```

### Step 3: Verify It's Working

The agent will output logs to:
```
../app/data/input/agent_logs.txt
```

You should see logs being generated immediately!

---

## 📊 What You'll See

```
======================================================================
  Windows Security Log Collection Agent
======================================================================

[SecurityAgent] Starting Windows Event Collector...
[SecurityAgent] Starting File Integrity Monitoring...
[SecurityAgent] Starting Process Monitoring...
[SecurityAgent] Starting Network Monitoring...
[SecurityAgent] Starting Registry Monitoring...

======================================================================
  Agent Started - 5 collectors active
======================================================================

Press Ctrl+C to stop...
```

---

## ⚙️ Quick Configuration

Edit `config/agent_config.json` to customize:

```json
{
  "collectors": {
    "windows_events": {
      "enabled": true,      // Enable/disable
      "poll_interval": 10   // Check every 10 seconds
    },
    "file_integrity": {
      "enabled": true,
      "watch_paths": [      // Add your paths here
        "C:\\Windows\\System32"
      ]
    }
  },
  "output": {
    "format": "mixed"       // Options: mixed, basic, windows, json
  }
}
```

---

## 🧪 Test Before Running

Run the test suite to verify everything works:

```bash
python test_agent.py
```

This will test all collectors and formatters.

---

## 🔍 Common Issues

### "Access Denied"
**Solution:** Run as Administrator

### "Python not found"
**Solution:** Install Python 3.8+ from https://www.python.org

### "Module not found"
**Solution:** Run `pip install -r requirements.txt`

### No logs generated
**Solution:** Check that output path exists: `../app/data/input/`

---

## 📈 Next Steps

1. **Monitor the output:** Check `../app/data/input/agent_logs.txt`
2. **Process the logs:** Run `python run.py` from the parent directory
3. **View in UI:** Access http://localhost:3000 after processing

---

## 🛑 Stopping the Agent

Press `Ctrl+C` in the terminal running the agent.

---

## 💡 Tips

1. **Run as a Service:** Use Task Scheduler or NSSM for automatic startup
2. **Adjust Intervals:** Increase poll_interval if CPU usage is high
3. **Customize Paths:** Add your critical directories to watch_paths
4. **Check Stats:** Agent prints statistics every 60 seconds
5. **Log Rotation:** Logs auto-rotate at 100 MB (configurable)

---

## 📚 Need More Help?

- Read the full [README.md](README.md)
- Check [agent_config.json](config/agent_config.json) for all options
- Run tests: `python test_agent.py`

---

**That's it! Your security agent is now collecting logs. 🎉**
