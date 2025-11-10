using System.Diagnostics;
using System.Management;
using SecurityAgent.Models;

namespace SecurityAgent.Collectors
{
    /// <summary>
    /// Monitors process creation using WMI
    /// Much more efficient than polling in Python
    /// </summary>
    public class ProcessCollector : ICollector
    {
        private readonly Action<ProcessInfo> _callback;
        private ManagementEventWatcher? _watcher;
        private readonly Dictionary<string, int> _stats = new()
        {
            ["events_collected"] = 0,
            ["processes_detected"] = 0,
            ["errors"] = 0
        };

        public bool IsRunning { get; private set; }

        public ProcessCollector(Action<ProcessInfo> callback)
        {
            _callback = callback;
        }

        public void Start()
        {
            if (IsRunning) return;

            try
            {
                // WMI query to watch for process creation
                var query = new WqlEventQuery("__InstanceCreationEvent",
                    TimeSpan.FromSeconds(1),
                    "TargetInstance ISA 'Win32_Process'");

                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += OnProcessCreated;
                _watcher.Start();

                IsRunning = true;
                Console.WriteLine("[ProcessCollector] Started (WMI event monitoring)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ProcessCollector] Failed to start: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _watcher?.Stop();
            _watcher?.Dispose();
            IsRunning = false;
            Console.WriteLine("[ProcessCollector] Stopped");
        }

        private void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];

                var processInfo = new ProcessInfo
                {
                    ProcessId = Convert.ToInt32(targetInstance["ProcessId"]),
                    ProcessName = targetInstance["Name"]?.ToString() ?? "Unknown",
                    ExecutablePath = targetInstance["ExecutablePath"]?.ToString() ?? "Unknown",
                    CommandLine = targetInstance["CommandLine"]?.ToString() ?? string.Empty,
                    ParentProcessId = Convert.ToInt32(targetInstance["ParentProcessId"]),
                    CreateTime = ManagementDateTimeConverter.ToDateTime(targetInstance["CreationDate"]?.ToString() ?? DateTime.Now.ToString())
                };

                // Get user name
                try
                {
                    using var process = Process.GetProcessById(processInfo.ProcessId);
                    processInfo.UserName = GetProcessUser(process);
                    processInfo.ParentProcessName = GetParentProcessName(processInfo.ParentProcessId);
                }
                catch
                {
                    processInfo.UserName = "Unknown";
                    processInfo.ParentProcessName = "Unknown";
                }

                _callback(processInfo);
                _stats["events_collected"]++;
                _stats["processes_detected"]++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ProcessCollector] Error processing event: {ex.Message}");
                _stats["errors"]++;
            }
        }

        private static string GetProcessUser(Process process)
        {
            try
            {
                var query = $"SELECT * FROM Win32_Process WHERE ProcessId = {process.Id}";
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    var ownerInfo = new string[2];
                    obj.InvokeMethod("GetOwner", ownerInfo);
                    return $"{ownerInfo[1]}\\{ownerInfo[0]}";
                }
            }
            catch { }
            return "Unknown";
        }

        private static string GetParentProcessName(int parentId)
        {
            try
            {
                using var parent = Process.GetProcessById(parentId);
                return parent.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        public Dictionary<string, object> GetStatistics()
        {
            return new Dictionary<string, object>(_stats)
            {
                ["running"] = IsRunning
            };
        }
    }
}
