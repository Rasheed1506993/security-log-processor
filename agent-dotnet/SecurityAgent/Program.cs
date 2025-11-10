using SecurityAgent.Collectors;
using SecurityAgent.Formatters;
using SecurityAgent.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace SecurityAgent
{
    internal class Program
    {
        private static LogWriter? _logWriter;
        private static List<ICollector> _collectors = new();
        private static IFormatter? _formatter;
        private static bool _running = true;

        static void Main(string[] args)
        {
            Console.WriteLine("======================================================================");
            Console.WriteLine("  Windows Security Log Collection Agent (.NET)");
            Console.WriteLine("======================================================================");

            // Load configuration
            var configPath = args.Length > 0 ? args[0] : "Config/agent_config.json";
            var config = LoadConfiguration(configPath);

            // Initialize formatter based on config
            var format = config["output"]?["format"]?.ToString() ?? "mixed";
            _formatter = format.ToLower() switch
            {
                "json" => new JsonFormatter(),
                "windows" => new WindowsFormatter(),
                _ => new BasicFormatter()
            };

            // Initialize log writer
            var logFile = config["output"]?["log_file"]?.ToString() ?? "../../app/data/input/agent_logs.txt";
            var maxSizeMB = config["output"]?["max_size_mb"]?.ToObject<int>() ?? 100;
            var backupCount = config["output"]?["backup_count"]?.ToObject<int>() ?? 5;

            _logWriter = new LogWriter(logFile, maxSizeMB, backupCount);
            Console.WriteLine($"[SecurityAgent] Output: {logFile}");
            Console.WriteLine($"[SecurityAgent] Formatter: {_formatter.GetType().Name}");
            Console.WriteLine();

            // Start collectors
            StartCollectors(config);

            // Handle Ctrl+C
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                _running = false;
                Console.WriteLine("\n[SecurityAgent] Stopping...");
            };

            // Statistics loop
            Console.WriteLine("Press Ctrl+C to stop...\n");
            var statsInterval = TimeSpan.FromSeconds(60);
            var lastStatsTime = DateTime.Now;

            while (_running)
            {
                Thread.Sleep(1000);

                if ((DateTime.Now - lastStatsTime) >= statsInterval)
                {
                    PrintStatistics();
                    lastStatsTime = DateTime.Now;
                }
            }

            // Cleanup
            StopCollectors();
            _logWriter.Dispose();
            Console.WriteLine("[SecurityAgent] Stopped");
        }

        private static JObject LoadConfiguration(string configPath)
        {
            try
            {
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JObject.Parse(json);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SecurityAgent] Error loading config: {ex.Message}");
            }

            // Default configuration
            return JObject.FromObject(new
            {
                collectors = new
                {
                    windows_events = new { enabled = true, poll_interval = 10 },
                    file_integrity = new { enabled = true, watch_paths = new[] { @"C:\Windows\System32", @"C:\Windows\System32\drivers" } },
                    process_monitoring = new { enabled = true }
                },
                output = new
                {
                    log_file = "../../app/data/input/agent_logs.txt",
                    max_size_mb = 100,
                    backup_count = 5,
                    format = "mixed"
                }
            });
        }

        private static void StartCollectors(JObject config)
        {
            var collectorsConfig = config["collectors"];
            if (collectorsConfig == null) return;

            // Windows Event Collector
            if (collectorsConfig["windows_events"]?["enabled"]?.ToObject<bool>() == true)
            {
                var pollInterval = collectorsConfig["windows_events"]?["poll_interval"]?.ToObject<int>() ?? 10;
                var collector = new WindowsEventCollector(OnWindowsEvent, pollInterval);
                collector.Start();
                _collectors.Add(collector);
            }

            // File Integrity Collector
            if (collectorsConfig["file_integrity"]?["enabled"]?.ToObject<bool>() == true)
            {
                var paths = collectorsConfig["file_integrity"]?["watch_paths"]?.ToObject<string[]>();
                var collector = new FileIntegrityCollector(OnFileChange, paths);
                collector.Start();
                _collectors.Add(collector);
            }

            // Process Collector
            if (collectorsConfig["process_monitoring"]?["enabled"]?.ToObject<bool>() == true)
            {
                var collector = new ProcessCollector(OnProcessCreated);
                collector.Start();
                _collectors.Add(collector);
            }

            Console.WriteLine("======================================================================");
            Console.WriteLine($"  Agent Started - {_collectors.Count} collectors active");
            Console.WriteLine("======================================================================\n");
        }

        private static void StopCollectors()
        {
            foreach (var collector in _collectors)
            {
                collector.Stop();
            }
            _collectors.Clear();
        }

        private static void OnWindowsEvent(string eventLog)
        {
            // Windows events come pre-formatted
            _logWriter?.WriteLog(eventLog);
        }

        private static void OnFileChange(Models.FileChange change)
        {
            var log = _formatter?.FormatFileIntegrity(change) ?? string.Empty;
            _logWriter?.WriteLog(log);
        }

        private static void OnProcessCreated(Models.ProcessInfo process)
        {
            // Filter out our own processes
            if (process.ProcessName.Contains("SecurityAgent", StringComparison.OrdinalIgnoreCase))
                return;

            var log = _formatter?.FormatProcess(process) ?? string.Empty;
            _logWriter?.WriteLog(log);
        }

        private static void PrintStatistics()
        {
            Console.WriteLine("\n======================================================================");
            Console.WriteLine("  Agent Statistics");
            Console.WriteLine("======================================================================\n");

            Console.WriteLine($"Agent Status: Running");
            Console.WriteLine($"Active Collectors: {_collectors.Count}\n");

            if (_logWriter != null)
            {
                Console.WriteLine("Log Writer:");
                var stats = _logWriter.GetStatistics();
                foreach (var kvp in stats)
                {
                    Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
                }
                Console.WriteLine();
            }

            Console.WriteLine("Collectors:\n");
            foreach (var collector in _collectors)
            {
                Console.WriteLine($"  {collector.GetType().Name}:");
                var stats = collector.GetStatistics();
                foreach (var kvp in stats)
                {
                    Console.WriteLine($"    {kvp.Key}: {kvp.Value}");
                }
                Console.WriteLine();
            }

            Console.WriteLine("======================================================================\n");
        }
    }
}
