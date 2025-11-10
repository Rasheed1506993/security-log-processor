using SecurityAgent.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace SecurityAgent.Formatters
{
    /// <summary>
    /// JSON log formatter
    /// Compatible with GenericDecoder from the main system
    /// </summary>
    public class JsonFormatter : IFormatter
    {
        private readonly JsonSerializerSettings _settings;

        public JsonFormatter()
        {
            _settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore
            };
        }

        public string FormatFileIntegrity(FileChange change)
        {
            var obj = new
            {
                timestamp = change.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "file_access",
                file_path = change.FilePath,
                action = change.Action,
                result = "success",
                severity = DetermineSeverity(change.FilePath, change.Action)
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        public string FormatProcess(ProcessInfo process)
        {
            var obj = new
            {
                timestamp = process.CreateTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "process_execution",
                process = new
                {
                    name = process.ProcessName,
                    pid = process.ProcessId,
                    parent_pid = process.ParentProcessId,
                    parent_name = process.ParentProcessName,
                    command_line = process.CommandLine,
                    user = process.UserName,
                    integrity_level = "medium"
                },
                file_info = new
                {
                    path = process.ExecutablePath
                },
                severity = DetermineProcessSeverity(process.ProcessName, process.CommandLine)
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        public string FormatNetwork(NetworkConnection connection)
        {
            var threatIndicators = new List<string>();
            if (!connection.IsInternal)
            {
                threatIndicators.Add("external_connection");
            }

            if (IsSuspiciousPort(connection.RemotePort))
            {
                threatIndicators.Add("suspicious_port");
            }

            var obj = new
            {
                timestamp = connection.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "network_connection",
                source = new
                {
                    ip = connection.LocalAddress,
                    port = connection.LocalPort,
                    hostname = Environment.MachineName
                },
                destination = new
                {
                    ip = connection.RemoteAddress,
                    port = connection.RemotePort,
                    country = "unknown"
                },
                protocol = connection.Protocol,
                bytes_transferred = 0,
                duration_seconds = 0,
                severity = threatIndicators.Count > 0 ? "high" : "medium",
                threat_indicators = threatIndicators.Count > 0 ? threatIndicators : null
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        public string FormatAuthentication(string result, string user, string source, DateTime timestamp)
        {
            var obj = new
            {
                timestamp = timestamp.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "authentication",
                user = user,
                source_ip = source,
                result = result.ToLower(),
                severity = result.ToLower() == "failed" ? "high" : "low",
                details = new
                {
                    attempts = 1,
                    locked = false
                }
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        public string FormatRegistry(RegistryChange change)
        {
            var obj = new
            {
                timestamp = change.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "registry_change",
                action = change.Action,
                registry = new
                {
                    key_path = change.KeyPath,
                    value_name = change.ValueName,
                    value_data = change.ValueData
                },
                severity = DetermineRegistrySeverity(change.KeyPath)
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        public string FormatService(string action, string serviceName, string status, DateTime timestamp)
        {
            var obj = new
            {
                timestamp = timestamp.ToString("yyyy-MM-ddTHH:mm:ss"),
                event_type = "service_change",
                action = action,
                service_name = serviceName,
                status = status,
                severity = DetermineServiceSeverity(serviceName)
            };

            return JsonConvert.SerializeObject(obj, _settings);
        }

        private static string DetermineSeverity(string filePath, string action)
        {
            var sensitive = new[] { "\\Windows\\System32", "\\Program Files", ".exe", ".dll", ".sys" };
            if (sensitive.Any(s => filePath.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return "high";
            }

            if (action.ToLower() == "deleted")
            {
                return "medium";
            }

            return "low";
        }

        private static string DetermineProcessSeverity(string processName, string commandLine)
        {
            var suspicious = new[] { "powershell", "cmd", "wscript", "cscript", "regsvr32" };
            if (suspicious.Any(s => processName.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                                   commandLine.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return "high";
            }

            return "medium";
        }

        private static string DetermineRegistrySeverity(string keyPath)
        {
            var critical = new[] { "Run", "RunOnce", "Services", "Policies" };
            if (critical.Any(k => keyPath.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                return "high";
            }

            return "medium";
        }

        private static string DetermineServiceSeverity(string serviceName)
        {
            var critical = new[] { "firewall", "defender", "security", "antivirus" };
            if (critical.Any(s => serviceName.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return "high";
            }

            return "medium";
        }

        private static bool IsSuspiciousPort(int port)
        {
            var suspicious = new[] { 4444, 31337, 1337, 6666, 12345 };
            return suspicious.Contains(port);
        }
    }
}
