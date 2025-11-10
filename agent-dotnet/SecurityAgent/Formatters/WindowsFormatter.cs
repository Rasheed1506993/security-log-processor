using SecurityAgent.Models;
using System.Text;

namespace SecurityAgent.Formatters
{
    /// <summary>
    /// Windows Event Log formatter
    /// Compatible with WindowsDecoder from the main system
    /// </summary>
    public class WindowsFormatter : IFormatter
    {
        public string FormatWindowsEvent(int eventId, Dictionary<string, string> eventData, DateTime timestamp)
        {
            // Format: Event ID: XXX TimeCreated: TIMESTAMP KEY1: VALUE1 KEY2: VALUE2 ...
            var time = timestamp.ToString("yyyy-MM-ddTHH:mm:ss");
            var sb = new StringBuilder();
            sb.Append($"Event ID: {eventId} TimeCreated: {time}");

            foreach (var kvp in eventData)
            {
                sb.Append($" {kvp.Key}: {kvp.Value}");
            }

            return sb.ToString();
        }

        // Implement IFormatter interface (delegates to JSON formatter or N/A)
        public string FormatFileIntegrity(FileChange change)
        {
            // Not typically used for Windows formatter
            return $"Event ID: 5145 TimeCreated: {change.Timestamp:yyyy-MM-ddTHH:mm:ss} ObjectName: {change.FilePath} AccessMask: {change.Action}";
        }

        public string FormatProcess(ProcessInfo process)
        {
            // Not typically used for Windows formatter
            return $"Event ID: 4688 TimeCreated: {process.CreateTime:yyyy-MM-ddTHH:mm:ss} NewProcessId: {process.ProcessId} NewProcessName: {process.ExecutablePath} SubjectUserName: {process.UserName} CommandLine: {process.CommandLine}";
        }

        public string FormatNetwork(NetworkConnection connection)
        {
            // Not typically used for Windows formatter
            return $"Event ID: 5156 TimeCreated: {connection.Timestamp:yyyy-MM-ddTHH:mm:ss} SourceAddress: {connection.LocalAddress} SourcePort: {connection.LocalPort} DestAddress: {connection.RemoteAddress} DestPort: {connection.RemotePort} Protocol: {connection.Protocol}";
        }

        public string FormatAuthentication(string result, string user, string source, DateTime timestamp)
        {
            var eventId = result.ToLower() == "success" ? 4624 : 4625;
            return $"Event ID: {eventId} TimeCreated: {timestamp:yyyy-MM-ddTHH:mm:ss} LogonType: 3 TargetUserName: {user} IpAddress: {source}";
        }

        public string FormatRegistry(RegistryChange change)
        {
            // Not typically used for Windows formatter
            return $"Event ID: 4657 TimeCreated: {change.Timestamp:yyyy-MM-ddTHH:mm:ss} ObjectName: {change.KeyPath} ObjectValueName: {change.ValueName} NewValue: {change.ValueData}";
        }

        public string FormatService(string action, string serviceName, string status, DateTime timestamp)
        {
            var eventId = status.ToLower() == "running" ? 7036 : 7040;
            return $"Event ID: {eventId} TimeCreated: {timestamp:yyyy-MM-ddTHH:mm:ss} ServiceName: {serviceName} State: {status}";
        }
    }
}
