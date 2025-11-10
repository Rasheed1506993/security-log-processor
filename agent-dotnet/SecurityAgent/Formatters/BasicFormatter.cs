using SecurityAgent.Models;

namespace SecurityAgent.Formatters
{
    /// <summary>
    /// Basic log formatter (FIM, PROC, NET, AUTH, REG, SVC)
    /// Compatible with LogDecoder from the main system
    /// </summary>
    public class BasicFormatter : IFormatter
    {
        public string FormatFileIntegrity(FileChange change)
        {
            // Format: FIM [YYYY-MM-DD HH:MM:SS] ACTION: FILE_PATH
            var timestamp = change.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            return $"FIM [{timestamp}] {change.Action}: {change.FilePath}";
        }

        public string FormatProcess(ProcessInfo process)
        {
            // Format: PROC [YYYY-MM-DD HH:MM:SS] PID:XXX User:USER Cmd:COMMAND
            var timestamp = process.CreateTime.ToString("yyyy-MM-dd HH:mm:ss");
            var command = !string.IsNullOrEmpty(process.CommandLine)
                ? process.CommandLine
                : process.ProcessName;

            return $"PROC [{timestamp}] PID:{process.ProcessId} User:{process.UserName} Cmd:{command}";
        }

        public string FormatNetwork(NetworkConnection connection)
        {
            // Format: NET [YYYY-MM-DD HH:MM:SS] PROTOCOL SRC_IP:SRC_PORT -> DST_IP:DST_PORT
            var timestamp = connection.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            return $"NET [{timestamp}] {connection.Protocol} {connection.LocalAddress}:{connection.LocalPort} -> {connection.RemoteAddress}:{connection.RemotePort}";
        }

        public string FormatAuthentication(string result, string user, string source, DateTime timestamp)
        {
            // Format: AUTH [YYYY-MM-DD HH:MM:SS] RESULT User:USER From:SOURCE
            var time = timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            return $"AUTH [{time}] {result} User:{user} From:{source}";
        }

        public string FormatRegistry(RegistryChange change)
        {
            // Format: REG [YYYY-MM-DD HH:MM:SS] ACTION: Key:KEY_PATH Value:VALUE
            var timestamp = change.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            var value = !string.IsNullOrEmpty(change.ValueName)
                ? $"{change.ValueName}={change.ValueData}"
                : change.ValueData;

            return $"REG [{timestamp}] {change.Action}: Key:{change.KeyPath} Value:{value}";
        }

        public string FormatService(string action, string serviceName, string status, DateTime timestamp)
        {
            // Format: SVC [YYYY-MM-DD HH:MM:SS] ACTION: Service:SERVICE_NAME Status:STATUS
            var time = timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            return $"SVC [{time}] {action}: Service:{serviceName} Status:{status}";
        }
    }
}
