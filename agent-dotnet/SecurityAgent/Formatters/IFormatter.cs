using SecurityAgent.Models;

namespace SecurityAgent.Formatters
{
    /// <summary>
    /// Interface for log formatters
    /// </summary>
    public interface IFormatter
    {
        string FormatFileIntegrity(FileChange change);
        string FormatProcess(ProcessInfo process);
        string FormatNetwork(NetworkConnection connection);
        string FormatAuthentication(string result, string user, string source, DateTime timestamp);
        string FormatRegistry(RegistryChange change);
        string FormatService(string action, string serviceName, string status, DateTime timestamp);
    }
}
