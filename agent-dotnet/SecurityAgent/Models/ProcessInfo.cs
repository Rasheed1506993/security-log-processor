namespace SecurityAgent.Models
{
    /// <summary>
    /// Process information model
    /// </summary>
    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = string.Empty;
        public DateTime CreateTime { get; set; }
        public long MemoryUsageMB { get; set; }
    }
}
