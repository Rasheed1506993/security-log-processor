namespace SecurityAgent.Models
{
    /// <summary>
    /// File system change information model
    /// </summary>
    public class FileChange
    {
        public string Action { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string OldFilePath { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}
