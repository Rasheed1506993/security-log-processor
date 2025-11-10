namespace SecurityAgent.Models
{
    /// <summary>
    /// Registry change information model
    /// </summary>
    public class RegistryChange
    {
        public string Action { get; set; } = string.Empty;
        public string KeyPath { get; set; } = string.Empty;
        public string ValueName { get; set; } = string.Empty;
        public string ValueData { get; set; } = string.Empty;
        public string PreviousData { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}
