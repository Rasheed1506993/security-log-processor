namespace SecurityAgent.Collectors
{
    /// <summary>
    /// Interface for all collectors
    /// </summary>
    public interface ICollector
    {
        /// <summary>
        /// Start collecting events
        /// </summary>
        void Start();

        /// <summary>
        /// Stop collecting events
        /// </summary>
        void Stop();

        /// <summary>
        /// Check if collector is running
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Get collector statistics
        /// </summary>
        Dictionary<string, object> GetStatistics();
    }
}
