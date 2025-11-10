using System.Collections.Concurrent;

namespace SecurityAgent.Utils
{
    /// <summary>
    /// Thread-safe log writer with rotation support
    /// </summary>
    public class LogWriter
    {
        private readonly string _logFilePath;
        private readonly long _maxSizeBytes;
        private readonly int _backupCount;
        private readonly object _lock = new object();
        private readonly BlockingCollection<string> _queue;
        private readonly CancellationTokenSource _cts;
        private readonly Task _writerTask;

        public LogWriter(string logFilePath, int maxSizeMB = 100, int backupCount = 5)
        {
            _logFilePath = logFilePath;
            _maxSizeBytes = maxSizeMB * 1024 * 1024;
            _backupCount = backupCount;
            _queue = new BlockingCollection<string>(10000); // Buffer up to 10k messages
            _cts = new CancellationTokenSource();

            // Ensure directory exists
            var directory = Path.GetDirectoryName(_logFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Start background writer
            _writerTask = Task.Run(() => ProcessQueue(_cts.Token));
        }

        public void WriteLog(string message)
        {
            if (!_queue.IsAddingCompleted)
            {
                _queue.Add(message);
            }
        }

        public void WriteLogBatch(IEnumerable<string> messages)
        {
            foreach (var message in messages)
            {
                WriteLog(message);
            }
        }

        private void ProcessQueue(CancellationToken cancellationToken)
        {
            try
            {
                foreach (var message in _queue.GetConsumingEnumerable(cancellationToken))
                {
                    WriteToFile(message);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
        }

        private void WriteToFile(string message)
        {
            try
            {
                lock (_lock)
                {
                    // Check if rotation is needed
                    if (ShouldRotate())
                    {
                        RotateLogs();
                    }

                    // Write the log
                    File.AppendAllText(_logFilePath, message + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LogWriter] Error writing log: {ex.Message}");
            }
        }

        private bool ShouldRotate()
        {
            if (!File.Exists(_logFilePath))
                return false;

            var fileInfo = new FileInfo(_logFilePath);
            return fileInfo.Length >= _maxSizeBytes;
        }

        private void RotateLogs()
        {
            try
            {
                // Delete oldest backup
                var oldestBackup = $"{_logFilePath}.{_backupCount}";
                if (File.Exists(oldestBackup))
                {
                    File.Delete(oldestBackup);
                }

                // Rotate existing backups
                for (int i = _backupCount - 1; i > 0; i--)
                {
                    var oldBackup = $"{_logFilePath}.{i}";
                    var newBackup = $"{_logFilePath}.{i + 1}";

                    if (File.Exists(oldBackup))
                    {
                        File.Move(oldBackup, newBackup);
                    }
                }

                // Rotate current log file
                if (File.Exists(_logFilePath))
                {
                    File.Move(_logFilePath, $"{_logFilePath}.1");
                }

                Console.WriteLine($"[LogWriter] Log file rotated: {_logFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LogWriter] Error rotating logs: {ex.Message}");
            }
        }

        public Dictionary<string, object> GetStatistics()
        {
            var stats = new Dictionary<string, object>
            {
                ["log_file"] = _logFilePath,
                ["file_exists"] = File.Exists(_logFilePath),
                ["queue_count"] = _queue.Count,
                ["max_size_mb"] = _maxSizeBytes / (1024 * 1024),
                ["backup_count"] = _backupCount
            };

            if (File.Exists(_logFilePath))
            {
                var fileInfo = new FileInfo(_logFilePath);
                stats["file_size_mb"] = fileInfo.Length / (1024.0 * 1024.0);
                stats["modified_time"] = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
            }

            return stats;
        }

        public void Dispose()
        {
            _queue.CompleteAdding();
            _cts.Cancel();
            _writerTask.Wait(TimeSpan.FromSeconds(5));
            _cts.Dispose();
            _queue.Dispose();
        }
    }
}
