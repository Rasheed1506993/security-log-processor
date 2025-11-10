using SecurityAgent.Models;

namespace SecurityAgent.Collectors
{
    /// <summary>
    /// Monitors file system changes using FileSystemWatcher
    /// Native .NET implementation - much more efficient than Python watchdog
    /// </summary>
    public class FileIntegrityCollector : ICollector
    {
        private readonly Action<FileChange> _callback;
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly string[] _watchPaths;
        private readonly Dictionary<string, int> _stats = new()
        {
            ["events_collected"] = 0,
            ["files_created"] = 0,
            ["files_modified"] = 0,
            ["files_deleted"] = 0,
            ["files_renamed"] = 0,
            ["errors"] = 0
        };

        public bool IsRunning { get; private set; }

        public FileIntegrityCollector(Action<FileChange> callback, string[]? watchPaths = null)
        {
            _callback = callback;
            _watchPaths = watchPaths ?? new[]
            {
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                @"C:\Windows\System32\drivers",
                @"C:\Program Files"
            };
        }

        public void Start()
        {
            if (IsRunning) return;

            foreach (var path in _watchPaths)
            {
                if (!Directory.Exists(path))
                {
                    Console.WriteLine($"[FileIntegrityCollector] Path does not exist: {path}");
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(path)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        IncludeSubdirectories = false,
                        EnableRaisingEvents = true
                    };

                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileModified;
                    watcher.Deleted += OnFileDeleted;
                    watcher.Renamed += OnFileRenamed;

                    _watchers.Add(watcher);
                    Console.WriteLine($"[FileIntegrityCollector] Watching: {path}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FileIntegrityCollector] Error watching {path}: {ex.Message}");
                }
            }

            IsRunning = true;
            Console.WriteLine("[FileIntegrityCollector] Started");
        }

        public void Stop()
        {
            if (!IsRunning) return;

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();

            IsRunning = false;
            Console.WriteLine("[FileIntegrityCollector] Stopped");
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (ShouldIgnore(e.FullPath)) return;

            var change = new FileChange
            {
                Action = "created",
                FilePath = e.FullPath,
                Timestamp = DateTime.Now
            };

            _callback(change);
            _stats["events_collected"]++;
            _stats["files_created"]++;
        }

        private void OnFileModified(object sender, FileSystemEventArgs e)
        {
            if (ShouldIgnore(e.FullPath)) return;

            var change = new FileChange
            {
                Action = "modified",
                FilePath = e.FullPath,
                Timestamp = DateTime.Now
            };

            _callback(change);
            _stats["events_collected"]++;
            _stats["files_modified"]++;
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (ShouldIgnore(e.FullPath)) return;

            var change = new FileChange
            {
                Action = "deleted",
                FilePath = e.FullPath,
                Timestamp = DateTime.Now
            };

            _callback(change);
            _stats["events_collected"]++;
            _stats["files_deleted"]++;
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (ShouldIgnore(e.FullPath)) return;

            var change = new FileChange
            {
                Action = "moved",
                FilePath = e.FullPath,
                OldFilePath = e.OldFullPath,
                Timestamp = DateTime.Now
            };

            _callback(change);
            _stats["events_collected"]++;
            _stats["files_renamed"]++;
        }

        private static bool ShouldIgnore(string path)
        {
            var ignoreExtensions = new[] { ".tmp", ".temp", ".log", ".bak", ".swp" };
            var ignoreNames = new[] { "Thumbs.db", "desktop.ini", ".DS_Store" };

            var fileName = Path.GetFileName(path).ToLower();
            var extension = Path.GetExtension(path).ToLower();

            return ignoreExtensions.Contains(extension) || ignoreNames.Contains(fileName);
        }

        public Dictionary<string, object> GetStatistics()
        {
            return new Dictionary<string, object>(_stats)
            {
                ["running"] = IsRunning,
                ["watch_count"] = _watchers.Count
            };
        }
    }
}
