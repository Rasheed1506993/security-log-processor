using System.Diagnostics.Eventing.Reader;

namespace SecurityAgent.Collectors
{
    /// <summary>
    /// Collects Windows Event Logs using EventLogReader
    /// Much more efficient than Python's PowerShell approach
    /// </summary>
    public class WindowsEventCollector : ICollector
    {
        private readonly Action<string> _callback;
        private readonly int _pollIntervalMs;
        private CancellationTokenSource? _cts;
        private Task? _collectionTask;
        private DateTime _lastCheckTime;

        private readonly Dictionary<string, int[]> _eventSources = new()
        {
            ["Security"] = new[] { 4624, 4625, 4634, 4672, 4673, 4720, 4722, 4724, 4726 },
            ["Microsoft-Windows-Windows Defender/Operational"] = new[] { 1116, 1117, 1118, 1119, 2000, 2001, 5001 },
            ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"] = new[] { 5031, 5152, 5154, 5156, 5157 },
            ["Microsoft-Windows-PowerShell/Operational"] = new[] { 4103, 4104, 4105, 4106 }
        };

        private readonly Dictionary<string, int> _stats = new()
        {
            ["events_collected"] = 0,
            ["security_events"] = 0,
            ["defender_events"] = 0,
            ["firewall_events"] = 0,
            ["powershell_events"] = 0,
            ["errors"] = 0
        };

        public bool IsRunning { get; private set; }

        public WindowsEventCollector(Action<string> callback, int pollIntervalSeconds = 10)
        {
            _callback = callback;
            _pollIntervalMs = pollIntervalSeconds * 1000;
            _lastCheckTime = DateTime.Now.AddMinutes(-1); // Start with last 1 minute
        }

        public void Start()
        {
            if (IsRunning) return;

            IsRunning = true;
            _cts = new CancellationTokenSource();
            _collectionTask = Task.Run(() => CollectionLoop(_cts.Token));
            Console.WriteLine($"[WindowsEventCollector] Started (polling every {_pollIntervalMs / 1000}s)");
        }

        public void Stop()
        {
            if (!IsRunning) return;

            IsRunning = false;
            _cts?.Cancel();
            _collectionTask?.Wait(TimeSpan.FromSeconds(5));
            Console.WriteLine("[WindowsEventCollector] Stopped");
        }

        private async Task CollectionLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    foreach (var source in _eventSources)
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        var events = CollectFromSource(source.Key, source.Value);
                        foreach (var eventLog in events)
                        {
                            _callback(eventLog);
                            _stats["events_collected"]++;

                            // Update category stats
                            if (source.Key.Contains("Security"))
                                _stats["security_events"]++;
                            else if (source.Key.Contains("Defender"))
                                _stats["defender_events"]++;
                            else if (source.Key.Contains("Firewall"))
                                _stats["firewall_events"]++;
                            else if (source.Key.Contains("PowerShell"))
                                _stats["powershell_events"]++;
                        }
                    }

                    await Task.Delay(_pollIntervalMs, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[WindowsEventCollector] Error: {ex.Message}");
                    _stats["errors"]++;
                    await Task.Delay(_pollIntervalMs, cancellationToken);
                }
            }
        }

        private List<string> CollectFromSource(string logName, int[] eventIds)
        {
            var events = new List<string>();

            try
            {
                var startTime = _lastCheckTime;
                var endTime = DateTime.Now;
                _lastCheckTime = endTime;

                // Build query
                var eventIdFilter = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
                var query = $"*[System[(({eventIdFilter}) and TimeCreated[@SystemTime>='{startTime:o}' and @SystemTime<='{endTime:o}'])]]";

                using var reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, query));

                EventRecord? eventRecord;
                while ((eventRecord = reader.ReadEvent()) != null)
                {
                    using (eventRecord)
                    {
                        var formattedEvent = FormatEvent(eventRecord);
                        if (!string.IsNullOrEmpty(formattedEvent))
                        {
                            events.Add(formattedEvent);
                        }
                    }
                }
            }
            catch (EventLogException)
            {
                // Log might not exist or access denied - silently skip
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WindowsEventCollector] Error reading {logName}: {ex.Message}");
            }

            return events;
        }

        private static string FormatEvent(EventRecord eventRecord)
        {
            try
            {
                var eventId = eventRecord.Id;
                var timeCreated = eventRecord.TimeCreated?.ToString("yyyy-MM-ddTHH:mm:ss") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");

                var result = $"Event ID: {eventId} TimeCreated: {timeCreated}";

                // Extract event data
                if (eventRecord.Properties != null)
                {
                    var xml = eventRecord.ToXml();
                    if (!string.IsNullOrEmpty(xml))
                    {
                        // Parse XML to get property names
                        var doc = System.Xml.Linq.XDocument.Parse(xml);
                        var ns = doc.Root?.GetDefaultNamespace() ?? System.Xml.Linq.XNamespace.None;
                        var eventData = doc.Root?.Element(ns + "EventData");

                        if (eventData != null)
                        {
                            foreach (var data in eventData.Elements(ns + "Data"))
                            {
                                var name = data.Attribute("Name")?.Value;
                                var value = data.Value;

                                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(value))
                                {
                                    result += $" {name}: {value}";
                                }
                            }
                        }
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WindowsEventCollector] Error formatting event: {ex.Message}");
                return string.Empty;
            }
        }

        public Dictionary<string, object> GetStatistics()
        {
            return new Dictionary<string, object>(_stats)
            {
                ["running"] = IsRunning,
                ["poll_interval_s"] = _pollIntervalMs / 1000,
                ["sources_monitored"] = _eventSources.Count
            };
        }
    }
}
