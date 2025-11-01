using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Xml.Linq;

[SupportedOSPlatform("windows")]
static class Program
{
    static void Main(string[] args)
    {
        // Check for admin privileges and relaunch if needed
        if (!IsAdministrator())
        {
            RelaunchAsAdmin(args);
            return;
        }

        // Show intro and manual
        ShowIntroAndManual();

        // Parse command-line args or prompt user
        string processName = args.Length > 0 ? args[0] : PromptForProcessName();
        int daysToLookBack = args.Length > 1 ? ParseDays(args[1]) : PromptForDays();

        // Normalize process name
        if (!processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            processName += ".exe";
        }

        // Query and process events
        var events = ReadProcessEvents(processName, daysToLookBack);

        // Display results
        DisplayResults(events);

        Console.WriteLine("\nPress Enter to exit...");
        Console.ReadLine();
    }

    static bool IsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void RelaunchAsAdmin(string[] args)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath!,
            UseShellExecute = true,
            Verb = "runas"
        };

        if (args.Length > 0)
        {
            startInfo.Arguments = string.Join(" ", args.Select(a => $"\"{a}\""));
        }

        try
        {
            Process.Start(startInfo);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to elevate: {ex.Message}");
            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }
    }

    static string PromptForProcessName()
    {
        Console.Write("Enter process name (e.g., javaw or javaw.exe): ");
        return Console.ReadLine()?.Trim() ?? string.Empty;
    }

    static int PromptForDays()
    {
        Console.Write("Days to look back [30]: ");
        var input = Console.ReadLine()?.Trim();

        if (string.IsNullOrWhiteSpace(input))
            return 30;

        return ParseDays(input);
    }

    static int ParseDays(string input)
    {
        if (!int.TryParse(input, out int days) || days <= 0)
        {
            Console.WriteLine("Invalid number of days. Using default of 30.");
            return 30;
        }
        return days;
    }

    static void ShowIntroAndManual()
    {
        Console.WriteLine("=============================================================================");
        Console.WriteLine("  Process Start/Stop Log Reader");
        Console.WriteLine("=============================================================================");
        Console.WriteLine();
        Console.WriteLine("This application lists launches and exits for a given process from the");
        Console.WriteLine("Windows Security event log. It reads Event IDs 4688 (process start) and");
        Console.WriteLine("4689 (process exit) and pairs them to show how long each instance ran.");
        Console.WriteLine();
        Console.WriteLine("=============================================================================");
        Console.WriteLine();
        
        var edition = Environment.OSVersion.Version.Major >= 10
            ? GetWindowsEdition()
            : "Professional";

        if (edition.Contains("Home", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("To enable process tracking on Windows Home, run these commands as Administrator:");
            Console.WriteLine();
            Console.WriteLine("  auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable");
            Console.WriteLine("  auditpol /set /subcategory:\"Process Termination\" /success:enable /failure:enable");
            Console.WriteLine();
            Console.WriteLine("Optional - to include command line in events:");
            Console.WriteLine("  reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f");
        }
        else
        {
            Console.WriteLine("To enable process tracking:");
            Console.WriteLine();
            Console.WriteLine("1. Open secpol.msc (Local Security Policy)");
            Console.WriteLine("   Navigate to: Security Settings > Advanced Audit Policy Configuration");
            Console.WriteLine("   > System Audit Policies > Detailed Tracking");
            Console.WriteLine("   Enable: Audit Process Creation (Success)");
            Console.WriteLine("   Enable: Audit Process Termination (Success)");
            Console.WriteLine();
            Console.WriteLine("2. Open gpedit.msc (Group Policy Editor)");
            Console.WriteLine("   Navigate to: Computer Configuration > Administrative Templates");
            Console.WriteLine("   > System > Audit Process Creation");
            Console.WriteLine("   Enable: Include command line in process creation events");
        }
        Console.WriteLine();
    }

    static string GetWindowsEdition()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("EditionID")?.ToString() ?? "Professional";
        }
        catch
        {
            return "Professional";
        }
    }

    static List<ProcessEvent> ReadProcessEvents(string processName, int daysToLookBack)
    {
        var cutoffTime = DateTime.Now.AddDays(-daysToLookBack);
        var processStarts = new Dictionary<string, Queue<ProcessEvent>>();
        var completedEvents = new List<ProcessEvent>();

        string query = "*[System[(EventID=4688 or EventID=4689)]]";

        try
        {
            var eventLogQuery = new EventLogQuery("Security", PathType.LogName, query);
            eventLogQuery.ReverseDirection = false; // Read oldest first for efficient pairing

            using var reader = new EventLogReader(eventLogQuery);

            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    if (record.TimeCreated == null || record.TimeCreated < cutoffTime)
                        continue;

                    var xml = XDocument.Parse(record.ToXml());
                    var ns = xml.Root?.Name.Namespace ?? XNamespace.None;
                    var eventData = xml.Descendants(ns + "EventData").FirstOrDefault();

                    if (eventData == null)
                        continue;

                    var dataDict = eventData.Elements(ns + "Data")
                        .Where(e => e.Attribute("Name") != null)
                        .ToDictionary(
                            e => e.Attribute("Name")!.Value,
                            e => e.Value
                        );

                    if (record.Id == 4688) // Process start
                    {
                        if (!dataDict.TryGetValue("NewProcessName", out var procPath))
                            continue;

                        if (!Path.GetFileName(procPath).Equals(processName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (!dataDict.TryGetValue("NewProcessId", out var newPid) ||
                            !dataDict.TryGetValue("SubjectLogonId", out var logonId))
                            continue;

                        var key = $"{newPid}_{logonId}";
                        var evt = new ProcessEvent
                        {
                            Start = record.TimeCreated.Value,
                            ProcessName = Path.GetFileName(procPath)
                        };

                        if (!processStarts.ContainsKey(key))
                            processStarts[key] = new Queue<ProcessEvent>();

                        processStarts[key].Enqueue(evt);
                    }
                    else if (record.Id == 4689) // Process exit
                    {
                        if (!dataDict.TryGetValue("ProcessName", out var procPath))
                            continue;

                        if (!Path.GetFileName(procPath).Equals(processName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (!dataDict.TryGetValue("ProcessId", out var pid) ||
                            !dataDict.TryGetValue("SubjectLogonId", out var logonId))
                            continue;

                        var key = $"{pid}_{logonId}";

                        if (processStarts.TryGetValue(key, out var queue) && queue.Count > 0)
                        {
                            var evt = queue.Dequeue();
                            evt.Finish = record.TimeCreated.Value;
                            completedEvents.Add(evt);
                        }
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Access denied to Security log. Administrator privileges required.");
            return completedEvents;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading event log: {ex.Message}");
            return completedEvents;
        }

        // Add unmatched starts
        foreach (var queue in processStarts.Values)
        {
            while (queue.Count > 0)
            {
                completedEvents.Add(queue.Dequeue());
            }
        }

        return completedEvents;
    }

    static void DisplayResults(List<ProcessEvent> events)
    {
        Console.WriteLine("\nResults:");
        Console.WriteLine();

        if (events.Count == 0)
        {
            Console.WriteLine("No matching events found. Process tracking may not be enabled.");
            return;
        }

        // Sort by Start descending
        var sorted = events.OrderByDescending(e => e.Start).ToList();

        // Print header
        Console.WriteLine($"{"Start",-21} {"Finish",-21} {"Duration",-10} Process");
        Console.WriteLine(new string('-', 70));

        // Print rows
        foreach (var evt in sorted)
        {
            var start = evt.Start.ToString("yyyy-MM-dd HH:mm:ss");
            var finish = evt.Finish?.ToString("yyyy-MM-dd HH:mm:ss") ?? new string(' ', 19);
            var duration = evt.Finish.HasValue
                ? FormatDuration(evt.Finish.Value - evt.Start)
                : new string(' ', 8);

            Console.WriteLine($"{start,-21} {finish,-21} {duration,-10} {evt.ProcessName}");
        }
    }

    static string FormatDuration(TimeSpan duration)
    {
        return $"{(int)duration.TotalHours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}";
    }

    class ProcessEvent
    {
        public DateTime Start { get; set; }
        public DateTime? Finish { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }
}
