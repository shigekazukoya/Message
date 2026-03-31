using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace MessageHookTool;

public static class DiagnosticsLogger
{
    private static readonly string LogFilePath = "diag.log";

    [DllImport("user32.dll")]
    internal static extern int GetGuiResources(IntPtr hProcess, int uiFlags);

    [DllImport("dwmapi.dll")]
    private static extern int DwmIsCompositionEnabled(out bool pfEnabled);

    internal static bool GetDwmEnabled()
    {
        DwmIsCompositionEnabled(out bool enabled);
        return enabled;
    }

    // WMI クエリ（呼び出し側で Task.Run に包んで使う）
    public static GpuInfo[] QueryGpuInfos()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DriverVersion, DriverDate FROM Win32_VideoController");
            return searcher.Get()
                .Cast<ManagementObject>()
                .Select(mo => new GpuInfo(
                    mo["Name"]?.ToString() ?? "Unknown",
                    mo["DriverVersion"]?.ToString() ?? "Unknown",
                    ParseDriverDate(mo["DriverDate"]?.ToString())))
                .ToArray();
        }
        catch
        {
            return [];
        }
    }

    private static string ParseDriverDate(string? wmiDate)
    {
        // WMI 日付形式: "20231015000000.000000+000"
        if (wmiDate is { Length: >= 8 })
            return $"{wmiDate[..4]}-{wmiDate[4..6]}-{wmiDate[6..8]}";
        return "Unknown";
    }

    // System イベントログから TDR 関連イベントを新しい順に取得
    public static TdrEvent[] QueryRecentTdrEvents(int maxEntries = 30)
    {
        var results = new List<TdrEvent>();
        try
        {
            var tdrSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "nvlddmkm", "atikmdag", "igfx", "dxgkrnl", "Display" };

            using var log = new EventLog("System");
            // Entries は古い順なので末尾から逆順に走査して最新 N 件を取る
            for (int i = log.Entries.Count - 1; i >= 0 && results.Count < maxEntries; i--)
            {
                var entry = log.Entries[i];
                if (!tdrSources.Contains(entry.Source)) continue;
                results.Add(new TdrEvent(entry.TimeGenerated, entry.Source,
                    entry.EntryType.ToString(), entry.Message?.Split('\n')[0] ?? ""));
            }
        }
        catch { /* アクセス権がない場合は空を返す */ }

        return results.ToArray(); // 既に新しい順
    }

    public static DiagnosticsSnapshot TakeSnapshot(string source, Exception? ex = null)
    {
        using var proc = Process.GetCurrentProcess();
        return new DiagnosticsSnapshot
        {
            Timestamp        = DateTime.Now,
            Source           = source,
            GdiObjects       = GetGuiResources(proc.Handle, 0),
            UserObjects      = GetGuiResources(proc.Handle, 1),
            HandleCount      = proc.HandleCount,
            WorkingSetMB     = proc.WorkingSet64 / 1024 / 1024,
            IsRemoteSession  = SystemInformation.TerminalServerSession,
            DwmEnabled       = GetDwmEnabled(),
            ExceptionMessage = ex?.Message,
            StackTrace       = ex?.StackTrace,
        };
    }

    public static void WriteToFile(DiagnosticsSnapshot snap)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {snap.Source} @ {snap.Timestamp:yyyy-MM-dd HH:mm:ss.fff} ===");
        if (snap.ExceptionMessage != null)
        {
            sb.AppendLine($"Exception   : {snap.ExceptionMessage}");
            sb.AppendLine($"Stack       : {snap.StackTrace}");
        }
        sb.AppendLine($"GDI Objects      : {snap.GdiObjects}");
        sb.AppendLine($"USER Objects     : {snap.UserObjects}");
        sb.AppendLine($"Handle Count     : {snap.HandleCount}");
        sb.AppendLine($"Working Set (MB) : {snap.WorkingSetMB}");
        sb.AppendLine($"Remote Session   : {snap.IsRemoteSession}");
        sb.AppendLine($"DWM Enabled      : {snap.DwmEnabled}");
        sb.AppendLine();

        File.AppendAllText(LogFilePath, sb.ToString());
    }

    public static string FormatEntry(DiagnosticsSnapshot snap)
    {
        var sb = new StringBuilder();
        sb.Append($"[{snap.Timestamp:HH:mm:ss.fff}] {snap.Source}");
        if (snap.ExceptionMessage != null)
            sb.Append($" | Exc: {snap.ExceptionMessage}");
        sb.Append($" | GDI={snap.GdiObjects} USER={snap.UserObjects}");
        sb.Append($" | Handles={snap.HandleCount} WS={snap.WorkingSetMB}MB");
        sb.Append($" | RDP={snap.IsRemoteSession} DWM={snap.DwmEnabled}");
        return sb.ToString();
    }
}

public class DiagnosticsSnapshot
{
    public DateTime Timestamp        { get; init; }
    public string   Source           { get; init; } = "";
    public int      GdiObjects       { get; init; }
    public int      UserObjects      { get; init; }
    public int      HandleCount      { get; init; }
    public long     WorkingSetMB     { get; init; }
    public bool     IsRemoteSession  { get; init; }
    public bool     DwmEnabled       { get; init; }
    public string?  ExceptionMessage { get; init; }
    public string?  StackTrace       { get; init; }
}

public record GpuInfo(string Name, string DriverVersion, string DriverDate);

public record TdrEvent(DateTime Time, string Source, string EntryType, string Message);
