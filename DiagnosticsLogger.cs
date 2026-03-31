using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace MessageHookTool;

public static class DiagnosticsLogger
{
    private static readonly string LogFilePath = "diag.log";

    [DllImport("user32.dll")]
    private static extern int GetGuiResources(IntPtr hProcess, int uiFlags);

    public static DiagnosticsSnapshot TakeSnapshot(string source, Exception? ex = null)
    {
        using var proc = Process.GetCurrentProcess();
        return new DiagnosticsSnapshot
        {
            Timestamp    = DateTime.Now,
            Source       = source,
            GdiObjects   = GetGuiResources(proc.Handle, 0),
            UserObjects  = GetGuiResources(proc.Handle, 1),
            HandleCount  = proc.HandleCount,
            WorkingSetMB = proc.WorkingSet64 / 1024 / 1024,
            IsRemoteSession = SystemInformation.TerminalServerSession,
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
        sb.Append($" | RDP={snap.IsRemoteSession}");
        return sb.ToString();
    }
}

public class DiagnosticsSnapshot
{
    public DateTime Timestamp      { get; init; }
    public string   Source         { get; init; } = "";
    public int      GdiObjects     { get; init; }
    public int      UserObjects    { get; init; }
    public int      HandleCount    { get; init; }
    public long     WorkingSetMB   { get; init; }
    public bool     IsRemoteSession { get; init; }
    public string?  ExceptionMessage { get; init; }
    public string?  StackTrace     { get; init; }
}
