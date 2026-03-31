using System.Diagnostics;

namespace MessageHookTool;

/// <summary>ComboBox に表示するプロセス情報</summary>
public class ProcessEntry
{
    public int    Pid         { get; }
    public string Name        { get; }
    public string WindowTitle { get; }
    public string DisplayName { get; }

    public ProcessEntry(Process proc)
    {
        Pid         = proc.Id;
        Name        = proc.ProcessName;
        WindowTitle = TryGetTitle(proc);
        DisplayName = $"[{Pid:D5}] {Name}"
                    + (WindowTitle.Length > 0 ? $"  —  {WindowTitle}" : "");
    }

    private static string TryGetTitle(Process proc)
    {
        try { return proc.MainWindowTitle; }
        catch { return ""; }
    }
}
