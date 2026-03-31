using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using WpfBrushes     = System.Windows.Media.Brushes;
using WpfFontWeights = System.Windows.FontWeights;
using WpfMessageBox  = System.Windows.MessageBox;

namespace MessageHookTool;

public partial class MainWindow : Window
{
    // ─── Win32 ───────────────────────────────────────────────
    private const uint EVENT_OBJECT_LOCATIONCHANGE = 0x800B;
    private const uint WINEVENT_OUTOFCONTEXT        = 0x0000;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")]
    private static extern int GetGuiResources(IntPtr hProcess, int uiFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWinEventHook(
        uint eventMin, uint eventMax, IntPtr hmodWinEventProc,
        WinEventDelegate lpfnWinEventProc,
        uint idProcess, uint idThread, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool UnhookWinEvent(IntPtr hWinEventHook);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    private delegate void WinEventDelegate(
        IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint idEventThread, uint dwmsEventTime);

    // ─── フィールド ───────────────────────────────────────────
    private IntPtr           _winEventHook;
    private WinEventDelegate? _winEventProc; // GC 防止

    private bool _monitoring = false;

    // 頻度監視
    private int      _countInWindow    = 0;
    private int      _totalCount       = 0;
    private int      _currentFrequency = 0;
    private int      _maxFrequency     = 0;
    private DateTime _windowStart      = DateTime.Now;
    private bool     _warnActive       = false;

    // プロセス一覧
    private List<ProcessEntry> _allProcesses = new();

    private readonly DispatcherTimer _statusTimer;

    // ─── 初期化 ──────────────────────────────────────────────
    public MainWindow()
    {
        InitializeComponent();
        App.DiagnosticsRecorded += OnDiagnosticsRecorded;

        _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _statusTimer.Tick += UpdateStatusBar;
        _statusTimer.Start();

        LoadProcessList();
    }

    // ─── SetWinEventHook ─────────────────────────────────────
    private void StartMonitoring(int pid)
    {
        _winEventProc = OnWinEvent;
        _winEventHook = SetWinEventHook(
            EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE,
            IntPtr.Zero, _winEventProc,
            (uint)pid, 0, WINEVENT_OUTOFCONTEXT);

        if (_winEventHook == IntPtr.Zero)
        {
            AppendLog($"[{Now}] 【エラー】SetWinEventHook 失敗 (PID={pid})");
            return;
        }

        _monitoring = true;
        AppendLog($"[{Now}] 監視開始  PID={pid}");
        UpdateMonitorUI(true);
    }

    private void StopMonitoring()
    {
        if (_winEventHook != IntPtr.Zero)
        {
            UnhookWinEvent(_winEventHook);
            _winEventHook = IntPtr.Zero;
            _winEventProc = null;
        }
        _monitoring = false;
        AppendLog($"[{Now}] 監視停止");
        UpdateMonitorUI(false);
    }

    private void OnWinEvent(IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
                            int idObject, int idChild, uint idEventThread, uint dwmsEventTime)
    {
        // OBJID_WINDOW = 0 のみ（カーソル等を除外）
        if (idObject != 0 || hwnd == IntPtr.Zero) return;

        GetWindowRect(hwnd, out var rect);
        var title = new StringBuilder(256);
        GetWindowText(hwnd, title, 256);
        GetWindowThreadProcessId(hwnd, out uint pid);

        CountAndWarn();

        var entry = new LogEntry(
            DateTime.Now,
            $"EVENT_OBJECT_LOCATIONCHANGE  hwnd=0x{hwnd:X8}  " +
            $"pos=({rect.Left},{rect.Top})  " +
            $"size=({rect.Right - rect.Left},{rect.Bottom - rect.Top})  " +
            $"pid={pid}  title=\"{title}\"",
            _warnActive
        );
        Dispatcher.InvokeAsync(() => AppendLogEntry(entry));
    }

    // ─── 頻度カウント ─────────────────────────────────────────
    private void CountAndWarn()
    {
        _countInWindow++;
        _totalCount++;

        var elapsed = (DateTime.Now - _windowStart).TotalSeconds;
        if (elapsed >= 1.0)
        {
            _currentFrequency = (int)(_countInWindow / elapsed);
            if (_currentFrequency > _maxFrequency)
                _maxFrequency = _currentFrequency;
            _warnActive    = _currentFrequency > GetThreshold();
            _countInWindow = 0;
            _windowStart   = DateTime.Now;
        }
    }

    // ─── プロセス一覧 ─────────────────────────────────────────
    private void LoadProcessList(string filter = "")
    {
        _allProcesses = Process.GetProcesses()
            .Where(p => { try { return p.Id != 0; } catch { return false; } })
            .OrderBy(p => p.ProcessName)
            .Select(p => new ProcessEntry(p))
            .ToList();
        ApplyFilter(filter);
    }

    private void ApplyFilter(string filter)
    {
        var filtered = string.IsNullOrWhiteSpace(filter)
            ? _allProcesses
            : _allProcesses.Where(p =>
                p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.WindowTitle.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.Pid.ToString().Contains(filter)).ToList();

        CmbProcess.ItemsSource   = filtered;
        CmbProcess.SelectedIndex = filtered.Count > 0 ? 0 : -1;
    }

    // ─── UI イベントハンドラ ─────────────────────────────────
    private void BtnRefresh_Click(object sender, RoutedEventArgs e)
    {
        LoadProcessList(TxtProcessFilter.Text);
        AppendLog($"[{Now}] プロセス一覧を更新: {_allProcesses.Count} 件");
    }

    private void TxtProcessFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_allProcesses.Count > 0)
            ApplyFilter(TxtProcessFilter.Text);
    }

    private void CmbProcess_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

    private void BtnStartStop_Click(object sender, RoutedEventArgs e)
    {
        if (_monitoring)
        {
            StopMonitoring();
            return;
        }

        if (CmbProcess.SelectedItem is not ProcessEntry pe)
        {
            WpfMessageBox.Show("対象プロセスを選択してください。",
                "エラー", System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }
        StartMonitoring(pe.Pid);
    }

    private void UpdateMonitorUI(bool running)
    {
        BtnStartStop.Content    = running ? "監視停止" : "監視開始";
        BtnStartStop.Background = running
            ? System.Windows.Media.Brushes.Crimson
            : System.Windows.Media.Brushes.MediumSeaGreen;
        CmbProcess.IsEnabled        = !running;
        TxtProcessFilter.IsEnabled  = !running;
        BtnRefresh.IsEnabled        = !running;
    }

    // ─── 方法2: 例外診断 ─────────────────────────────────────
    private void OnDiagnosticsRecorded(DiagnosticsSnapshot snap)
    {
        if (ChkWriteFile.IsChecked == true)
            DiagnosticsLogger.WriteToFile(snap);

        Dispatcher.InvokeAsync(() =>
        {
            var item = new ListBoxItem
            {
                Content    = DiagnosticsLogger.FormatEntry(snap),
                Foreground = WpfBrushes.DarkRed,
                FontWeight = WpfFontWeights.Bold,
                Tag        = snap,
            };
            ListExceptions.Items.Add(item);
            if (ChkAutoScroll.IsChecked == true)
                ListExceptions.ScrollIntoView(item);
        });
    }

    // ─── ステータスバー ───────────────────────────────────────
    private void UpdateStatusBar(object? sender, EventArgs e)
    {
        using var proc = Process.GetCurrentProcess();
        proc.Refresh();

        TxtGdi.Text     = GetGuiResources(proc.Handle, 0).ToString();
        TxtUser.Text    = GetGuiResources(proc.Handle, 1).ToString();
        TxtHandles.Text = proc.HandleCount.ToString();
        TxtWS.Text      = $"{proc.WorkingSet64 / 1024 / 1024} MB";
        TxtRdp.Text     = System.Windows.Forms.SystemInformation.TerminalServerSession ? "YES" : "NO";

        TxtTotalCount.Text   = _totalCount.ToString();
        TxtFrequency.Text    = _currentFrequency.ToString();
        TxtMaxFrequency.Text = _maxFrequency.ToString();

        TxtWarning.Visibility = _warnActive ? Visibility.Visible : Visibility.Collapsed;
        if (_warnActive)
            TxtWarning.Text = $"警告: 頻度超過 ({_currentFrequency} 回/秒)";
    }

    // ─── ログ ─────────────────────────────────────────────────
    private record LogEntry(DateTime Timestamp, string Message, bool IsWarning = false);

    private void AppendLogEntry(LogEntry entry)
    {
        var item = new ListBoxItem
        {
            Content    = entry.Message,
            Foreground = entry.IsWarning ? WpfBrushes.OrangeRed : WpfBrushes.Black,
            FontWeight = entry.IsWarning ? WpfFontWeights.Bold : WpfFontWeights.Normal,
        };
        ListLog.Items.Add(item);

        if (ChkAutoScroll.IsChecked == true)
            ListLog.ScrollIntoView(item);

        while (ListLog.Items.Count > 5000)
            ListLog.Items.RemoveAt(0);

        if (ChkWriteFile.IsChecked == true)
            File.AppendAllText("diag.log", entry.Message + Environment.NewLine);
    }

    private void AppendLog(string text) =>
        AppendLogEntry(new LogEntry(DateTime.Now, text));

    // ─── ユーティリティ ──────────────────────────────────────
    private static string Now => DateTime.Now.ToString("HH:mm:ss.fff");

    private int GetThreshold()
    {
        if (int.TryParse(TxtThreshold.Text, out int v) && v > 0) return v;
        return 100;
    }

    // ─── ボタンハンドラ ──────────────────────────────────────
    private void BtnClearLog_Click(object sender, RoutedEventArgs e) =>
        ListLog.Items.Clear();

    private void BtnResetStats_Click(object sender, RoutedEventArgs e)
    {
        _totalCount = _countInWindow = _currentFrequency = _maxFrequency = 0;
        _windowStart = DateTime.Now;
        _warnActive  = false;
    }

    private void BtnExportLog_Click(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        foreach (ListBoxItem item in ListLog.Items)
            sb.AppendLine(item.Content?.ToString());

        var path = $"export_{DateTime.Now:yyyyMMdd_HHmmss}.log";
        File.WriteAllText(path, sb.ToString());
        WpfMessageBox.Show($"エクスポートしました:\n{Path.GetFullPath(path)}",
            "エクスポート完了",
            System.Windows.MessageBoxButton.OK,
            System.Windows.MessageBoxImage.Information);
    }

    // ─── クリーンアップ ──────────────────────────────────────
    protected override void OnClosed(EventArgs e)
    {
        _statusTimer.Stop();
        StopMonitoring();
        App.DiagnosticsRecorded -= OnDiagnosticsRecorded;
        base.OnClosed(e);
    }
}
