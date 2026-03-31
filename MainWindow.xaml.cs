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

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint   message;
        public IntPtr wParam, lParam;
        public uint   time;
        public int    ptX, ptY;
    }

    [DllImport("user32.dll")]
    private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint min, uint max);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(ref MSG lpmsg);

    [DllImport("user32.dll")]
    private static extern bool PostThreadMessage(uint idThread, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    private const uint WM_QUIT = 0x0012;

    // ─── フィールド ───────────────────────────────────────────
    private Thread?           _hookThread;
    private uint              _hookThreadId;
    private WinEventDelegate? _winEventProc; // GC 収集防止のためインスタンスフィールドで保持

    private bool _monitoring = false;

    // 頻度監視（フックスレッド・UIスレッド両方からアクセスするため Interlocked / volatile で保護）
    private int           _countInWindow    = 0;
    private int           _totalCount       = 0;
    private volatile int  _currentFrequency = 0;
    private volatile int  _maxFrequency     = 0;
    private long          _windowStartTicks = DateTime.Now.Ticks;
    private volatile bool _warnActive       = false;
    private volatile int  _threshold        = 100; // UIスレッドから書き、フックスレッドから読む

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

    // ─── SetWinEventHook（専用スレッドで Win32 メッセージループを回す） ───
    private void StartMonitoring(int pid)
    {
        var ready = new ManualResetEventSlim(false);
        bool hookOk = false;

        // インスタンスフィールドに保持して GC 収集を防ぐ
        _winEventProc = OnWinEvent;

        _hookThread = new Thread(() =>
        {
            // このスレッドの Win32 スレッド ID を記録
            _hookThreadId = GetCurrentThreadId();

            var hook = SetWinEventHook(
                EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE,
                IntPtr.Zero, _winEventProc,
                (uint)pid, 0, WINEVENT_OUTOFCONTEXT);

            hookOk = hook != IntPtr.Zero;
            ready.Set(); // UI スレッドへ結果を通知

            if (!hookOk) return;

            // Win32 メッセージループ（WM_QUIT が来るまで回し続ける）
            while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }

            UnhookWinEvent(hook);
        });

        _hookThread.SetApartmentState(ApartmentState.STA);
        _hookThread.IsBackground = true;
        _hookThread.Start();

        // フック結果を待機（最大 2 秒）
        ready.Wait(TimeSpan.FromSeconds(2));

        if (!hookOk)
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
        if (_hookThreadId != 0)
        {
            // WM_QUIT をフックスレッドに送ってループを終了
            PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
            _hookThread?.Join(TimeSpan.FromSeconds(2));
            _hookThreadId = 0;
            _hookThread   = null;
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
        if (!Dispatcher.HasShutdownStarted)
            Dispatcher.InvokeAsync(() => AppendLogEntry(entry));
    }

    // ─── 頻度カウント（フックスレッドから呼ばれる） ──────────
    private void CountAndWarn()
    {
        // _countInWindow / _totalCount はフックスレッドのみ書くので Interlocked 不要だが
        // _currentFrequency / _maxFrequency は UI スレッドから読むため volatile で保護済み
        _countInWindow++;
        Interlocked.Increment(ref _totalCount);

        var elapsed = TimeSpan.FromTicks(DateTime.Now.Ticks - Interlocked.Read(ref _windowStartTicks)).TotalSeconds;
        if (elapsed >= 1.0)
        {
            var freq = (int)(_countInWindow / elapsed);
            _currentFrequency = freq;
            if (freq > _maxFrequency)
                _maxFrequency = freq;
            _warnActive    = freq > _threshold;
            _countInWindow = 0;
            Interlocked.Exchange(ref _windowStartTicks, DateTime.Now.Ticks);
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

        TxtTotalCount.Text   = Volatile.Read(ref _totalCount).ToString();
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

    private void TxtThreshold_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (int.TryParse(TxtThreshold.Text, out int v) && v > 0)
            _threshold = v;
    }

    // ─── ボタンハンドラ ──────────────────────────────────────
    private void BtnClearLog_Click(object sender, RoutedEventArgs e) =>
        ListLog.Items.Clear();

    private void BtnResetStats_Click(object sender, RoutedEventArgs e)
    {
        Interlocked.Exchange(ref _totalCount, 0);
        _countInWindow = _currentFrequency = _maxFrequency = 0;
        Interlocked.Exchange(ref _windowStartTicks, DateTime.Now.Ticks);
        _warnActive = false;
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
