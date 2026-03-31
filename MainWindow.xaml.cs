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
    private const uint EVENT_OBJECT_CREATE        = 0x8000;
    private const uint EVENT_OBJECT_DESTROY       = 0x8001;
    private const uint EVENT_OBJECT_SHOW          = 0x8002;
    private const uint EVENT_OBJECT_HIDE          = 0x8003;
    private const uint EVENT_OBJECT_LOCATIONCHANGE = 0x800B;
    private const uint EVENT_SYSTEM_FOREGROUND    = 0x0003;
    private const uint EVENT_SYSTEM_MOVESIZESTART = 0x000A;
    private const uint EVENT_SYSTEM_MOVESIZEEND   = 0x000B;
    private const uint WINEVENT_OUTOFCONTEXT       = 0x0000;
    private const uint QS_ALLINPUT                 = 0x04FF;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

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

    [DllImport("user32.dll")]
    private static extern uint GetQueueStatus(uint flags);

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

    private const int WindowTextCapacity = 256;

    // ─── ログ種別 ─────────────────────────────────────────────
    private enum LogType { System, LocationChange, WindowEvent, QueueStatus }
    private record LogEntry(DateTime Timestamp, string Message, bool IsWarning = false, LogType Type = LogType.System);

    // ─── フィールド ───────────────────────────────────────────
    private Thread?           _hookThread;
    private uint              _hookThreadId;
    private WinEventDelegate? _winEventProc;

    private bool _monitoring = false;
    private int  _targetPid  = 0;

    // 頻度監視
    private int           _countInWindow    = 0;
    private int           _totalCount       = 0;
    private volatile int  _currentFrequency = 0;
    private volatile int  _maxFrequency     = 0;
    private long          _windowStartTicks = DateTime.Now.Ticks;
    private volatile bool _warnActive       = false;
    private volatile int  _threshold        = 100;

    // キュー溜まり監視（読み取りは Volatile.Read、書き込みは Interlocked で保護）
    private int  _pendingDispatchCount = 0;
    private long _lastQueueWarnTicks   = 0;   // 警告スロットル（フックスレッド専用）

    // フィルタ状態（UIスレッドのみ）
    private bool _filterSystem         = true;
    private bool _filterLocationChange = true;
    private bool _filterWindowEvent    = true;
    private bool _filterQueueStatus    = true;

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
        InitGpuInfo();
    }

    private void InitGpuInfo()
    {
        TxtGpuInfo.Text = "取得中...";
        Task.Run(DiagnosticsLogger.QueryGpuInfos).ContinueWith(t =>
        {
            var gpus = t.Result;
            var text = gpus.Length == 0
                ? "(取得失敗)"
                : string.Join("  /  ", gpus.Select(g =>
                    $"{g.Name}  driver={g.DriverVersion}  ({g.DriverDate})"));
            Dispatcher.InvokeAsync(() => TxtGpuInfo.Text = text);
        });
    }

    // ─── SetWinEventHook（専用スレッドで Win32 メッセージループを回す） ───
    private void StartMonitoring(int pid)
    {
        var ready = new ManualResetEventSlim(false);
        bool hookOk = false;

        _winEventProc = OnWinEvent;

        _hookThread = new Thread(() =>
        {
            _hookThreadId = GetCurrentThreadId();

            var hooks = new List<IntPtr>();
            // OBJECT イベント: CREATE/DESTROY/SHOW/HIDE/LOCATIONCHANGE (0x8000–0x800B)
            var h1 = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_LOCATIONCHANGE,
                                     IntPtr.Zero, _winEventProc, (uint)pid, 0, WINEVENT_OUTOFCONTEXT);
            if (h1 != IntPtr.Zero) hooks.Add(h1);
            // SYSTEM イベント: FOREGROUND / MOVESIZESTART / MOVESIZEEND (0x0003–0x000B)
            var h2 = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_MOVESIZEEND,
                                     IntPtr.Zero, _winEventProc, (uint)pid, 0, WINEVENT_OUTOFCONTEXT);
            if (h2 != IntPtr.Zero) hooks.Add(h2);

            hookOk = hooks.Count > 0;
            ready.Set();
            if (!hookOk) return;

            while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }

            foreach (var h in hooks) UnhookWinEvent(h);
        });

        _hookThread.SetApartmentState(ApartmentState.STA);
        _hookThread.IsBackground = true;
        _hookThread.Start();

        ready.Wait(TimeSpan.FromSeconds(2));

        if (!hookOk)
        {
            AppendLog($"[{Now}] 【エラー】SetWinEventHook 失敗 (PID={pid})");
            return;
        }

        _monitoring = true;
        _targetPid  = pid;
        AppendLog($"[{Now}] 監視開始  PID={pid}");
        UpdateMonitorUI(true);
    }

    private void StopMonitoring()
    {
        if (_hookThreadId != 0)
        {
            PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
            _hookThread?.Join(TimeSpan.FromSeconds(2));
            _hookThreadId = 0;
            _hookThread   = null;
        }
        _monitoring = false;
        _targetPid  = 0;
        AppendLog($"[{Now}] 監視停止");
        UpdateMonitorUI(false);
    }

    private void OnWinEvent(IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
                            int idObject, int idChild, uint idEventThread, uint dwmsEventTime)
    {
        if (idObject != 0 || hwnd == IntPtr.Zero) return;

        // 処理ラグ（dwmsEventTime は GetTickCount と同単位: システム起動からのミリ秒）
        var lagMs = unchecked((int)((uint)Environment.TickCount - dwmsEventTime));
        if (lagMs < 0) lagMs = 0;

        if (eventType == EVENT_OBJECT_LOCATIONCHANGE)
        {
            GetWindowRect(hwnd, out var rect);
            var title = new StringBuilder(WindowTextCapacity);
            GetWindowText(hwnd, title, WindowTextCapacity);
            GetWindowThreadProcessId(hwnd, out uint pid);
            CountAndWarn();

            PostLogEntry(
                $"[{Now}] EVENT_OBJECT_LOCATIONCHANGE  hwnd=0x{hwnd:X8}  " +
                $"pos=({rect.Left},{rect.Top})  " +
                $"size=({rect.Right - rect.Left},{rect.Bottom - rect.Top})  " +
                $"pid={pid}  title=\"{title}\"  lag={lagMs}ms",
                LogType.LocationChange, _warnActive);
            return;
        }

        // その他のイベント
        string evName = eventType switch
        {
            EVENT_OBJECT_CREATE        => "OBJECT_CREATE",
            EVENT_OBJECT_DESTROY       => "OBJECT_DESTROY",
            EVENT_OBJECT_SHOW          => "OBJECT_SHOW",
            EVENT_OBJECT_HIDE          => "OBJECT_HIDE",
            EVENT_SYSTEM_FOREGROUND    => "SYSTEM_FOREGROUND",
            EVENT_SYSTEM_MOVESIZESTART => "SYSTEM_MOVESIZESTART",
            EVENT_SYSTEM_MOVESIZEEND   => "SYSTEM_MOVESIZEEND",
            _                          => $"EVENT_0x{eventType:X4}",
        };

        if (eventType == EVENT_OBJECT_DESTROY)
        {
            // 破棄済みウィンドウは GetWindowText 等が使えないため hwnd のみ記録
            PostLogEntry($"[{Now}] {evName}  hwnd=0x{hwnd:X8}  lag={lagMs}ms",
                         LogType.WindowEvent);
            return;
        }

        var sb = new StringBuilder(WindowTextCapacity);
        GetWindowText(hwnd, sb, WindowTextCapacity);
        GetWindowThreadProcessId(hwnd, out uint pid2);
        PostLogEntry(
            $"[{Now}] {evName}  hwnd=0x{hwnd:X8}  pid={pid2}  title=\"{sb}\"  lag={lagMs}ms",
            LogType.WindowEvent);
    }

    // ─── ログエントリをUIスレッドへディスパッチ ──────────────
    private void PostLogEntry(string message, LogType type, bool isWarning = false)
    {
        var entry = new LogEntry(DateTime.Now, message, isWarning, type);
        if (!Dispatcher.HasShutdownStarted)
        {
            Interlocked.Increment(ref _pendingDispatchCount);
            Dispatcher.InvokeAsync(() =>
            {
                Interlocked.Decrement(ref _pendingDispatchCount);
                AppendLogEntry(entry);
            });
        }
    }

    // ─── 頻度カウント + キュー状態チェック（フックスレッドから呼ばれる） ───
    private void CountAndWarn()
    {
        _countInWindow++;
        Interlocked.Increment(ref _totalCount);

        var nowTicks = DateTime.Now.Ticks;
        var elapsed  = TimeSpan.FromTicks(nowTicks - Interlocked.Read(ref _windowStartTicks)).TotalSeconds;

        var pending = Volatile.Read(ref _pendingDispatchCount);
        if (pending > 50 && TimeSpan.FromTicks(nowTicks - _lastQueueWarnTicks).TotalSeconds >= 1.0)
        {
            _lastQueueWarnTicks = nowTicks;
            var liveFreq = elapsed > 0 ? (int)(_countInWindow / elapsed) : _currentFrequency;
            var qs    = GetQueueStatus(QS_ALLINPUT);
            var qsNow = (int)(qs & 0xFFFF);
            var qsNew = (int)((qs >> 16) & 0xFFFF);
            PostLogEntry(
                $"[{Now}] [キュー警告] UIディスパッチ待ち={pending}件  " +
                $"Win32キュー種別=0x{qsNow:X4}(新着=0x{qsNew:X4})  LOCATIONCHANGE頻度={liveFreq}回/秒",
                LogType.QueueStatus, isWarning: true);
        }
        if (elapsed >= 1.0)
        {
            var freq = (int)(_countInWindow / elapsed);
            _currentFrequency = freq;
            if (freq > _maxFrequency)
                _maxFrequency = freq;
            _warnActive    = freq > _threshold;
            _countInWindow = 0;
            Interlocked.Exchange(ref _windowStartTicks, nowTicks);
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

    // ─── TDR ログ確認 ────────────────────────────────────────
    private void BtnCheckTdr_Click(object sender, RoutedEventArgs e)
    {
        ListTdr.Items.Clear();
        ListTdr.Visibility = Visibility.Visible;

        var events = DiagnosticsLogger.QueryRecentTdrEvents();
        if (events.Length == 0)
        {
            ListTdr.Items.Add("(直近件に TDR 関連イベントなし: nvlddmkm / atikmdag / igfx / dxgkrnl / Display)");
            return;
        }

        foreach (var ev in events)
        {
            ListTdr.Items.Add(
                $"[{ev.Time:yyyy-MM-dd HH:mm:ss}] [{ev.EntryType}] {ev.Source}: {ev.Message}");
        }

        AppendLog($"[{Now}] TDR イベント {events.Length} 件を取得");
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
        if (_targetPid != 0)
        {
            try
            {
                using var target = Process.GetProcessById(_targetPid);
                target.Refresh();
                TxtGdi.Text     = DiagnosticsLogger.GetGuiResources(target.Handle, 0).ToString();
                TxtUser.Text    = DiagnosticsLogger.GetGuiResources(target.Handle, 1).ToString();
                TxtHandles.Text = target.HandleCount.ToString();
                TxtWS.Text      = $"{target.WorkingSet64 / 1024 / 1024} MB";
            }
            catch
            {
                TxtGdi.Text     = "-";
                TxtUser.Text    = "-";
                TxtHandles.Text = "-";
                TxtWS.Text      = "-";
            }
        }
        else
        {
            TxtGdi.Text     = "-";
            TxtUser.Text    = "-";
            TxtHandles.Text = "-";
            TxtWS.Text      = "-";
        }
        TxtRdp.Text     = System.Windows.Forms.SystemInformation.TerminalServerSession ? "YES" : "NO";
        TxtDwm.Text     = DiagnosticsLogger.GetDwmEnabled() ? "ON" : "OFF";

        TxtTotalCount.Text      = Volatile.Read(ref _totalCount).ToString();
        TxtFrequency.Text       = _currentFrequency.ToString();
        TxtMaxFrequency.Text    = _maxFrequency.ToString();
        TxtPendingDispatch.Text = Volatile.Read(ref _pendingDispatchCount).ToString();

        TxtWarning.Visibility = _warnActive ? Visibility.Visible : Visibility.Collapsed;
        if (_warnActive)
            TxtWarning.Text = $"警告: 頻度超過 ({_currentFrequency} 回/秒)";
    }

    // ─── ログ ─────────────────────────────────────────────────
    private void AppendLogEntry(LogEntry entry)
    {
        bool show = IsTypeVisible(entry.Type);

        var item = new ListBoxItem
        {
            Content    = entry.Message,
            Foreground = entry.Type switch
            {
                LogType.QueueStatus    => WpfBrushes.OrangeRed,
                LogType.WindowEvent    => WpfBrushes.DodgerBlue,
                LogType.LocationChange => entry.IsWarning ? WpfBrushes.OrangeRed : WpfBrushes.Black,
                _                     => WpfBrushes.Gray,
            },
            FontWeight = entry.IsWarning ? WpfFontWeights.Bold : WpfFontWeights.Normal,
            Tag        = entry.Type,
            Visibility = show ? Visibility.Visible : Visibility.Collapsed,
        };
        ListLog.Items.Add(item);

        if (show && ChkAutoScroll.IsChecked == true)
            ListLog.ScrollIntoView(item);

        while (ListLog.Items.Count > 5000)
            ListLog.Items.RemoveAt(0);

        if (ChkWriteFile.IsChecked == true)
            File.AppendAllText("diag.log", entry.Message + Environment.NewLine);
    }

    private void AppendLog(string text) =>
        AppendLogEntry(new LogEntry(DateTime.Now, text, false, LogType.System));

    // ─── ログフィルタ ─────────────────────────────────────────
    private bool IsTypeVisible(LogType type) => type switch
    {
        LogType.System         => _filterSystem,
        LogType.LocationChange => _filterLocationChange,
        LogType.WindowEvent    => _filterWindowEvent,
        LogType.QueueStatus    => _filterQueueStatus,
        _ => true
    };

    private void ApplyLogFilter()
    {
        foreach (ListBoxItem item in ListLog.Items)
        {
            if (item.Tag is LogType lt)
                item.Visibility = IsTypeVisible(lt) ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void ChkFilter_Click(object sender, RoutedEventArgs e)
    {
        _filterSystem         = ChkFilterSystem.IsChecked         == true;
        _filterLocationChange = ChkFilterLocationChange.IsChecked == true;
        _filterWindowEvent    = ChkFilterWindowEvent.IsChecked    == true;
        _filterQueueStatus    = ChkFilterQueueStatus.IsChecked    == true;
        ApplyLogFilter();
    }

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
