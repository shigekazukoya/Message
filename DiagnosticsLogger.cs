using Microsoft.Win32;
using System.ComponentModel;
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
    private static readonly IntPtr GrGlobal = new(-2);

    private const int GR_GDIOBJECTS = 0;
    private const int GR_USEROBJECTS = 1;
    private const int GR_GDIOBJECTS_PEAK = 2;
    private const int GR_USEROBJECTS_PEAK = 4;
    private const int UOI_HEAPSIZE = 5;
    private const int ErrorNotEnoughQuota = 1816;
    private const int CommitPressureThresholdPercent = 95;
    private const int GuiPressureThresholdPercent = 80;
    private const int GuiCriticalThresholdPercent = 95;
    private const long LowPhysicalMemoryThresholdMB = 512;
    private const long CriticalPhysicalMemoryThresholdMB = 256;
    private const long SuspiciousPagedPoolThresholdMB = 256;
    private const long SuspiciousNonPagedPoolThresholdMB = 128;
    private const int SuspiciousHandleCount = 20000;
    private const int InvestigationTopCount = 6;
    private const uint GA_ROOT = 2;

    // レジストリに明示値がない場合の一般的な既定値として扱う
    private const int DefaultGdiProcessHandleQuota = 10000;
    private const int DefaultUserProcessHandleQuota = 10000;

    private const string WindowsKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string SubsystemsKey = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems";

    [DllImport("user32.dll")]
    internal static extern int GetGuiResources(IntPtr hProcess, int uiFlags);

    [DllImport("dwmapi.dll")]
    private static extern int DwmIsCompositionEnabled(out bool pfEnabled);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetProcessMemoryInfo(
        IntPtr hProcess, ref PROCESS_MEMORY_COUNTERS_EX counters, uint size);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetPerformanceInfo(
        ref PERFORMANCE_INFORMATION performanceInformation, uint size);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetUserObjectInformation(
        IntPtr hObj, int nIndex, out uint pvInfo, int nLength, out int needed);

    [DllImport("user32.dll")]
    private static extern IntPtr GetThreadDesktop(uint dwThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern IntPtr GetAncestor(IntPtr hWnd, uint gaFlags);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MEMORY_COUNTERS_EX
    {
        public uint cb;
        public uint PageFaultCount;
        public UIntPtr PeakWorkingSetSize;
        public UIntPtr WorkingSetSize;
        public UIntPtr QuotaPeakPagedPoolUsage;
        public UIntPtr QuotaPagedPoolUsage;
        public UIntPtr QuotaPeakNonPagedPoolUsage;
        public UIntPtr QuotaNonPagedPoolUsage;
        public UIntPtr PagefileUsage;
        public UIntPtr PeakPagefileUsage;
        public UIntPtr PrivateUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PERFORMANCE_INFORMATION
    {
        public uint cb;
        public IntPtr CommitTotal;
        public IntPtr CommitLimit;
        public IntPtr CommitPeak;
        public IntPtr PhysicalTotal;
        public IntPtr PhysicalAvailable;
        public IntPtr SystemCache;
        public IntPtr KernelTotal;
        public IntPtr KernelPaged;
        public IntPtr KernelNonpaged;
        public IntPtr PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    internal static bool GetDwmEnabled()
    {
        DwmIsCompositionEnabled(out bool enabled);
        return enabled;
    }

    public static QuotaProbe? TryTakeQuotaProbe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return TakeQuotaProbe(proc);
        }
        catch
        {
            return null;
        }
    }

    public static DiagnosticsSnapshot TakeSnapshot(string source, Exception? ex = null)
    {
        using var proc = Process.GetCurrentProcess();
        var nativeErrorCode = (ex as Win32Exception)?.NativeErrorCode;
        var quotaProbe = TakeQuotaProbe(proc);

        return new DiagnosticsSnapshot
        {
            Timestamp        = DateTime.Now,
            Source           = source,
            ExceptionMessage = ex?.Message,
            StackTrace       = ex?.StackTrace,
            NativeErrorCode  = nativeErrorCode,
            QuotaProbe       = quotaProbe,
            Investigation    = nativeErrorCode == ErrorNotEnoughQuota
                ? TakeInvestigation(quotaProbe, nativeErrorCode)
                : null,
        };
    }

    private static QuotaProbe TakeQuotaProbe(Process proc)
    {
        proc.Refresh();

        var memCounters = QueryProcessMemoryInfo(proc.Handle);
        var perfInfo = QueryPerformanceInfo();
        var desktopHeap = QueryDesktopHeapInfo();

        var gdiQuotaValue = ReadRegistryInt(WindowsKey, "GDIProcessHandleQuota");
        var userQuotaValue = ReadRegistryInt(WindowsKey, "USERProcessHandleQuota");

        var probe = new QuotaProbe
        {
            ProcessId                   = proc.Id,
            ProcessName                 = proc.ProcessName,
            GdiObjects                  = GetGuiResources(proc.Handle, GR_GDIOBJECTS),
            GdiPeakObjects              = GetGuiResources(proc.Handle, GR_GDIOBJECTS_PEAK),
            GdiQuota                    = gdiQuotaValue ?? DefaultGdiProcessHandleQuota,
            GdiQuotaIsDefault           = !gdiQuotaValue.HasValue,
            UserObjects                 = GetGuiResources(proc.Handle, GR_USEROBJECTS),
            UserPeakObjects             = GetGuiResources(proc.Handle, GR_USEROBJECTS_PEAK),
            UserQuota                   = userQuotaValue ?? DefaultUserProcessHandleQuota,
            UserQuotaIsDefault          = !userQuotaValue.HasValue,
            HandleCount                 = proc.HandleCount,
            ThreadCount                 = proc.Threads.Count,
            WorkingSetMB                = proc.WorkingSet64 / 1024 / 1024,
            PrivateUsageMB              = ToMb(memCounters.PrivateUsage),
            PagefileUsageMB             = ToMb(memCounters.PagefileUsage),
            PagedPoolUsageMB            = ToMb(memCounters.QuotaPagedPoolUsage),
            NonPagedPoolUsageMB         = ToMb(memCounters.QuotaNonPagedPoolUsage),
            CommitTotalMB               = perfInfo.CommitTotalMB,
            CommitLimitMB               = perfInfo.CommitLimitMB,
            CommitUsagePercent          = perfInfo.CommitLimitMB > 0
                ? (int)((perfInfo.CommitTotalMB * 100) / perfInfo.CommitLimitMB)
                : 0,
            AvailablePhysicalMB         = perfInfo.PhysicalAvailableMB,
            KernelPagedMB               = perfInfo.KernelPagedMB,
            KernelNonPagedMB            = perfInfo.KernelNonPagedMB,
            SessionGdiObjects           = GetGuiResources(GrGlobal, GR_GDIOBJECTS),
            SessionUserObjects          = GetGuiResources(GrGlobal, GR_USEROBJECTS),
            CurrentDesktopHeapKB        = desktopHeap.CurrentDesktopHeapKB,
            SharedSectionKB             = desktopHeap.SharedSectionKB,
            InteractiveDesktopHeapKB    = desktopHeap.InteractiveDesktopHeapKB,
            NonInteractiveDesktopHeapKB = desktopHeap.NonInteractiveDesktopHeapKB,
        };

        var analysis = AnalyzeQuota(probe, null);
        probe.DiagnosisSummary = analysis.Summary;
        probe.LikelyMissingResource = analysis.MissingResource;
        probe.RecommendedAction = analysis.Recommendation;
        probe.HasPressure = HasPressure(probe);
        return probe;
    }

    public static QuotaInvestigation TakeInvestigation(int pid, int? nativeErrorCode = null)
    {
        var probe = TryTakeQuotaProbe(pid);
        return TakeInvestigation(probe, nativeErrorCode);
    }

    private static QuotaInvestigation TakeInvestigation(QuotaProbe? probe, int? nativeErrorCode)
    {
        var analysis = AnalyzeQuota(probe, nativeErrorCode);
        var windowInventory = probe != null
            ? QueryWindowInventory(probe.ProcessId)
            : new WindowInventory();
        var wpfCauseHint = BuildWpfCauseHint(probe, windowInventory, nativeErrorCode);

        return new QuotaInvestigation
        {
            FocusProcessId = probe?.ProcessId,
            FocusProcessName = probe?.ProcessName,
            MissingResource = analysis.MissingResource,
            Summary = analysis.Summary,
            Recommendation = analysis.Recommendation,
            WindowInventory = windowInventory,
            WpfCauseHint = wpfCauseHint,
        };
    }

    public static string BuildDiagnosis(QuotaProbe probe, int? nativeErrorCode)
    {
        return AnalyzeQuota(probe, nativeErrorCode).Summary;
    }

    public static string FormatQuotaSummary(QuotaProbe probe) =>
        $"PID={probe.ProcessId} GDI={probe.GdiObjects}/{probe.GdiQuota} USER={probe.UserObjects}/{probe.UserQuota} " +
        $"Private={probe.PrivateUsageMB}MB PagedPool={probe.PagedPoolUsageMB}MB NonPagedPool={probe.NonPagedPoolUsageMB}MB " +
        $"Commit={probe.CommitTotalMB}/{probe.CommitLimitMB}MB({probe.CommitUsagePercent}%)";

    private static bool HasPressure(QuotaProbe probe)
    {
        if (probe.GdiQuota > 0 && probe.GdiObjects * 100 / probe.GdiQuota >= GuiPressureThresholdPercent)
            return true;

        if (probe.UserQuota > 0 && probe.UserObjects * 100 / probe.UserQuota >= GuiPressureThresholdPercent)
            return true;

        if (probe.CommitLimitMB > 0 && probe.CommitUsagePercent >= CommitPressureThresholdPercent)
            return true;

        if (probe.AvailablePhysicalMB is > 0 and < LowPhysicalMemoryThresholdMB)
            return true;

        if (probe.PagedPoolUsageMB >= SuspiciousPagedPoolThresholdMB ||
            probe.NonPagedPoolUsageMB >= SuspiciousNonPagedPoolThresholdMB)
            return true;

        if (probe.HandleCount >= SuspiciousHandleCount)
            return true;

        return false;
    }

    public static QuotaAnalysis AnalyzeQuota(QuotaProbe? probe, int? nativeErrorCode)
    {
        if (probe == null)
        {
            return nativeErrorCode == ErrorNotEnoughQuota
                ? new QuotaAnalysis
                {
                    MissingResource = "desktop heap / kernel pool / commit",
                    Summary = "1816(ERROR_NOT_ENOUGH_QUOTA) が発生しましたが、対象プロセスの採取に失敗しました",
                Recommendation = "再現直前に原因スキャンを実行し、対象アプリの HWND 構成と Commit 使用率を採取してください",
                }
                : new QuotaAnalysis
                {
                    MissingResource = "不明",
                    Summary = "クォータ情報を取得できませんでした",
                Recommendation = "再現直前の採取有無と対象プロセスの取得権限を確認してください",
                };
        }

        var findings = new List<string>();
        var gdiPercent = probe.GdiQuota > 0 ? probe.GdiObjects * 100 / probe.GdiQuota : 0;
        var userPercent = probe.UserQuota > 0 ? probe.UserObjects * 100 / probe.UserQuota : 0;

        if (nativeErrorCode == ErrorNotEnoughQuota)
            findings.Add("1816(ERROR_NOT_ENOUGH_QUOTA)");

        if (gdiPercent >= GuiPressureThresholdPercent)
            findings.Add($"GDI 枯渇候補 {probe.GdiObjects}/{probe.GdiQuota} ({gdiPercent}%)");

        if (userPercent >= GuiPressureThresholdPercent)
            findings.Add($"USER 枯渇候補 {probe.UserObjects}/{probe.UserQuota} ({userPercent}%)");

        if (probe.CommitLimitMB > 0 && probe.CommitUsagePercent >= CommitPressureThresholdPercent)
            findings.Add($"Commit 圧迫 {probe.CommitTotalMB}/{probe.CommitLimitMB}MB ({probe.CommitUsagePercent}%)");

        if (probe.AvailablePhysicalMB is > 0 and < LowPhysicalMemoryThresholdMB)
            findings.Add($"空き物理メモリ低下 {probe.AvailablePhysicalMB}MB");

        if (probe.PagedPoolUsageMB >= SuspiciousPagedPoolThresholdMB)
            findings.Add($"Paged Pool 増大 {probe.PagedPoolUsageMB}MB");

        if (probe.NonPagedPoolUsageMB >= SuspiciousNonPagedPoolThresholdMB)
            findings.Add($"NonPaged Pool 増大 {probe.NonPagedPoolUsageMB}MB");

        if (probe.HandleCount >= SuspiciousHandleCount)
            findings.Add($"ハンドル増大 {probe.HandleCount}");

        var summary = findings.Count == 0
            ? "顕著な quota 圧迫は未検出"
            : string.Join(" / ", findings);

        if (probe.CommitLimitMB > 0 && probe.CommitUsagePercent >= CommitPressureThresholdPercent)
        {
            return new QuotaAnalysis
            {
                MissingResource = "Commit / ページファイル",
                Summary = summary,
                Recommendation = "対象アプリのメモリ増加とページファイル設定を確認してください",
            };
        }

        if (gdiPercent >= GuiCriticalThresholdPercent && gdiPercent >= userPercent)
        {
            return new QuotaAnalysis
            {
                MissingResource = "GDI オブジェクト",
                Summary = summary,
                Recommendation = "WPF 単体より WinFormsHost / System.Drawing / Bitmap / Icon / HBITMAP 連携の解放漏れを疑ってください",
            };
        }

        if (userPercent >= GuiCriticalThresholdPercent)
        {
            return new QuotaAnalysis
            {
                MissingResource = "USER オブジェクト",
                Summary = summary,
                Recommendation = "Window / Popup / ToolTip / ContextMenu / HwndSource / HwndHost の増殖を疑ってください",
            };
        }

        if (probe.AvailablePhysicalMB is > 0 and < CriticalPhysicalMemoryThresholdMB)
        {
            return new QuotaAnalysis
            {
                MissingResource = "物理メモリ / Commit",
                Summary = summary,
                Recommendation = "対象アプリの Private Bytes 増加とページファイル不足を確認してください",
            };
        }

        if (probe.PagedPoolUsageMB >= SuspiciousPagedPoolThresholdMB ||
            probe.NonPagedPoolUsageMB >= SuspiciousNonPagedPoolThresholdMB)
        {
            return new QuotaAnalysis
            {
                MissingResource = "kernel pool",
                Summary = summary,
                Recommendation = "ドライバ由来の pool 枯渇やアプリ内 handle リークの可能性があります",
            };
        }

        if (probe.HandleCount >= SuspiciousHandleCount)
        {
            return new QuotaAnalysis
            {
                MissingResource = "カーネルハンドル",
                Summary = summary,
                Recommendation = "対象アプリ内のファイル / イベント / スレッド handle リークを疑ってください",
            };
        }

        if (gdiPercent >= GuiPressureThresholdPercent && gdiPercent >= userPercent)
        {
            return new QuotaAnalysis
            {
                MissingResource = "GDI オブジェクト",
                Summary = summary,
                Recommendation = "GDI 使用率が高めです。Bitmap / Icon / WinForms 連携のリーク有無を継続監視してください",
            };
        }

        if (userPercent >= GuiPressureThresholdPercent)
        {
            return new QuotaAnalysis
            {
                MissingResource = "USER オブジェクト",
                Summary = summary,
                Recommendation = "USER 使用率が高めです。Window / Popup / ToolTip / ContextMenu の増加傾向を確認してください",
            };
        }

        if (nativeErrorCode == ErrorNotEnoughQuota)
        {
            return new QuotaAnalysis
            {
                MissingResource = "desktop heap / kernel pool / commit",
                Summary = summary == "顕著な quota 圧迫は未検出"
                    ? $"1816(ERROR_NOT_ENOUGH_QUOTA)。GDI={probe.GdiObjects}/{probe.GdiQuota}, USER={probe.UserObjects}/{probe.UserQuota}, Commit={probe.CommitUsagePercent}%"
                    : summary,
                Recommendation = "GDI/USER が平常域なら desktop heap が有力です。WPF の隠し HWND や Popup/ToolTip/ContextMenu の増殖を確認してください",
            };
        }

        return new QuotaAnalysis
        {
            MissingResource = "不足候補なし",
            Summary = summary,
            Recommendation = "再現直前に原因スキャンを実行し、対象アプリの HWND 構成を採取してください",
        };
    }

    private static WindowInventory QueryWindowInventory(int pid)
    {
        var windows = new Dictionary<IntPtr, WindowSnapshot>();

        EnumWindows((hWnd, _) =>
        {
            if (!BelongsToProcess(hWnd, pid))
                return true;

            AddWindowSnapshot(windows, hWnd, isTopLevel: true);
            EnumChildWindows(hWnd, (child, _) =>
            {
                AddWindowSnapshot(windows, child, isTopLevel: false);
                return true;
            }, IntPtr.Zero);
            return true;
        }, IntPtr.Zero);

        var allWindows = windows.Values.ToArray();
        var classBuckets = allWindows
            .GroupBy(x => x.ClassName, StringComparer.Ordinal)
            .Select(g => new WindowClassSample
            {
                ClassName = g.Key,
                Count = g.Count(),
                VisibleCount = g.Count(x => x.IsVisible),
                HiddenCount = g.Count(x => !x.IsVisible),
                TopLevelCount = g.Count(x => x.IsTopLevel),
            })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.ClassName, StringComparer.Ordinal)
            .Take(InvestigationTopCount)
            .ToArray();

        return new WindowInventory
        {
            TotalWindows = allWindows.Length,
            VisibleWindows = allWindows.Count(x => x.IsVisible),
            HiddenWindows = allWindows.Count(x => !x.IsVisible),
            TopLevelWindows = allWindows.Count(x => x.IsTopLevel),
            HiddenTopLevelWindows = allWindows.Count(x => x.IsTopLevel && !x.IsVisible),
            HwndWrapperCount = allWindows.Count(x => x.ClassName.StartsWith("HwndWrapper[", StringComparison.Ordinal)),
            HiddenHwndWrapperCount = allWindows.Count(x =>
                x.ClassName.StartsWith("HwndWrapper[", StringComparison.Ordinal) && !x.IsVisible),
            WindowsFormsHostCount = allWindows.Count(x => x.ClassName.StartsWith("WindowsForms10.", StringComparison.Ordinal)),
            WebViewHostCount = allWindows.Count(x =>
                x.ClassName.StartsWith("Chrome_WidgetWin_", StringComparison.Ordinal) ||
                x.ClassName.Contains("WebView", StringComparison.OrdinalIgnoreCase)),
            TopClasses = classBuckets,
        };
    }

    private static bool BelongsToProcess(IntPtr hWnd, int pid)
    {
        GetWindowThreadProcessId(hWnd, out uint windowPid);
        return windowPid == (uint)pid;
    }

    private static void AddWindowSnapshot(Dictionary<IntPtr, WindowSnapshot> windows, IntPtr hWnd, bool isTopLevel)
    {
        if (hWnd == IntPtr.Zero || windows.ContainsKey(hWnd))
            return;

        windows[hWnd] = new WindowSnapshot
        {
            Handle = hWnd,
            ClassName = GetClassNameSafe(hWnd),
            IsVisible = IsWindowVisible(hWnd),
            IsTopLevel = isTopLevel || GetAncestor(hWnd, GA_ROOT) == hWnd,
        };
    }

    private static string GetClassNameSafe(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        return GetClassName(hWnd, sb, sb.Capacity) > 0
            ? sb.ToString()
            : "(unknown)";
    }

    private static string BuildWpfCauseHint(QuotaProbe? probe, WindowInventory inventory, int? nativeErrorCode)
    {
        if (probe == null)
            return "対象プロセスの採取に失敗したため、WPF 固有の原因までは絞れていません";

        var gdiPercent = probe.GdiQuota > 0 ? probe.GdiObjects * 100 / probe.GdiQuota : 0;
        var userPercent = probe.UserQuota > 0 ? probe.UserObjects * 100 / probe.UserQuota : 0;

        if (gdiPercent >= GuiPressureThresholdPercent)
        {
            return "GDI が高いため、純粋な WPF より WinFormsHost / System.Drawing / Icon / Bitmap / HBITMAP 連携の解放漏れが有力です";
        }

        if (userPercent >= GuiPressureThresholdPercent ||
            inventory.HiddenTopLevelWindows >= 10 ||
            inventory.HiddenHwndWrapperCount >= 10)
        {
            return "USER か隠し HWND が増えています。WPF の Window / Popup / ToolTip / ContextMenu / HwndSource / HwndHost の増殖が有力です";
        }

        if (inventory.WindowsFormsHostCount > 0)
        {
            return "WindowsFormsHost 系 HWND が見えます。WPF 単体より WinForms 連携側の Window / GDI / Handle 管理を疑ってください";
        }

        if (inventory.WebViewHostCount > 0)
        {
            return "WebView 系 HWND が見えます。WebView2 / Chromium ホストのウィンドウ増殖や破棄漏れも候補です";
        }

        if (nativeErrorCode == ErrorNotEnoughQuota)
        {
            return "WPF で 1816 かつ GDI/USER が平常なら desktop heap が有力です。隠し Window や一時 Popup の増殖を確認してください";
        }

        return "この時点では明確な WPF 固有原因は出ていません。再現直前の HWND 数とクラス内訳の変化を見てください";
    }

    private static PROCESS_MEMORY_COUNTERS_EX QueryProcessMemoryInfo(IntPtr hProcess)
    {
        var counters = new PROCESS_MEMORY_COUNTERS_EX
        {
            cb = (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS_EX>()
        };

        if (!GetProcessMemoryInfo(hProcess, ref counters, counters.cb))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        return counters;
    }

    private static SystemPerformanceInfo QueryPerformanceInfo()
    {
        var info = new PERFORMANCE_INFORMATION
        {
            cb = (uint)Marshal.SizeOf<PERFORMANCE_INFORMATION>()
        };

        if (!GetPerformanceInfo(ref info, info.cb))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var pageSize = (ulong)info.PageSize.ToInt64();
        return new SystemPerformanceInfo
        {
            CommitTotalMB     = PagesToMb((ulong)info.CommitTotal.ToInt64(), pageSize),
            CommitLimitMB     = PagesToMb((ulong)info.CommitLimit.ToInt64(), pageSize),
            PhysicalAvailableMB = PagesToMb((ulong)info.PhysicalAvailable.ToInt64(), pageSize),
            KernelPagedMB     = PagesToMb((ulong)info.KernelPaged.ToInt64(), pageSize),
            KernelNonPagedMB  = PagesToMb((ulong)info.KernelNonpaged.ToInt64(), pageSize),
        };
    }

    private static DesktopHeapInfo QueryDesktopHeapInfo()
    {
        var info = new DesktopHeapInfo();

        try
        {
            var desktop = GetThreadDesktop(GetCurrentThreadId());
            if (desktop != IntPtr.Zero &&
                GetUserObjectInformation(desktop, UOI_HEAPSIZE, out uint heapSizeKb, sizeof(uint), out _))
            {
                info.CurrentDesktopHeapKB = (int)heapSizeKb;
            }
        }
        catch
        {
            // 取得失敗時は 0 のまま
        }

        try
        {
            var subsystemWindows = Registry.GetValue(SubsystemsKey, "Windows", null)?.ToString();
            if (!string.IsNullOrWhiteSpace(subsystemWindows))
            {
                var token = subsystemWindows.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault(x => x.StartsWith("SharedSection=", StringComparison.OrdinalIgnoreCase));
                if (token != null)
                {
                    var values = token["SharedSection=".Length..].Split(',');
                    if (values.Length >= 1 && int.TryParse(values[0], out int shared))
                        info.SharedSectionKB = shared;
                    if (values.Length >= 2 && int.TryParse(values[1], out int interactive))
                        info.InteractiveDesktopHeapKB = interactive;
                    if (values.Length >= 3 && int.TryParse(values[2], out int nonInteractive))
                        info.NonInteractiveDesktopHeapKB = nonInteractive;
                }
            }
        }
        catch
        {
            // 取得失敗時は 0 のまま
        }

        return info;
    }

    private static int? ReadRegistryInt(string keyPath, string valueName)
    {
        var value = Registry.GetValue(keyPath, valueName, null);
        return value switch
        {
            int i => i,
            string s when int.TryParse(s, out var parsed) => parsed,
            _ => null
        };
    }

    private static long ToMb(UIntPtr bytes) => (long)(bytes.ToUInt64() / 1024 / 1024);

    private static long PagesToMb(ulong pages, ulong pageSize) =>
        (long)((pages * pageSize) / 1024 / 1024);

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
            for (int i = log.Entries.Count - 1; i >= 0 && results.Count < maxEntries; i--)
            {
                var entry = log.Entries[i];
                if (!tdrSources.Contains(entry.Source)) continue;
                results.Add(new TdrEvent(entry.TimeGenerated, entry.Source,
                    entry.EntryType.ToString(), entry.Message?.Split('\n')[0] ?? ""));
            }
        }
        catch { }

        return results.ToArray();
    }

    public static void WriteToFile(DiagnosticsSnapshot snap)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {snap.Source} @ {snap.Timestamp:yyyy-MM-dd HH:mm:ss.fff} ===");
        if (snap.ExceptionMessage != null)
        {
            sb.AppendLine($"Exception         : {snap.ExceptionMessage}");
            if (snap.NativeErrorCode.HasValue)
                sb.AppendLine($"Win32 Error       : {snap.NativeErrorCode.Value}");
            sb.AppendLine($"Stack             : {snap.StackTrace}");
        }

        if (snap.QuotaProbe != null)
        {
            var probe = snap.QuotaProbe;
            sb.AppendLine($"Process           : {probe.ProcessName} ({probe.ProcessId})");
            sb.AppendLine($"GDI Objects       : {probe.GdiObjects} (peak={probe.GdiPeakObjects}, quota={probe.GdiQuota}{(probe.GdiQuotaIsDefault ? ", default" : "")})");
            sb.AppendLine($"USER Objects      : {probe.UserObjects} (peak={probe.UserPeakObjects}, quota={probe.UserQuota}{(probe.UserQuotaIsDefault ? ", default" : "")})");
            sb.AppendLine($"Handle Count      : {probe.HandleCount}");
            sb.AppendLine($"Thread Count      : {probe.ThreadCount}");
            sb.AppendLine($"Working Set (MB)  : {probe.WorkingSetMB}");
            sb.AppendLine($"Private Usage(MB) : {probe.PrivateUsageMB}");
            sb.AppendLine($"Pagefile Usage(MB): {probe.PagefileUsageMB}");
            sb.AppendLine($"Paged Pool (MB)   : {probe.PagedPoolUsageMB}");
            sb.AppendLine($"NonPaged Pool(MB) : {probe.NonPagedPoolUsageMB}");
            sb.AppendLine($"Commit (MB)       : {probe.CommitTotalMB}/{probe.CommitLimitMB} ({probe.CommitUsagePercent}%)");
            sb.AppendLine($"Avail Phys (MB)   : {probe.AvailablePhysicalMB}");
            sb.AppendLine($"Kernel Pool (MB)  : paged={probe.KernelPagedMB} nonpaged={probe.KernelNonPagedMB}");
            sb.AppendLine($"Session GUI       : GDI={probe.SessionGdiObjects} USER={probe.SessionUserObjects}");
            sb.AppendLine($"Desktop Heap (KB) : current={probe.CurrentDesktopHeapKB} shared={probe.SharedSectionKB} interactive={probe.InteractiveDesktopHeapKB} noninteractive={probe.NonInteractiveDesktopHeapKB}");
            sb.AppendLine($"Missing Resource  : {AnalyzeQuota(probe, snap.NativeErrorCode).MissingResource}");
            sb.AppendLine($"Diagnosis         : {BuildDiagnosis(probe, snap.NativeErrorCode)}");
            sb.AppendLine($"Recommendation    : {AnalyzeQuota(probe, snap.NativeErrorCode).Recommendation}");
        }

        if (snap.Investigation != null)
        {
            var investigation = snap.Investigation;
            sb.AppendLine("Investigation     :");
            sb.AppendLine($"  Missing         : {investigation.MissingResource}");
            sb.AppendLine($"  Summary         : {investigation.Summary}");
            sb.AppendLine($"  Recommendation  : {investigation.Recommendation}");
            sb.AppendLine($"  WPF Hint        : {investigation.WpfCauseHint}");
            if (investigation.WindowInventory != null)
            {
                var inventory = investigation.WindowInventory;
                sb.AppendLine($"  HWND            : total={inventory.TotalWindows} top={inventory.TopLevelWindows} visible={inventory.VisibleWindows} hidden={inventory.HiddenWindows} hiddenTop={inventory.HiddenTopLevelWindows}");
                sb.AppendLine($"  WPF Classes     : HwndWrapper={inventory.HwndWrapperCount} hiddenHwndWrapper={inventory.HiddenHwndWrapperCount} WinForms={inventory.WindowsFormsHostCount} WebView={inventory.WebViewHostCount}");
                sb.AppendLine($"  Top Classes     : {FormatWindowClasses(inventory.TopClasses)}");
            }
        }

        sb.AppendLine();
        File.AppendAllText(LogFilePath, sb.ToString());
    }

    public static string FormatEntry(DiagnosticsSnapshot snap)
    {
        var sb = new StringBuilder();
        sb.Append($"[{snap.Timestamp:HH:mm:ss.fff}] {snap.Source}");

        if (snap.ExceptionMessage != null)
        {
            sb.Append($" | Exc: {snap.ExceptionMessage}");
            if (snap.NativeErrorCode.HasValue)
                sb.Append($" | Win32={snap.NativeErrorCode.Value}");
        }

        if (snap.QuotaProbe != null)
        {
            var probe = snap.QuotaProbe;
            sb.Append($" | GDI={probe.GdiObjects}/{probe.GdiQuota} USER={probe.UserObjects}/{probe.UserQuota}");
            sb.Append($" | Private={probe.PrivateUsageMB}MB");
            sb.Append($" | Commit={probe.CommitUsagePercent}%");
            sb.Append($" | 不足候補={AnalyzeQuota(probe, snap.NativeErrorCode).MissingResource}");
            sb.Append($" | {BuildDiagnosis(probe, snap.NativeErrorCode)}");
        }

        sb.Append($" | RDP={SystemInformation.TerminalServerSession} DWM={GetDwmEnabled()}");
        return sb.ToString();
    }

    public static string FormatInvestigationReport(QuotaInvestigation investigation)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[{DateTime.Now:HH:mm:ss.fff}] 原因スキャン");
        if (investigation.FocusProcessId.HasValue)
            sb.AppendLine($"対象             : {investigation.FocusProcessName} ({investigation.FocusProcessId})");
        sb.AppendLine($"不足候補         : {investigation.MissingResource}");
        sb.AppendLine($"判定             : {investigation.Summary}");
        sb.AppendLine($"次に見る点       : {investigation.Recommendation}");
        sb.AppendLine($"WPF 観点         : {investigation.WpfCauseHint}");
        if (investigation.WindowInventory != null)
        {
            var inventory = investigation.WindowInventory;
            sb.AppendLine($"HWND             : total={inventory.TotalWindows} top={inventory.TopLevelWindows} visible={inventory.VisibleWindows} hidden={inventory.HiddenWindows} hiddenTop={inventory.HiddenTopLevelWindows}");
            sb.AppendLine($"WPF クラス       : HwndWrapper={inventory.HwndWrapperCount} hiddenHwndWrapper={inventory.HiddenHwndWrapperCount} WinForms={inventory.WindowsFormsHostCount} WebView={inventory.WebViewHostCount}");
            sb.AppendLine($"上位クラス       : {FormatWindowClasses(inventory.TopClasses)}");
        }
        return sb.ToString().TrimEnd();
    }

    private static string FormatWindowClasses(IEnumerable<WindowClassSample> classes)
    {
        var entries = classes
            .Select(sample =>
                $"{sample.ClassName}={sample.Count}(top={sample.TopLevelCount}, hidden={sample.HiddenCount})")
            .ToArray();
        return entries.Length == 0 ? "(取得なし)" : string.Join(", ", entries);
    }
}

public sealed class DiagnosticsSnapshot
{
    public DateTime Timestamp { get; set; }
    public string Source { get; set; } = "";
    public string? ExceptionMessage { get; set; }
    public string? StackTrace { get; set; }
    public int? NativeErrorCode { get; set; }
    public QuotaProbe? QuotaProbe { get; set; }
    public QuotaInvestigation? Investigation { get; set; }
}

public sealed class QuotaProbe
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public int GdiObjects { get; set; }
    public int GdiPeakObjects { get; set; }
    public int GdiQuota { get; set; }
    public bool GdiQuotaIsDefault { get; set; }
    public int UserObjects { get; set; }
    public int UserPeakObjects { get; set; }
    public int UserQuota { get; set; }
    public bool UserQuotaIsDefault { get; set; }
    public int HandleCount { get; set; }
    public int ThreadCount { get; set; }
    public long WorkingSetMB { get; set; }
    public long PrivateUsageMB { get; set; }
    public long PagefileUsageMB { get; set; }
    public long PagedPoolUsageMB { get; set; }
    public long NonPagedPoolUsageMB { get; set; }
    public long CommitTotalMB { get; set; }
    public long CommitLimitMB { get; set; }
    public int CommitUsagePercent { get; set; }
    public long AvailablePhysicalMB { get; set; }
    public long KernelPagedMB { get; set; }
    public long KernelNonPagedMB { get; set; }
    public int SessionGdiObjects { get; set; }
    public int SessionUserObjects { get; set; }
    public int CurrentDesktopHeapKB { get; set; }
    public int SharedSectionKB { get; set; }
    public int InteractiveDesktopHeapKB { get; set; }
    public int NonInteractiveDesktopHeapKB { get; set; }
    public string DiagnosisSummary { get; set; } = "";
    public string LikelyMissingResource { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
    public bool HasPressure { get; set; }
}

public sealed class QuotaAnalysis
{
    public string MissingResource { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Recommendation { get; set; } = "";
}

public sealed class QuotaInvestigation
{
    public int? FocusProcessId { get; set; }
    public string? FocusProcessName { get; set; }
    public string MissingResource { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public string WpfCauseHint { get; set; } = "";
    public WindowInventory? WindowInventory { get; set; }
}

public sealed class WindowInventory
{
    public int TotalWindows { get; set; }
    public int VisibleWindows { get; set; }
    public int HiddenWindows { get; set; }
    public int TopLevelWindows { get; set; }
    public int HiddenTopLevelWindows { get; set; }
    public int HwndWrapperCount { get; set; }
    public int HiddenHwndWrapperCount { get; set; }
    public int WindowsFormsHostCount { get; set; }
    public int WebViewHostCount { get; set; }
    public WindowClassSample[] TopClasses { get; set; } = [];
}

public sealed class WindowClassSample
{
    public string ClassName { get; set; } = "";
    public int Count { get; set; }
    public int VisibleCount { get; set; }
    public int HiddenCount { get; set; }
    public int TopLevelCount { get; set; }
}

internal sealed class WindowSnapshot
{
    public IntPtr Handle { get; set; }
    public string ClassName { get; set; } = "";
    public bool IsVisible { get; set; }
    public bool IsTopLevel { get; set; }
}

internal sealed class DesktopHeapInfo
{
    public int CurrentDesktopHeapKB { get; set; }
    public int SharedSectionKB { get; set; }
    public int InteractiveDesktopHeapKB { get; set; }
    public int NonInteractiveDesktopHeapKB { get; set; }
}

internal sealed class SystemPerformanceInfo
{
    public long CommitTotalMB { get; set; }
    public long CommitLimitMB { get; set; }
    public long PhysicalAvailableMB { get; set; }
    public long KernelPagedMB { get; set; }
    public long KernelNonPagedMB { get; set; }
}

public record GpuInfo(string Name, string DriverVersion, string DriverDate);

public record TdrEvent(DateTime Time, string Source, string EntryType, string Message);
