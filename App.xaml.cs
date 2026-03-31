using System.ComponentModel;
using System.Windows.Threading;
using WpfApplication = System.Windows.Application;
using WpfStartupEventArgs = System.Windows.StartupEventArgs;

namespace MessageHookTool;

public partial class App : WpfApplication
{
    // 例外ログをUIに転送するためのイベント
    public static event Action<DiagnosticsSnapshot>? DiagnosticsRecorded;

    protected override void OnStartup(WpfStartupEventArgs e)
    {
        base.OnStartup(e);

        // 方法2: UIスレッドの未処理例外
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        // 方法2: 非UIスレッドの未処理例外
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        // TaskScheduler例外
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs args)
    {
        RecordException("DispatcherUnhandledException", args.Exception);

        // Win32例外（GDIリソース枯渇など）の場合はクラッシュを防いで継続
        if (args.Exception is Win32Exception)
            args.Handled = true;
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs args)
    {
        if (args.ExceptionObject is Exception ex)
            RecordException("UnhandledException", ex);
    }

    private void OnUnobservedTaskException(object? sender, System.Threading.Tasks.UnobservedTaskExceptionEventArgs args)
    {
        RecordException("UnobservedTaskException", args.Exception);
        args.SetObserved();
    }

    private static void RecordException(string source, Exception ex)
    {
        var snap = DiagnosticsLogger.TakeSnapshot(source, ex);
        DiagnosticsLogger.WriteToFile(snap);
        DiagnosticsRecorded?.Invoke(snap);
    }
}
