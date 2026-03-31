# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
dotnet build
dotnet run
dotnet publish -c Release
```

Target: `net8.0-windows`, output type `WinExe`. Single NuGet dependency: `System.Management` (WMI queries).

## Project Purpose

A WPF Windows desktop tool (`MessageHookTool`) that monitors Win32 window events on a selected process. Key features:
- Hooks `EVENT_OBJECT_LOCATIONCHANGE` and system events via `SetWinEventHook`
- Tracks event frequency and warns when it exceeds configurable thresholds
- Monitors GDI/User object counts, handle counts, and working set for leak detection
- Captures TDR (GPU timeout/recovery) events from the Windows Event Log
- Queries GPU info via WMI

## Architecture

**MainWindow.xaml.cs** — Core monitoring logic. Spawns a dedicated STA hook thread with a Win32 message loop. The `OnWinEvent` callback runs on that thread and uses `Interlocked`/`volatile` for lock-free counters, then posts log entries to the UI dispatcher. A 1-second timer updates the status bar with live resource metrics.

**DiagnosticsLogger.cs** — Standalone diagnostic helper. Queries GPU via `Win32_VideoController` WMI, reads TDR events from Event Log (sources: `nvlddmkm`, `atikmdag`, `igfx`, `dxgkrnl`, `Display`), snapshots process resource counts, and writes to `diag.log`.

**App.xaml.cs** — Registers three global exception handlers (`DispatcherUnhandledException`, `AppDomain.UnhandledException`, `TaskScheduler.UnobservedTaskException`) and routes them to `DiagnosticsLogger`.

**ProcessEntry.cs** — Thin wrapper around `System.Diagnostics.Process` for the process-selector combobox (shows PID, name, window title).

**MainWindow.xaml** — UI with process selector, start/stop button, two log viewers (event log + diagnostic log), filter toggles (System / LocationChange / WindowEvent / QueueStatus), and a status bar.

## Threading Model

- Hook thread: STA apartment, runs `GetMessage`/`TranslateMessage`/`DispatchMessage` loop
- UI thread: receives entries via `Dispatcher.BeginInvoke`
- Shared counters use `Interlocked` operations or `volatile` — avoid introducing locks across threads

## Code Conventions

- Comments and UI labels are in Japanese
- Section headers use `───` separator style
- No test project exists in the solution
