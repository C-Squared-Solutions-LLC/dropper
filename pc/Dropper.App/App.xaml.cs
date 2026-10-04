using System.IO;
using System.Windows;
using System.Windows.Threading;
using Dropper.App.Services;
using Dropper.App.Views;
using System.Net;
using Dropper.Core.Engine;
using Dropper.Core.Net;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Microsoft.Win32;

namespace Dropper.App;

public partial class App : Application
{
    private SingleInstance? _single;
    private DropperEngine? _engine;
    private TrayIcon? _tray;
    private MainWindow? _main;
    private PairingWindow? _pairing;
    private SettingsWindow? _settings;
    private bool _trayHintShown;

    public static new App Current => (App)Application.Current;
    public DropperEngine Engine => _engine ?? throw new InvalidOperationException("Not started");
    public bool EngineReady { get; private set; }
    public bool Quitting { get; private set; }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Elevated helper mode (started by Settings or install.ps1 through UAC): edit the
        // firewall rules for this program and exit. No window, no engine, no IPC.
        if (e.Args.Length >= 1 && e.Args[0] is "--configure-firewall" or "--remove-firewall")
        {
            Shutdown(RunFirewallCommand(e.Args));
            return;
        }

        var args = CommandLine.Parse(e.Args);

        _single = new SingleInstance(DevMode.Enabled ? "dev" : "");
        if (!_single.IsPrimary)
        {
            _single.SendToPrimary(args.ToMessage());
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandled;
        SessionEnding += (_, _) => _ = QuitAsync();
        System.Windows.Forms.Application.EnableVisualStyles();
        ThemeManager.Initialize(this);

        _engine = new DropperEngine(DevMode.Enabled ? DevMode.Options() : new EngineOptions
        {
            DataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Dropper"),
        });
        HookEngine(_engine);

        _tray = new TrayIcon(ShowMain, SendClipboard, () => { ShowMain(); _main?.ChooseFiles(); },
            ShowPairing, ShowSettings, () => _ = QuitAsync());

        _main = new MainWindow(this);
        if (!args.Minimized) _main.Show();
        _single.Listen(msg => Dispatcher.BeginInvoke(() => HandleIpc(msg)));

        try
        {
            await _engine.StartAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Dropper couldn't start:\n\n{ex.Message}", "Dropper", MessageBoxButton.OK, MessageBoxImage.Error);
            await QuitAsync();
            return;
        }
        EngineReady = true;
        _main.OnEngineStarted();
        UpdateTrayTooltip();

        if (args.Paths.Count > 0) QueuePaths(args.Paths);
        if (args.Pair) ShowPairing();
    }

    // ------------------------------------------------------------------ engine events

    private void HookEngine(DropperEngine engine)
    {
        engine.ItemAdded += i => Ui(() => _main?.OnItemAdded(i));
        engine.ItemChanged += i => Ui(() => _main?.OnItemChanged(i));
        engine.ItemRemoved += i => Ui(() => _main?.OnItemRemoved(i));
        engine.ItemReceived += i => Ui(() => OnItemReceived(i));
        engine.DevicesChanged += () => Ui(() =>
        {
            _main?.RefreshDevices();
            _settings?.RefreshDevices();
            UpdateTrayTooltip();
        });
        engine.NetworkChanged += () => Ui(() =>
        {
            _main?.RefreshDevices();
            _settings?.RefreshNetwork();
        });
        engine.PairingRequested += r => Ui(() =>
        {
            if (_pairing is not null) _pairing.ShowRequest(r);
            else r.Reject();
        });
        engine.PairingCompleted += o => Ui(() => _pairing?.ShowOutcome(o));
    }

    private void Ui(Action action) => Dispatcher.BeginInvoke(action);

    private void OnItemReceived(ActivityItem item)
    {
        var config = Engine.Config;
        if (item.Kind == ItemKind.Text)
        {
            bool copied = config.AutoCopyText && item.Text is not null && ClipboardService.SetText(item.Text);
            if (config.NotifyOnReceive)
            {
                string title = item.IsLink ? $"Link from {item.DeviceName}" : $"Text from {item.DeviceName}";
                string body = Views.Format.Snippet(item.Text, "") + (copied ? "\nCopied to clipboard" : "");
                _tray?.Notify(title, body, ShowMain);
            }
        }
        else if (config.NotifyOnReceive)
        {
            string path = item.LocalPath!;
            _tray?.Notify($"File from {item.DeviceName}", $"{item.Name} · {Views.Format.Size(item.Size)}",
                () => WindowsIntegration.ShowInFolder(path));
        }
    }

    private void UpdateTrayTooltip()
    {
        if (_tray is null || _engine is null || !EngineReady) return;
        var connected = Engine.GetDevices().FirstOrDefault(d => d.Connected);
        _tray.SetTooltip(connected is not null ? $"Dropper · {connected.Name} connected" : "Dropper · waiting for your phone");
    }

    // ------------------------------------------------------------------ commands

    private void HandleIpc(IpcMessage msg)
    {
        switch (msg.Command)
        {
            case "send":
                ShowMain();
                QueuePaths(msg.Paths);
                break;
            case "pair":
                ShowPairing();
                break;
            default:
                ShowMain();
                break;
        }
    }

    public void QueuePaths(IReadOnlyList<string> paths)
    {
        if (!EngineReady) return;
        var existing = paths.Where(p => File.Exists(p) || Directory.Exists(p)).ToList();
        if (existing.Count == 0) return;
        try { Engine.QueueFiles(existing); }
        catch (InvalidOperationException ex) { ShowMain(); _main?.ShowBanner(ex.Message, isError: true); }
    }

    public void SendClipboard()
    {
        if (!EngineReady) return;
        try
        {
            switch (ClipboardService.Read())
            {
                case ClipboardContent.Files f:
                    Engine.QueueFiles(f.Paths);
                    break;
                case ClipboardContent.Image img:
                    string folder = Path.Combine(Engine.DataDirectory, "tmp", Guid.NewGuid().ToString("N"));
                    Engine.QueueFiles(new[] { ClipboardService.SaveImage(img.Bitmap, folder) }, temporary: true);
                    break;
                case ClipboardContent.Text t:
                    Engine.QueueText(t.Value);
                    break;
                default:
                    _main?.ShowBanner("The clipboard is empty.", isError: false);
                    break;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException)
        {
            ShowMain();
            _main?.ShowBanner(ex.Message, isError: true);
        }
    }

    public void ShowMain()
    {
        if (_main is null) return;
        if (!_main.IsVisible) _main.Show();
        if (_main.WindowState == WindowState.Minimized) _main.WindowState = WindowState.Normal;
        _main.Activate();
        _main.Topmost = true;
        _main.Topmost = false;
        _main.Focus();
    }

    public void ShowPairing()
    {
        if (!EngineReady) return;
        ShowMain();
        if (_pairing is not null)
        {
            _pairing.Activate();
            return;
        }
        try
        {
            _pairing = new PairingWindow(this) { Owner = _main };
        }
        catch (InvalidOperationException ex)
        {
            _main?.ShowBanner(ex.Message, isError: true);
            return;
        }
        _pairing.Closed += (_, _) => _pairing = null;
        _pairing.Show();
    }

    public void ShowSettings()
    {
        if (!EngineReady) return;
        ShowMain();
        if (_settings is not null)
        {
            _settings.Activate();
            return;
        }
        _settings = new SettingsWindow(this) { Owner = _main };
        _settings.Closed += (_, _) => _settings = null;
        _settings.Show();
    }

    /// <summary>Called when the main window is closed with "keep running in the tray" on.</summary>
    public void OnMainHidden()
    {
        if (_trayHintShown) return;
        _trayHintShown = true;
        _tray?.Notify("Dropper is still running", "It keeps receiving in the background. Right-click the tray icon to quit.", ShowMain);
    }

    public async Task QuitAsync()
    {
        if (Quitting) return;
        Quitting = true;
        _pairing?.Close();
        _settings?.Close();
        _main?.Close();
        _tray?.Dispose();
        if (_engine is not null)
        {
            try { await _engine.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception) { /* exiting anyway */ }
        }
        _single?.Dispose();
        Shutdown();
    }

    private static int RunFirewallCommand(string[] args)
    {
        try
        {
            string exe = WindowsIntegration.ExePath;
            if (args[0] == "--remove-firewall")
            {
                Firewall.Remove(exe);
                return 0;
            }
            int port = args.Length > 1 && int.TryParse(args[1], out int p) && p is >= 1024 and <= 65535 ? p : Wire.DefaultPort;
            Firewall.Configure(exe, port);
            return Firewall.RulesPresent(exe) ? 0 : 1;
        }
        catch (Exception)
        {
            return 2;
        }
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _engine?.Log($"Unhandled UI exception: {e.Exception}");
        MessageBox.Show($"Something went wrong:\n\n{e.Exception.Message}", "Dropper", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}

/// <summary>Dropper.exe [--minimized] [--pair] [--send] [paths...]</summary>
internal sealed record CommandLine(bool Minimized, bool Pair, IReadOnlyList<string> Paths)
{
    public static CommandLine Parse(string[] args)
    {
        bool minimized = false, pair = false;
        var paths = new List<string>();
        foreach (var a in args)
        {
            if (a.Equals("--minimized", StringComparison.OrdinalIgnoreCase)) minimized = true;
            else if (a.Equals("--pair", StringComparison.OrdinalIgnoreCase)) pair = true;
            else if (a.Equals("--send", StringComparison.OrdinalIgnoreCase)) { }
            else if (!a.StartsWith("--", StringComparison.Ordinal))
            {
                try { paths.Add(Path.GetFullPath(a)); }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
            }
        }
        return new CommandLine(minimized, pair, paths);
    }

    public IpcMessage ToMessage() =>
        Paths.Count > 0 ? new IpcMessage("send", Paths.ToArray())
        : Pair ? new IpcMessage("pair", Array.Empty<string>())
        : new IpcMessage("show", Array.Empty<string>());
}

/// <summary>
/// Developer mode (DROPPER_DEV_LOOPBACK=1): loopback-only listening, a separate data
/// folder and identity key, and the pairing link written to a file so an emulator
/// test can pair without a camera. It can only make Dropper less reachable, never more.
/// </summary>
internal static class DevMode
{
    public static bool Enabled { get; } = Environment.GetEnvironmentVariable("DROPPER_DEV_LOOPBACK") == "1";

    public static EngineOptions Options()
    {
        var advertise = IPAddress.TryParse(Environment.GetEnvironmentVariable("DROPPER_DEV_ADVERTISE"), out var a) ? a : IPAddress.Parse("10.0.2.2");
        return new EngineOptions
        {
            DataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Dropper-dev"),
            KeyName = "Dropper-Identity-dev",
            ListenOverride = [new LanAddress(IPAddress.Loopback, 8, "loopback (dev)", "dev") { Advertised = advertise }],
            DiscoveryBindAddress = IPAddress.Loopback,
            ReceiveFolderOverride = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Dropper-dev", "received"),
        };
    }

    public static void WritePairingLink(string dataDir, string uri)
    {
        if (Enabled) File.WriteAllText(Path.Combine(dataDir, "dev-pairing-uri.txt"), uri);
    }
}
