using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Dropper.App.Services;
using Dropper.Core.Crypto;
using Dropper.Core.Engine;

namespace Dropper.App.Views;

public partial class PairingWindow : Window
{
    private readonly App _app;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private PairingTicket? _ticket;
    private PairingRequest? _pending;
    private bool _finished;
    private DateTimeOffset? _pcHostUntil;
    private TaskCompletionSource<bool>? _joinerConfirm;
    private CancellationTokenSource? _joinerCts;
    private bool _legacyTls;

    internal PairingWindow(App app)
    {
        _app = app;
        InitializeComponent();
        ThemeManager.Attach(this);
        SourceInitialized += (_, _) => HideFromScreenCapture();
        PcFingerprint.Text = Fingerprint.Display(app.Engine.Identity.Fingerprint);
        _timer.Tick += (_, _) => UpdateExpiry();
        Closing += OnClosing;
        if (!app.Engine.Tls13Available)
        {
            // Windows 10: phones need TLS 1.3, so only PC-to-PC pairing is possible.
            PhoneMode.IsEnabled = false;
            PhoneMode.ToolTip = "Pairing a phone needs Windows 11 (phones use TLS 1.3 only).";
            PcMode.IsChecked = true; // Mode_Checked shows the PC panel
            return;
        }
        NewTicket(); // throws InvalidOperationException when there is no LAN; the caller reports it
    }

    private void NewTicket()
    {
        _ticket = _app.Engine.StartPairing();
        _pending = null;
        _finished = false;
        QrImage.Source = QrRenderer.Render(_ticket.Uri);
        DevMode.WritePairingLink(_app.Engine.DataDirectory, _ticket.Uri);
        ExpiredOverlay.Visibility = Visibility.Collapsed;
        Show(QrPanel);
        UpdateExpiry();
        _timer.Start();
    }

    private void UpdateExpiry()
    {
        if (_pcHostUntil is { } until)
        {
            var remaining = until - _app.Engine.Now;
            if (remaining <= TimeSpan.Zero)
            {
                _pcHostUntil = null;
                _app.Engine.CancelPcPairing();
                HostStatus.Text = "Stopped waiting. Start again whenever the other PC is ready.";
                HostButton.Content = "Let another PC find this one";
            }
            else
            {
                HostStatus.Text = $"Waiting… On the other PC: Pair a device → Another PC → Find PCs. ({(int)remaining.TotalMinutes}:{remaining.Seconds:00} left)";
            }
        }
        if (_ticket is null) return;
        var left = _ticket.ExpiresAt - _app.Engine.Now;
        if (left <= TimeSpan.Zero)
        {
            _timer.Stop();
            ExpiryText.Text = "Expired";
            ExpiredOverlay.Visibility = Visibility.Visible;
            _app.Engine.CancelPairing();
            return;
        }
        ExpiryText.Text = $"Code expires in {(int)left.TotalMinutes}:{left.Seconds:00}";
    }

    private void Show(FrameworkElement panel)
    {
        QrPanel.Visibility = panel == QrPanel ? Visibility.Visible : Visibility.Collapsed;
        PcPanel.Visibility = panel == PcPanel ? Visibility.Visible : Visibility.Collapsed;
        ModeSwitch.Visibility = panel == QrPanel || panel == PcPanel ? Visibility.Visible : Visibility.Collapsed;
        ApprovePanel.Visibility = panel == ApprovePanel ? Visibility.Visible : Visibility.Collapsed;
        ResultPanel.Visibility = panel == ResultPanel ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>A phone scanned the code and proved it; the user compares the 6-digit codes.</summary>
    public void ShowRequest(PairingRequest request)
    {
        _timer.Stop();
        _pending = request;
        string model = string.IsNullOrEmpty(request.Model) ? "" : $" ({request.Model})";
        ApproveDeviceText.Text = $"“{request.DeviceName}”{model} wants to pair with this PC.";
        SasText.Text = request.Sas;
        ApproveDetails.Text = $"From {request.From} · key {request.Fingerprint}";
        ApproveHint.Text = request.IsPc
            ? "Approve only if the other PC shows exactly this code and you approve there too. If the codes differ, reject."
            : "Approve only if your phone shows exactly this code. If it doesn't, someone else may be trying to pair: reject.";
        ShowLegacyTls(request.LegacyTls);
        RejectButton.IsEnabled = true;
        Show(ApprovePanel);
        Activate();
        request.Abandoned.Register(() => Dispatcher.BeginInvoke(() =>
        {
            if (_pending == request && !_finished)
                ShowResult(false, "Pairing cancelled", request.IsPc
                    ? "The other PC stopped waiting. Try again when both PCs are ready."
                    : "The phone stopped waiting. Make a new code to try again.");
        }));
    }

    public void ShowOutcome(PairingOutcome outcome)
    {
        if (outcome.Success)
            ShowResult(true, "Paired!", $"{outcome.DeviceName} can now send and receive. You can close this window.");
        else
            ShowResult(false, "Not paired", outcome.Message + (PcMode.IsChecked == true ? " Try again when both PCs are ready." : " Make a new code to try again."));
    }

    private void ShowResult(bool success, string title, string text)
    {
        _finished = true;
        _timer.Stop();
        ResultTitle.Text = title;
        ResultText.Text = text;
        ResultGlyph.Text = success ? "" : "";
        ResultGlyph.Foreground = (Brush)FindResource(success ? "SuccessBrush" : "DangerBrush");
        ResultIconCircle.Background = (Brush)FindResource(success ? "SuccessSoftBrush" : "DangerSoftBrush");
        TryAgainButton.Visibility = success ? Visibility.Collapsed : Visibility.Visible;
        Show(ResultPanel);
    }

    private void Approve_Click(object sender, RoutedEventArgs e)
    {
        ApproveButton.IsEnabled = RejectButton.IsEnabled = false;
        bool allowTls12 = _legacyTls && LegacyTlsCheck.IsChecked == true;
        if (_joinerConfirm is { } c) c.TrySetResult(!_legacyTls || allowTls12);
        else _pending?.Approve(allowTls12);
    }

    /// <summary>TLS 1.2 is never implied: Approve stays disabled until the user allows it.</summary>
    private void ShowLegacyTls(bool legacy)
    {
        _legacyTls = legacy;
        LegacyTlsCheck.IsChecked = false;
        LegacyTlsPanel.Visibility = legacy ? Visibility.Visible : Visibility.Collapsed;
        ApproveButton.IsEnabled = !legacy;
    }

    private void LegacyTls_Click(object sender, RoutedEventArgs e) =>
        ApproveButton.IsEnabled = RejectButton.IsEnabled && LegacyTlsCheck.IsChecked == true;

    private void Reject_Click(object sender, RoutedEventArgs e)
    {
        ApproveButton.IsEnabled = RejectButton.IsEnabled = false;
        if (_joinerConfirm is { } c) c.TrySetResult(false);
        else _pending?.Reject();
    }

    private void NewCode_Click(object sender, RoutedEventArgs e)
    {
        if (PcMode.IsChecked == true)
        {
            _finished = false;
            Show(PcPanel);
            return;
        }
        try { NewTicket(); }
        catch (InvalidOperationException ex) { ShowResult(false, "Can't pair right now", ex.Message); }
    }

    // ------------------------------------------------------------------ another PC

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        if (QrPanel is null || PcPanel is null) return; // still initializing
        if (PcMode.IsChecked == true)
        {
            _timer.Stop();
            _app.Engine.CancelPairing();
            _ticket = null;
            _finished = false;
            Show(PcPanel);
            _timer.Start();
        }
        else
        {
            StopHosting();
            try { NewTicket(); }
            catch (InvalidOperationException ex) { ShowResult(false, "Can't pair right now", ex.Message); }
        }
    }

    private void Host_Click(object sender, RoutedEventArgs e)
    {
        if (_pcHostUntil is not null)
        {
            StopHosting();
            return;
        }
        try
        {
            _pcHostUntil = _app.Engine.StartPcPairing();
            HostButton.Content = "Stop waiting";
            UpdateExpiry();
            _timer.Start();
        }
        catch (InvalidOperationException ex)
        {
            HostStatus.Text = ex.Message;
        }
    }

    private void StopHosting()
    {
        _pcHostUntil = null;
        _app.Engine.CancelPcPairing();
        HostStatus.Text = "Other PCs on your network can find this one for 3 minutes.";
        HostButton.Content = "Let another PC find this one";
    }

    private async void Find_Click(object sender, RoutedEventArgs e)
    {
        FindButton.IsEnabled = false;
        FindStatus.Text = "Looking…";
        FoundList.Items.Clear();
        var found = await _app.Engine.FindPcsAsync(TimeSpan.FromSeconds(1.5));
        FindButton.IsEnabled = true;
        FindButton.Content = "Search again";
        if (found.Count == 0)
        {
            FindStatus.Text = "No PC is waiting. On the other PC, choose “Let another PC find this one”, then search again.";
            return;
        }
        FindStatus.Text = found.Count == 1 ? "Found 1 PC:" : $"Found {found.Count} PCs:";
        foreach (var pc in found)
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 6), LastChildFill = true };
            var pair = new Button { Style = (Style)FindResource("SecondaryButton"), Content = "Pair", Tag = pc };
            pair.Click += PairWithFound_Click;
            DockPanel.SetDock(pair, Dock.Right);
            row.Children.Add(pair);
            var label = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            label.Children.Add(new TextBlock { Text = pc.Name, FontWeight = FontWeights.SemiBold });
            label.Children.Add(new TextBlock { Text = pc.Endpoint.Address.ToString(), Style = (Style)FindResource("CaptionText") });
            row.Children.Add(label);
            FoundList.Items.Add(row);
        }
    }

    private async void PairWithFound_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not DiscoveredPc pc) return;
        StopHosting();
        _finished = false;
        _joinerCts = new CancellationTokenSource();
        FindStatus.Text = $"Connecting to {pc.Name}…";
        var outcome = await _app.Engine.PairWithPcAsync(pc.Endpoint,
            code => Dispatcher.Invoke(() => AskJoinerToConfirm(pc, code)), _joinerCts.Token);
        _joinerConfirm = null;
        if (!IsLoaded) return;
        ShowOutcome(outcome);
    }

    /// <summary>Joiner side: show the 6-digit code and wait for the user's answer.</summary>
    private Task<bool> AskJoinerToConfirm(DiscoveredPc pc, PcPairingCode code)
    {
        _joinerConfirm = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        ApproveDeviceText.Text = $"Pairing with “{pc.Name}” ({pc.Endpoint.Address}).";
        SasText.Text = code.Sas;
        ApproveDetails.Text = "Approve here and on the other PC.";
        ApproveHint.Text = "Approve only if the other PC shows exactly this code. If the codes differ, reject.";
        RejectButton.IsEnabled = true;
        ShowLegacyTls(code.LegacyTls);
        Show(ApprovePanel);
        Activate();
        return _joinerConfirm.Task;
    }

    private void Done_Click(object sender, RoutedEventArgs e) => Close();

    /// <summary>
    /// The QR code carries a one-time secret: keep it out of screenshots, recordings and
    /// screen sharing (Teams, Zoom…). Developer mode skips this so automated tests can capture it.
    /// </summary>
    private void HideFromScreenCapture()
    {
        if (DevMode.Enabled) return;
        var hwnd = new WindowInteropHelper(this).Handle;
        if (!SetWindowDisplayAffinity(hwnd, WdaExcludeFromCapture))
            SetWindowDisplayAffinity(hwnd, WdaMonitor); // older Windows: shows black instead
    }

    private const uint WdaMonitor = 0x01;
    private const uint WdaExcludeFromCapture = 0x11;

    [DllImport("user32.dll")]
    private static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        _timer.Stop();
        if (!_finished) _pending?.Reject();
        _joinerConfirm?.TrySetResult(false);
        _joinerCts?.Cancel();
        _app.Engine.CancelPairing();
        _app.Engine.CancelPcPairing();
    }
}
