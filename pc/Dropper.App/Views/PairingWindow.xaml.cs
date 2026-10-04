using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
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

    internal PairingWindow(App app)
    {
        _app = app;
        InitializeComponent();
        ThemeManager.Attach(this);
        SourceInitialized += (_, _) => HideFromScreenCapture();
        PcFingerprint.Text = Fingerprint.Display(app.Engine.Identity.Fingerprint);
        _timer.Tick += (_, _) => UpdateExpiry();
        Closing += OnClosing;
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
        ApproveDetails.Text = $"From {request.From} · phone key {request.Fingerprint}";
        ApproveButton.IsEnabled = RejectButton.IsEnabled = true;
        Show(ApprovePanel);
        Activate();
        request.Abandoned.Register(() => Dispatcher.BeginInvoke(() =>
        {
            if (_pending == request && !_finished)
                ShowResult(false, "Pairing cancelled", "The phone stopped waiting. Make a new code to try again.");
        }));
    }

    public void ShowOutcome(PairingOutcome outcome)
    {
        if (outcome.Success)
            ShowResult(true, "Paired!", $"{outcome.DeviceName} can now send and receive. You can close this window.");
        else
            ShowResult(false, "Not paired", outcome.Message + " Make a new code to try again.");
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
        _pending?.Approve();
    }

    private void Reject_Click(object sender, RoutedEventArgs e)
    {
        ApproveButton.IsEnabled = RejectButton.IsEnabled = false;
        _pending?.Reject();
    }

    private void NewCode_Click(object sender, RoutedEventArgs e)
    {
        try { NewTicket(); }
        catch (InvalidOperationException ex) { ShowResult(false, "Can't pair right now", ex.Message); }
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
        _app.Engine.CancelPairing();
    }
}
