using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Dropper.App.Services;
using Dropper.Core.Crypto;
using Dropper.Core.Net;
using Dropper.Core.Protocol;

namespace Dropper.App.Views;

public partial class SettingsWindow : Window
{
    private readonly App _app;

    internal SettingsWindow(App app)
    {
        _app = app;
        InitializeComponent();
        ThemeManager.Attach(this);
        Load();
    }

    private void Load()
    {
        var engine = _app.Engine;
        var config = engine.Config;
        ReceiveFolderText.Text = engine.ReceiveFolder;
        ReceiveFolderText.ToolTip = engine.ReceiveFolder;
        AutoCopyToggle.IsChecked = config.AutoCopyText;
        NotifyToggle.IsChecked = config.NotifyOnReceive;
        TrayToggle.IsChecked = config.CloseToTray;
        StartupToggle.IsChecked = WindowsIntegration.IsStartupEnabled();
        SendToToggle.IsChecked = WindowsIntegration.IsSendToEnabled();
        PortBox.Text = engine.Port.ToString();
        KeyStorageText.Text = engine.Identity.StorageDescription;
        FingerprintBox.Text = Fingerprint.DisplayFull(engine.Identity.Fingerprint);
        VersionText.Text = $"Dropper {Wire.AppVersion} · protocol v{Wire.ProtocolVersion}";
        RefreshDevices();
        RefreshNetwork();
        RefreshFirewall();
    }

    public void RefreshDevices()
    {
        DeviceList.Items.Clear();
        var devices = _app.Engine.GetDevices();
        NoDevicesText.Visibility = devices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var d in devices)
        {
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var icon = new Border
            {
                Width = 36, Height = 36, CornerRadius = new CornerRadius(18),
                Background = (Brush)FindResource("AccentSoftBrush"), VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock
                {
                    Style = (Style)FindResource("GlyphText"), Text = "", FontSize = 16,
                    Foreground = (Brush)FindResource("AccentTextBrush"),
                },
            };
            grid.Children.Add(icon);

            var info = new StackPanel { Margin = new Thickness(12, 0, 12, 0) };
            info.Children.Add(new TextBlock { Text = d.Name, FontWeight = FontWeights.SemiBold });
            string seen = d.Connected ? "connected now" : d.LastSeen is { } ls ? "last seen " + Format.Time(ls) : "not connected yet";
            info.Children.Add(new TextBlock
            {
                Style = (Style)FindResource("SubtleText"),
                Text = (string.IsNullOrEmpty(d.Model) ? "" : d.Model + " · ") + "paired " + Format.Time(d.PairedAt) + " · " + seen,
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0),
            });
            info.Children.Add(new TextBlock { Style = (Style)FindResource("MonoText"), Text = d.FingerprintDisplay, Margin = new Thickness(0, 4, 0, 0) });
            if (d.Tls12Allowed)
                info.Children.Add(new TextBlock
                {
                    Style = (Style)FindResource("CaptionText"),
                    Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush"),
                    Text = "TLS 1.2 allowed (that PC runs Windows 10). Remove and pair again to revoke.",
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0),
                });
            Grid.SetColumn(info, 1);
            grid.Children.Add(info);

            var remove = new Button { Style = (Style)FindResource("SecondaryButton"), Content = "Remove", VerticalAlignment = VerticalAlignment.Top, Tag = d };
            remove.Click += async (_, _) =>
            {
                if (MessageBox.Show(this, $"Remove “{d.Name}”?\n\nIt will be disconnected and can't connect again until you pair it again.",
                        "Remove device", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
                await _app.Engine.RemoveDeviceAsync(d.FpHex);
            };
            Grid.SetColumn(remove, 2);
            grid.Children.Add(remove);

            DeviceList.Items.Add(grid);
        }
    }

    public void RefreshNetwork()
    {
        var engine = _app.Engine;
        if (engine.IsListening)
        {
            NetStatusText.Text = "Listening on " + string.Join(", ", engine.Lans.Select(l => $"{l.Address}:{engine.Port} ({l.InterfaceName})"));
            NetDot.Fill = (Brush)FindResource("SuccessBrush");
        }
        else
        {
            NetStatusText.Text = engine.NetworkError ?? "Not listening";
            NetDot.Fill = (Brush)FindResource("DangerBrush");
        }

        InterfaceChoices.Children.Clear();
        string? current = engine.Config.InterfaceOverride;
        AddInterfaceChoice(null, "Automatic (recommended)", current is null);
        foreach (var (id, label) in LanInterfaces.ListCandidates())
            AddInterfaceChoice(id, label, string.Equals(current, id, StringComparison.OrdinalIgnoreCase));
    }

    private void AddInterfaceChoice(string? id, string label, bool selected)
    {
        var rb = new RadioButton
        {
            Style = (Style)FindResource("ChoiceRadio"),
            Content = new TextBlock { Text = label, TextTrimming = TextTrimming.CharacterEllipsis },
            GroupName = "iface",
            IsChecked = selected,
        };
        rb.Checked += (_, _) =>
        {
            if (string.Equals(_app.Engine.Config.InterfaceOverride, id, StringComparison.OrdinalIgnoreCase)) return;
            _app.Engine.UpdateConfig(c => c.InterfaceOverride = id);
        };
        InterfaceChoices.Children.Add(rb);
    }

    private void RefreshFirewall()
    {
        bool ok = WindowsIntegration.FirewallRulesPresent();
        FirewallText.Text = ok
            ? "Allowed for your local subnet on private networks only."
            : "Not set up yet. Your devices can't reach this PC until Dropper is allowed.";
        FirewallText.Foreground = (Brush)FindResource(ok ? "SuccessBrush" : "WarningBrush");
    }

    // ------------------------------------------------------------------ handlers

    private void ChangeFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Where should received files go?",
            InitialDirectory = Directory.Exists(_app.Engine.ReceiveFolder) ? _app.Engine.ReceiveFolder : null,
        };
        if (dlg.ShowDialog(this) != true) return;
        _app.Engine.UpdateConfig(c => c.ReceiveFolder = dlg.FolderName);
        ReceiveFolderText.Text = _app.Engine.ReceiveFolder;
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenFolder(_app.Engine.ReceiveFolder);

    private void AutoCopy_Click(object sender, RoutedEventArgs e) =>
        _app.Engine.UpdateConfig(c => c.AutoCopyText = AutoCopyToggle.IsChecked == true);

    private void Notify_Click(object sender, RoutedEventArgs e) =>
        _app.Engine.UpdateConfig(c => c.NotifyOnReceive = NotifyToggle.IsChecked == true);

    private void Tray_Click(object sender, RoutedEventArgs e) =>
        _app.Engine.UpdateConfig(c => c.CloseToTray = TrayToggle.IsChecked == true);

    private void Startup_Click(object sender, RoutedEventArgs e)
    {
        try { WindowsIntegration.SetStartup(StartupToggle.IsChecked == true); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            MessageBox.Show(this, ex.Message, "Dropper", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        StartupToggle.IsChecked = WindowsIntegration.IsStartupEnabled();
    }

    private void SendTo_Click(object sender, RoutedEventArgs e)
    {
        try { WindowsIntegration.SetSendTo(SendToToggle.IsChecked == true); }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Couldn't update the Send to menu:\n\n" + ex.Message, "Dropper", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        SendToToggle.IsChecked = WindowsIntegration.IsSendToEnabled();
    }

    private void Pair_Click(object sender, RoutedEventArgs e) => _app.ShowPairing();

    private void ApplyPort_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PortBox.Text.Trim(), out int port) || port is < 1024 or > 65535)
        {
            MessageBox.Show(this, "Pick a port between 1024 and 65535.", "Dropper", MessageBoxButton.OK, MessageBoxImage.Information);
            PortBox.Text = _app.Engine.Port.ToString();
            return;
        }
        if (port == _app.Engine.Port) return;
        _app.Engine.UpdateConfig(c => c.Port = port);
        MessageBox.Show(this,
            "Port changed. Paired devices find the new port automatically through discovery." +
            (WindowsIntegration.FirewallRulesPresent() ? "\n\nRun “Allow on local network…” again so the firewall rule uses the new port." : ""),
            "Dropper", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Firewall_Click(object sender, RoutedEventArgs e)
    {
        var (ok, message) = WindowsIntegration.ConfigureFirewall(_app.Engine.Port);
        RefreshFirewall();
        if (!ok && message != "Cancelled.")
            MessageBox.Show(this, message, "Windows Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private async void ResetIdentity_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                "Create a new identity key for this PC?\n\nEvery paired phone is removed and has to pair again. Only do this if you think this PC's key was exposed.",
                "Reset identity", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        await _app.Engine.ResetIdentityAsync();
        Load();
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenFolder(_app.Engine.DataDirectory);
}
