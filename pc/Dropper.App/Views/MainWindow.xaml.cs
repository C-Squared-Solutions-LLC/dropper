using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Dropper.App.Services;
using Dropper.Core.Engine;
using Dropper.Core.Storage;

namespace Dropper.App.Views;

public partial class MainWindow : Window
{
    private readonly App _app;
    private readonly ObservableCollection<ItemViewModel> _items = new();
    private readonly Dictionary<string, ItemViewModel> _byKey = new();
    private readonly DispatcherTimer _bannerTimer = new() { Interval = TimeSpan.FromSeconds(8) };
    private readonly DispatcherTimer _clockTimer = new() { Interval = TimeSpan.FromMinutes(1) };
    private HashSet<string> _connected = new();
    private string? _targetFp;

    internal MainWindow(App app)
    {
        _app = app;
        InitializeComponent();
        ThemeManager.Attach(this);
        ThemeManager.Changed += RefreshAll;
        if (DevMode.Enabled) Title = "Dropper (developer mode · loopback only)";
        ActivityList.ItemsSource = _items;
        _bannerTimer.Tick += (_, _) => HideBanner();
        _clockTimer.Tick += (_, _) => RefreshAll(); // "Yesterday", relative times
        _clockTimer.Start();
        AddHandler(PreviewDragEnterEvent, new DragEventHandler(Window_PreviewDragOver), true);
        AddHandler(PreviewDragOverEvent, new DragEventHandler(Window_PreviewDragOver), true);
        AddHandler(PreviewDropEvent, new DragEventHandler(Window_PreviewDrop), true);
        Closing += OnClosing;
        UpdateEmptyState();
    }

    // ------------------------------------------------------------------ engine → UI

    public void OnEngineStarted()
    {
        foreach (var item in _app.Engine.GetActivity().OrderByDescending(i => i.Created))
            Add(item, atTop: false);
        RefreshDevices();
        UpdateEmptyState();
    }

    public void OnItemAdded(ActivityItem item)
    {
        Add(item, atTop: true);
        UpdateEmptyState();
        ActivityList.ScrollIntoView(_items[0]);
    }

    public void OnItemChanged(ActivityItem item)
    {
        if (_byKey.TryGetValue(KeyOf(item), out var vm)) vm.Refresh();
        else OnItemAdded(item);
    }

    public void OnItemRemoved(ActivityItem item)
    {
        if (!_byKey.Remove(KeyOf(item), out var vm)) return;
        _items.Remove(vm);
        UpdateEmptyState();
    }

    private void Add(ActivityItem item, bool atTop)
    {
        if (_byKey.ContainsKey(KeyOf(item))) return;
        var vm = new ItemViewModel(item, fp => _connected.Contains(fp));
        _byKey[KeyOf(item)] = vm;
        if (atTop) _items.Insert(0, vm);
        else _items.Add(vm);
    }

    private static string KeyOf(ActivityItem i) => i.Direction + ":" + i.Id;

    private void RefreshAll()
    {
        foreach (var vm in _items) vm.Refresh();
    }

    private void UpdateEmptyState() =>
        EmptyState.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    public void RefreshDevices()
    {
        if (!_app.EngineReady) return;
        var engine = _app.Engine;
        var devices = engine.GetDevices();
        _connected = devices.Where(d => d.Connected).Select(d => d.FpHex).ToHashSet();
        if (_targetFp is not null && devices.All(d => d.FpHex != _targetFp)) _targetFp = null;

        string listening = engine.IsListening
            ? "Listening on " + string.Join(", ", engine.Lans.Select(l => $"{l.Address}:{engine.Port} ({l.InterfaceName})"))
            : engine.NetworkError ?? "Not listening";
        StatusText.ToolTip = listening;

        BuildDeviceChoices(devices);

        if (devices.Count == 0)
        {
            DeviceNameText.Text = "No phone paired yet";
            SetStatus(engine.NetworkError ?? "Pair your phone to start sending.", engine.NetworkError is null ? "NeutralDotBrush" : "DangerBrush");
            PairInlineButton.Visibility = Visibility.Visible;
            SecureBadge.Visibility = Visibility.Collapsed;
        }
        else
        {
            var target = CurrentTarget(devices)!;
            DeviceNameText.Text = target.Name;
            if (engine.NetworkError is { } error)
                SetStatus(error, "DangerBrush");
            else if (target.Connected)
                SetStatus($"Connected · {target.RemoteAddress}", "SuccessBrush");
            else
                SetStatus("Not connected · open Dropper on your phone. Anything you send waits here until it connects.", "NeutralDotBrush");
            PairInlineButton.Visibility = Visibility.Collapsed;
            SecureBadge.Visibility = Visibility.Visible;
        }
        RefreshAll();
    }

    private DeviceStatus? CurrentTarget(IReadOnlyList<DeviceStatus> devices) =>
        devices.FirstOrDefault(d => d.FpHex == _targetFp)
        ?? devices.FirstOrDefault(d => d.Connected)
        ?? devices.OrderByDescending(d => d.LastSeen ?? d.PairedAt).FirstOrDefault();

    private void BuildDeviceChoices(IReadOnlyList<DeviceStatus> devices)
    {
        DeviceChoices.Items.Clear();
        if (devices.Count < 2)
        {
            DeviceChoices.Visibility = Visibility.Collapsed;
            return;
        }
        var target = CurrentTarget(devices);
        foreach (var d in devices)
        {
            var rb = new RadioButton
            {
                Style = (Style)FindResource("ChoiceRadio"),
                Content = d.Name + (d.Connected ? "  ●" : ""),
                IsChecked = d.FpHex == target?.FpHex,
                GroupName = "target",
                Margin = new Thickness(0, 0, 8, 0),
                Padding = new Thickness(8, 4, 8, 4),
                Tag = d.FpHex,
            };
            rb.Checked += (s, _) =>
            {
                _targetFp = (string)((RadioButton)s).Tag;
                RefreshDevices();
            };
            DeviceChoices.Items.Add(rb);
        }
        DeviceChoices.Visibility = Visibility.Visible;
    }

    private void SetStatus(string text, string dotBrushKey)
    {
        StatusText.Text = text;
        StatusDot.Fill = (Brush)FindResource(dotBrushKey);
    }

    // ------------------------------------------------------------------ banner

    public void ShowBanner(string text, bool isError)
    {
        BannerText.Text = text;
        Banner.Background = (Brush)FindResource(isError ? "DangerSoftBrush" : "AccentSoftBrush");
        BannerGlyph.Text = isError ? "" : "";
        BannerGlyph.Foreground = (Brush)FindResource(isError ? "DangerBrush" : "AccentTextBrush");
        Banner.Visibility = Visibility.Visible;
        _bannerTimer.Stop();
        _bannerTimer.Start();
    }

    private void HideBanner()
    {
        _bannerTimer.Stop();
        Banner.Visibility = Visibility.Collapsed;
    }

    private void DismissBanner_Click(object sender, RoutedEventArgs e) => HideBanner();

    // ------------------------------------------------------------------ sending

    private bool Try(Action action)
    {
        if (!_app.EngineReady) return false;
        try
        {
            action();
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException)
        {
            ShowBanner(ex.Message, isError: true);
            return false;
        }
    }

    private void Queue(IEnumerable<string> paths) => Try(() => _app.Engine.QueueFiles(paths, _targetFp));

    public void ChooseFiles()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Multiselect = true, Title = "Choose files to send to your phone" };
        if (dlg.ShowDialog(this) == true) Queue(dlg.FileNames);
    }

    private void ChooseFiles_Click(object sender, RoutedEventArgs e) => ChooseFiles();

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Multiselect = true, Title = "Choose folders to send (they will be zipped)" };
        if (dlg.ShowDialog(this) == true) Queue(dlg.FolderNames);
    }

    private void SendClipboard_Click(object sender, RoutedEventArgs e) => _app.SendClipboard();

    private void SendText_Click(object sender, RoutedEventArgs e) => SendComposed();

    private void SendComposed()
    {
        string text = ComposeBox.Text;
        if (string.IsNullOrWhiteSpace(text)) return;
        if (Try(() => _app.Engine.QueueText(text, _targetFp))) ComposeBox.Clear();
    }

    private void Compose_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
        {
            e.Handled = true;
            SendComposed();
        }
    }

    private void Compose_TextChanged(object sender, TextChangedEventArgs e) =>
        SendTextButton.IsEnabled = !string.IsNullOrWhiteSpace(ComposeBox.Text);

    // ------------------------------------------------------------------ drag & drop

    private void SetDropHighlight(bool on)
    {
        DropZone.Background = (Brush)FindResource(on ? "DropZoneActiveBrush" : "DropZoneBrush");
        DropOutline.Stroke = (Brush)FindResource(on ? "AccentBrush" : "DropZoneBorderBrush");
        DropTitle.Text = on ? "Release to send to your phone" : "Drop files, folders or text here";
    }

    // Files are taken anywhere in the window (even over the text box).
    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        e.Effects = DragDropEffects.Copy;
        e.Handled = true;
        SetDropHighlight(true);
    }

    private void Window_PreviewDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        e.Handled = true;
        SetDropHighlight(false);
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0) Queue(paths);
    }

    // Text dropped on the text box goes into the box; anywhere else it is sent right away.
    private void Window_DragEnter(object sender, DragEventArgs e) => Window_DragOver(sender, e);

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        if (e.Handled) return;
        bool text = e.Data.GetDataPresent(DataFormats.UnicodeText) || e.Data.GetDataPresent(DataFormats.Text);
        e.Effects = text ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
        if (text) SetDropHighlight(true);
    }

    private void Window_DragLeave(object sender, DragEventArgs e) => SetDropHighlight(false);

    private void Window_Drop(object sender, DragEventArgs e)
    {
        SetDropHighlight(false);
        if (e.Handled) return;
        string? text = e.Data.GetData(DataFormats.UnicodeText) as string ?? e.Data.GetData(DataFormats.Text) as string;
        if (!string.IsNullOrWhiteSpace(text)) Try(() => _app.Engine.QueueText(text, _targetFp));
        e.Handled = true;
    }

    // ------------------------------------------------------------------ row actions

    private static ItemViewModel? Row(object sender) => (sender as FrameworkElement)?.DataContext as ItemViewModel;

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (Row(sender)?.Item.Text is { } text && ClipboardService.SetText(text))
            ShowBanner("Copied to the clipboard.", isError: false);
    }

    private void OpenLink_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenLink(Row(sender)?.Item.Text);

    private void OpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (Row(sender)?.Item.LocalPath is not { } path) return;
        if (!File.Exists(path))
        {
            ShowBanner("That file has been moved or deleted.", isError: true);
            return;
        }
        try { WindowsIntegration.OpenFile(path); }
        catch (System.ComponentModel.Win32Exception ex) { ShowBanner(ex.Message, isError: true); }
    }

    private void ShowInFolder_Click(object sender, RoutedEventArgs e)
    {
        if (Row(sender)?.Item.LocalPath is { } path) WindowsIntegration.ShowInFolder(path);
    }

    private void Retry_Click(object sender, RoutedEventArgs e)
    {
        if (Row(sender) is { } vm) _app.Engine.Retry(vm.Item.Id);
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (Row(sender) is { } vm) _app.Engine.RemoveItem(vm.Item.Id);
    }

    private void ClearFinished_Click(object sender, RoutedEventArgs e)
    {
        if (_app.EngineReady) _app.Engine.ClearFinished();
    }

    // ------------------------------------------------------------------ chrome

    private void Pair_Click(object sender, RoutedEventArgs e) => _app.ShowPairing();

    private void Settings_Click(object sender, RoutedEventArgs e) => _app.ShowSettings();

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_app.Quitting) return;
        if (!_app.EngineReady || _app.Engine.Config.CloseToTray)
        {
            e.Cancel = true;
            Hide();
            _app.OnMainHidden();
            return;
        }
        e.Cancel = true;
        _ = _app.QuitAsync();
    }
}
