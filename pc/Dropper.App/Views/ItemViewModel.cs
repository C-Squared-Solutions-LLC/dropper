using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;

namespace Dropper.App.Views;

/// <summary>One row in the activity list.</summary>
public sealed class ItemViewModel(ActivityItem item, Func<string, bool> isConnected) : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public ActivityItem Item { get; } = item;
    public string Key => Item.Direction + ":" + Item.Id;
    private bool Incoming => Item.Direction == Direction.Incoming;

    public string Title => Item.Kind == ItemKind.Text
        ? Format.Snippet(Item.Text, Item.State == ItemState.Receiving ? "Receiving text…" : "(empty)")
        : Item.Name;

    public string? TitleTooltip => Item.Kind == ItemKind.Text ? Format.Tooltip(Item.Text) : Item.LocalPath ?? Item.Name;

    public string Glyph => Item.Kind == ItemKind.Text
        ? (Item.IsLink ? "" : "")
        : Format.FileGlyph(Item.Name);

    public string DirectionText => (Incoming ? "From " : "To ") + Item.DeviceName;

    public string Detail => (Item.Kind == ItemKind.Text ? (Item.IsLink ? "Link" : "Text") : Format.Size(Item.Size))
                            + " · " + Format.Time(Item.Created);

    public string StatusText => Item.State switch
    {
        ItemState.Preparing => "Preparing…",
        ItemState.Queued => isConnected(Item.DeviceFp) ? "Queued" : "Waiting for device",
        ItemState.Sending => $"Sending {Percent}%",
        ItemState.Receiving => $"Receiving {Percent}%",
        ItemState.Delivered => "Delivered",
        ItemState.Received => "Received",
        ItemState.Failed => "Failed",
        ItemState.Cancelled => "Cancelled",
        _ => "",
    };

    public Brush StatusBrush => Res(Item.State switch
    {
        ItemState.Delivered or ItemState.Received => "SuccessBrush",
        ItemState.Failed => "DangerBrush",
        ItemState.Sending or ItemState.Receiving => "AccentTextBrush",
        _ => "SubtleTextBrush",
    });

    public Brush IconBackground => Res(Incoming ? "SuccessSoftBrush" : "AccentSoftBrush");
    public Brush IconForeground => Res(Incoming ? "SuccessBrush" : "AccentTextBrush");

    private int Percent => Item.Size > 0 ? (int)Math.Min(100, Item.Transferred * 100 / Item.Size) : 0;
    public bool ShowProgress => Item.State is ItemState.Sending or ItemState.Receiving;
    public double Progress => Percent;

    public bool HasError => Item.State is ItemState.Failed or ItemState.Cancelled && !string.IsNullOrEmpty(Item.Error);
    public string? Error => Item.Error;

    public bool CanCopy => Item.Kind == ItemKind.Text && !string.IsNullOrEmpty(Item.Text) && !ShowProgress;
    public bool CanOpenLink => Item.IsLink && !ShowProgress;
    /// <summary>Only files Windows will treat as downloaded, and never types that run code.</summary>
    public bool CanOpenFile => Item.Kind == ItemKind.File && Incoming && Item.State == ItemState.Received
                               && Item.Tagged && !FileNames.IsExecutableType(Item.Name);

    public string? Note => Item.Kind == ItemKind.File && Incoming && Item.State == ItemState.Received
        ? !Item.Tagged
            ? "Saved without Windows' download protection (the folder doesn't support it), so Dropper won't open it for you."
            : FileNames.IsExecutableType(Item.Name)
                ? "Program or script: open it yourself from the folder only if you trust it."
                : null
        : null;

    public bool HasNote => Note is not null;
    public bool CanShowInFolder => Item.Kind == ItemKind.File && Item.LocalPath is not null && !Item.IsTemp
                                   && (!Incoming || Item.State == ItemState.Received);
    public bool CanRetry => !Incoming && Item.State is ItemState.Failed or ItemState.Cancelled;
    public bool CanRemove => Item.State is not (ItemState.Sending or ItemState.Receiving);

    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));

    private static Brush Res(string key) => (Brush)Application.Current.FindResource(key);
}

internal static class Format
{
    public static string Size(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1)
        {
            v /= 1024;
            u++;
        }
        return u == 0 ? $"{bytes} B" : v.ToString(v >= 100 ? "0" : "0.0", CultureInfo.CurrentCulture) + " " + units[u];
    }

    public static string Time(DateTimeOffset when)
    {
        var local = when.ToLocalTime();
        var today = DateTime.Today;
        string time = local.ToString("t", CultureInfo.CurrentCulture);
        if (local.Date == today) return time;
        if (local.Date == today.AddDays(-1)) return "Yesterday " + time;
        if (local.Date > today.AddDays(-7)) return local.ToString("ddd ", CultureInfo.CurrentCulture) + time;
        return local.ToString("MMM d, ", CultureInfo.CurrentCulture) + time;
    }

    public static string Snippet(string? text, string fallback)
    {
        if (string.IsNullOrWhiteSpace(text)) return fallback;
        var line = text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? fallback;
        line = Core.Protocol.TextSafety.CleanDisplayName(line, 160);
        bool more = text.Trim().Length > line.Length;
        return more && !line.EndsWith('…') ? line + " …" : line;
    }

    public static string? Tooltip(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        return text.Length > 600 ? text[..600] + "…" : text;
    }

    public static string FileGlyph(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" or ".png" or ".gif" or ".webp" or ".heic" or ".bmp" or ".svg" => "",
        ".mp4" or ".mov" or ".mkv" or ".webm" or ".avi" => "",
        ".mp3" or ".m4a" or ".wav" or ".ogg" or ".flac" => "",
        ".zip" or ".7z" or ".rar" or ".tar" or ".gz" => "",
        ".pdf" or ".doc" or ".docx" or ".txt" or ".md" or ".rtf" or ".odt" => "",
        _ => "",
    };
}
