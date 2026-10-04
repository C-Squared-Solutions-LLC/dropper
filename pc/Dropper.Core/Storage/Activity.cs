using System.Text.Json;
using System.Text.Json.Serialization;
using Dropper.Core.Crypto;
using Dropper.Core.Protocol;

namespace Dropper.Core.Storage;

public enum Direction { Outgoing, Incoming }

public enum ItemState { Preparing, Queued, Sending, Receiving, Delivered, Received, Failed, Cancelled }

/// <summary>One sent or received item: both the outbox and the history.</summary>
public sealed class ActivityItem
{
    public string Id { get; set; } = "";
    public Direction Direction { get; set; }
    [JsonConverter(typeof(JsonStringEnumConverter<ItemKind>))]
    public ItemKind Kind { get; set; }
    public string Name { get; set; } = "";
    public string? Text { get; set; }
    public string? LocalPath { get; set; }
    public long Size { get; set; }
    public string Mime { get; set; } = "";
    public string DeviceFp { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public DateTimeOffset Created { get; set; }
    [JsonConverter(typeof(JsonStringEnumConverter<ItemState>))]
    public ItemState State { get; set; }
    public int Attempts { get; set; }
    public string? Error { get; set; }
    /// <summary>The outgoing file is a temp file Dropper made (zip, clipboard image): delete it once delivered.</summary>
    public bool IsTemp { get; set; }
    /// <summary>A received file carries Mark-of-the-Web (Windows treats it as downloaded).</summary>
    public bool Tagged { get; set; }

    [JsonIgnore] public long Transferred { get; set; }

    [JsonIgnore]
    public bool IsPending => State is ItemState.Preparing or ItemState.Queued or ItemState.Sending or ItemState.Receiving;

    [JsonIgnore]
    public bool IsLink => Kind == ItemKind.Text && LinkDetector.IsSingleWebLink(Text);
}

public static class LinkDetector
{
    /// <summary>True only when the whole trimmed text is one http(s) URL (docs/PROTOCOL.md §11).</summary>
    public static bool IsSingleWebLink(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string t = text.Trim();
        if (t.Length > 4096 || t.Any(char.IsWhiteSpace)) return false;
        return Uri.TryCreate(t, UriKind.Absolute, out var u)
            && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
            && !string.IsNullOrEmpty(u.Host);
    }
}

/// <summary>
/// Thread-safe list of <see cref="ActivityItem"/>s, persisted DPAPI-encrypted
/// (sent and received text is stored there). Keeps all pending items plus the
/// most recent finished ones.
/// </summary>
public sealed class ActivityStore
{
    private const int MaxFinished = 200;
    private readonly string _path;
    private readonly List<ActivityItem> _items = new();
    private readonly object _gate = new();
    private readonly Timer _saveTimer;
    private int _dirty;

    public ActivityStore(string path)
    {
        _path = path;
        _saveTimer = new Timer(_ => FlushIfDirty(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public void Load(Action<string> log)
    {
        if (!File.Exists(_path)) return;
        try
        {
            var json = Dpapi.Unprotect(File.ReadAllBytes(_path));
            var items = JsonSerializer.Deserialize(json, StorageJson.Default.ListActivityItem) ?? new();
            foreach (var i in items)
            {
                // Anything mid-flight when we last exited: outgoing goes back to the
                // queue, incoming partials were discarded.
                if (i.State is ItemState.Sending or ItemState.Preparing) i.State = ItemState.Queued;
                if (i.State == ItemState.Receiving) { i.State = ItemState.Failed; i.Error = "Interrupted"; }
            }
            lock (_gate) _items.AddRange(items.Where(i => Messages.IsValidId(i.Id)));
        }
        catch (Exception ex) when (ex is JsonException or System.Security.Cryptography.CryptographicException or IOException)
        {
            log($"Activity history unreadable, starting fresh ({ex.GetType().Name})");
        }
    }

    public List<ActivityItem> Snapshot()
    {
        lock (_gate) return _items.ToList();
    }

    public void Add(ActivityItem item)
    {
        lock (_gate) _items.Add(item);
        MarkDirty();
    }

    public bool Remove(string id)
    {
        bool removed;
        lock (_gate) removed = _items.RemoveAll(i => i.Id == id) > 0;
        if (removed) MarkDirty();
        return removed;
    }

    public ActivityItem? Find(string id)
    {
        lock (_gate) return _items.FirstOrDefault(i => i.Id == id);
    }

    /// <summary>Oldest queued outgoing item for a device.</summary>
    public ActivityItem? NextQueued(string deviceFp)
    {
        lock (_gate)
            return _items.FirstOrDefault(i =>
                i.Direction == Direction.Outgoing && i.State == ItemState.Queued && i.DeviceFp == deviceFp);
    }

    public List<ActivityItem> Where(Func<ActivityItem, bool> predicate)
    {
        lock (_gate) return _items.Where(predicate).ToList();
    }

    /// <summary>Mutates an item under the store lock and schedules a save.</summary>
    public void Update(ActivityItem item, Action<ActivityItem> change)
    {
        lock (_gate) change(item);
        MarkDirty();
    }

    public void MarkDirty()
    {
        Interlocked.Exchange(ref _dirty, 1);
        _saveTimer.Change(1000, Timeout.Infinite);
    }

    public void FlushIfDirty()
    {
        if (Interlocked.Exchange(ref _dirty, 0) == 0) return;
        List<ActivityItem> copy;
        lock (_gate)
        {
            var finished = _items.Where(i => !i.IsPending).OrderByDescending(i => i.Created).Skip(MaxFinished).ToHashSet();
            if (finished.Count > 0) _items.RemoveAll(finished.Contains);
            copy = _items.ToList();
        }
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(copy, StorageJson.Default.ListActivityItem);
            AtomicFile.WriteAllBytes(_path, Dpapi.Protect(json));
        }
        catch (IOException)
        {
            Interlocked.Exchange(ref _dirty, 1); // retry on the next change
        }
    }
}
