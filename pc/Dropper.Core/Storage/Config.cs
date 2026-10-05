using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dropper.Core.Protocol;

namespace Dropper.Core.Storage;

public sealed class DeviceRecord
{
    public string Fp { get; set; } = "";              // lowercase hex SHA-256(SPKI)
    public string CertDer { get; set; } = "";         // base64
    public string Name { get; set; } = "";
    public string Model { get; set; } = "";
    public string SecretProtected { get; set; } = ""; // base64(DPAPI(device_secret))
    public DateTimeOffset PairedAt { get; set; }
    public DateTimeOffset? LastSeen { get; set; }
    /// <summary>"phone" or "pc".</summary>
    public string Kind { get; set; } = "phone";
    /// <summary>True when THIS PC connects to that peer (another PC we paired with as the joiner).</summary>
    public bool Outbound { get; set; }
    /// <summary>Last known "ip:port" list for an outbound peer.</summary>
    public List<string> Addresses { get; set; } = new();
}

public sealed class AppConfig
{
    public int Version { get; set; } = 1;
    public int Port { get; set; } = Wire.DefaultPort;
    public string? ReceiveFolder { get; set; }
    public bool AutoCopyText { get; set; } = true;
    public bool CloseToTray { get; set; } = true;
    public bool NotifyOnReceive { get; set; } = true;
    public string? InterfaceOverride { get; set; }
    public List<DeviceRecord> Devices { get; set; } = new();
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AppConfig))]
[JsonSerializable(typeof(List<ActivityItem>))]
internal partial class StorageJson : JsonSerializerContext;

/// <summary>Atomic JSON persistence for <see cref="AppConfig"/>.</summary>
public sealed class ConfigStore(string path)
{
    public AppConfig Load()
    {
        if (!File.Exists(path)) return new AppConfig();
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), StorageJson.Default.AppConfig) ?? new AppConfig();
        }
        catch (JsonException)
        {
            // Keep the unreadable file for inspection rather than silently losing pairings.
            File.Copy(path, path + ".corrupt-" + DateTime.Now.ToString("yyyyMMddHHmmss"), overwrite: true);
            return new AppConfig();
        }
    }

    public void Save(AppConfig config) =>
        AtomicFile.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(config, StorageJson.Default.AppConfig));
}

public static class AtomicFile
{
    public static void WriteAllBytes(string path, byte[] data)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(data);
            fs.Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: true);
    }
}

public static class KnownFolders
{
    private static readonly Guid Downloads = new("374DE290-123F-4565-9164-39C4925E467B");

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath(in Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

    public static string GetDownloads()
    {
        try
        {
            if (SHGetKnownFolderPath(Downloads, 0, IntPtr.Zero, out var p) == 0)
            {
                try { return Marshal.PtrToStringUni(p)!; }
                finally { Marshal.FreeCoTaskMem(p); }
            }
        }
        catch (EntryPointNotFoundException) { }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    }
}
