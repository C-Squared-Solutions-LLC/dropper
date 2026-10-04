using System.Text;
using Dropper.Core.Protocol;

namespace Dropper.Core.Transfer;

/// <summary>Turns a peer-supplied file name into a safe local one (docs/PROTOCOL.md §11).</summary>
public static class FileNames
{
    private const int MaxLength = 150;

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
    };

    /// <summary>
    /// Extensions Windows acts on just by *displaying* a folder (remote icon paths in
    /// shortcuts and shell files can leak NTLM credentials), plus .pif. Neutralized with a suffix.
    /// </summary>
    private static readonly HashSet<string> ShellTriggerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".lnk", ".url", ".scf", ".library-ms", ".searchconnector-ms", ".desktop", ".website", ".pif",
    };

    /// <summary>Whole names Explorer or AutoPlay read on their own.</summary>
    private static readonly HashSet<string> ShellTriggerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "desktop.ini", "autorun.inf",
    };

    public static string Sanitize(string? name)
    {
        name ??= "";
        int cut = Math.Max(name.LastIndexOf('/'), name.LastIndexOf('\\'));
        if (cut >= 0) name = name[(cut + 1)..];

        var sb = new StringBuilder(name.Length);
        foreach (Rune r in name.EnumerateRunes())
        {
            if (TextSafety.IsInvisible(r) || r == Rune.ReplacementChar) continue;
            if (r.IsAscii && "<>:\"/\\|?*".Contains((char)r.Value)) continue;
            sb.Append(r.ToString());
        }
        string s = Tidy(sb.ToString());

        if (s.Length > MaxLength)
        {
            string ext = Path.GetExtension(s);
            if (ext.Length > 20) ext = "";
            string baseName = TextSafety.Truncate(s[..^ext.Length], MaxLength - ext.Length).TrimEnd('.', ' ');
            s = Tidy((baseName.Length == 0 ? "file" : baseName) + ext);
        }

        // Final-form checks, on exactly the name that will be written: truncation can
        // expose an inner extension (e.g. "x.lnk.<long junk>"), so these must come last.
        string stem = s.Split('.')[0].TrimEnd(' ');
        if (ReservedDeviceNames.Contains(stem)) s = "_" + s;
        if (ShellTriggerNames.Contains(s) || ShellTriggerExtensions.Contains(Path.GetExtension(s))) s += ".blocked";
        return s;
    }

    private static string Tidy(string s)
    {
        s = s.Trim().TrimEnd('.', ' ');
        return s.Length == 0 || s == "." || s == ".." ? "file" : s;
    }

    /// <summary>Types Windows runs (or interprets as code) when opened: never offered as "Open" in the UI.</summary>
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ws", ".hta", ".msi", ".msp", ".mst", ".msc", ".cpl", ".reg", ".jar", ".lnk", ".url",
        ".application", ".appref-ms", ".gadget", ".inf", ".chm", ".sct", ".xbap", ".settingcontent-ms",
        ".library-ms", ".searchconnector-ms", ".scf", ".theme", ".themepack", ".diagcab", ".appx", ".appxbundle",
        ".msix", ".msixbundle", ".iso", ".img", ".vhd", ".vhdx", ".blocked",
    };

    public static bool IsExecutableType(string name) => ExecutableExtensions.Contains(Path.GetExtension(name));

    /// <summary>Moves <paramref name="source"/> into <paramref name="directory"/> under a name that doesn't exist yet.</summary>
    public static string MoveToUnique(string source, string directory, string safeName)
    {
        string stem = Path.GetFileNameWithoutExtension(safeName);
        string ext = Path.GetExtension(safeName);
        for (int n = 0; n < 10_000; n++)
        {
            string candidate = Path.Combine(directory, n == 0 ? safeName : $"{stem} ({n}){ext}");
            if (File.Exists(candidate) || Directory.Exists(candidate)) continue;
            try
            {
                File.Move(source, candidate, overwrite: false);
                return candidate;
            }
            catch (IOException) when (File.Exists(candidate))
            {
                // Lost a race with another writer; try the next name.
            }
        }
        throw new IOException("Could not find a free file name.");
    }
}

/// <summary>Mark-of-the-Web: makes Windows treat received files as downloaded from the internet.</summary>
public static class Motw
{
    /// <summary>Returns false when the volume can't hold the tag (FAT/exFAT, some network shares).</summary>
    public static bool Apply(string path)
    {
        try
        {
            File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n", Encoding.ASCII);
            return File.Exists(path + ":Zone.Identifier");
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (NotSupportedException) { return false; }
    }
}

public static class Mime
{
    private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        [".jpg"] = "image/jpeg", [".jpeg"] = "image/jpeg", [".png"] = "image/png", [".gif"] = "image/gif",
        [".webp"] = "image/webp", [".heic"] = "image/heic", [".bmp"] = "image/bmp", [".svg"] = "image/svg+xml",
        [".mp4"] = "video/mp4", [".mov"] = "video/quicktime", [".mkv"] = "video/x-matroska", [".webm"] = "video/webm",
        [".mp3"] = "audio/mpeg", [".m4a"] = "audio/mp4", [".wav"] = "audio/wav", [".ogg"] = "audio/ogg", [".flac"] = "audio/flac",
        [".pdf"] = "application/pdf", [".zip"] = "application/zip", [".7z"] = "application/x-7z-compressed",
        [".txt"] = "text/plain", [".csv"] = "text/csv", [".json"] = "application/json", [".html"] = "text/html",
        [".doc"] = "application/msword", [".docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        [".xls"] = "application/vnd.ms-excel", [".xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        [".ppt"] = "application/vnd.ms-powerpoint", [".pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        [".apk"] = "application/vnd.android.package-archive",
    };

    public static string FromName(string name) =>
        Map.TryGetValue(Path.GetExtension(name), out var m) ? m : "application/octet-stream";
}
