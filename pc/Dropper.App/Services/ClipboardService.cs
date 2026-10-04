using System.Collections.Specialized;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media.Imaging;

namespace Dropper.App.Services;

internal abstract record ClipboardContent
{
    public sealed record Files(IReadOnlyList<string> Paths) : ClipboardContent;
    public sealed record Image(BitmapSource Bitmap) : ClipboardContent;
    public sealed record Text(string Value) : ClipboardContent;
    public sealed record Empty : ClipboardContent;
}

/// <summary>Clipboard access with retries (another app may briefly hold the clipboard open).</summary>
internal static class ClipboardService
{
    public static ClipboardContent Read()
    {
        return Retry<ClipboardContent>(() =>
        {
            if (Clipboard.ContainsFileDropList())
            {
                StringCollection list = Clipboard.GetFileDropList();
                var paths = list.Cast<string>().Where(p => File.Exists(p) || Directory.Exists(p)).ToList();
                if (paths.Count > 0) return new ClipboardContent.Files(paths);
            }
            if (Clipboard.ContainsImage() && Clipboard.GetImage() is { } img)
                return new ClipboardContent.Image(img);
            if (Clipboard.ContainsText())
            {
                string t = Clipboard.GetText();
                if (!string.IsNullOrEmpty(t)) return new ClipboardContent.Text(t);
            }
            return new ClipboardContent.Empty();
        }) ?? new ClipboardContent.Empty();
    }

    /// <summary>
    /// Puts text on the clipboard but keeps it out of Windows Clipboard History and
    /// Cloud Clipboard sync: what arrives from the phone is often a code or password.
    /// </summary>
    public static bool SetText(string text) =>
        Retry(() =>
        {
            var data = new DataObject();
            data.SetData(DataFormats.UnicodeText, text);
            data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
            Clipboard.SetDataObject(data, copy: true);
            return true;
        });

    /// <summary>Saves a clipboard image as a PNG in <paramref name="folder"/> and returns its path.</summary>
    public static string SaveImage(BitmapSource image, string folder)
    {
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, $"clipboard-{DateTime.Now:yyyyMMdd-HHmmss}.png");
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(image));
        using var fs = File.Create(path);
        encoder.Save(fs);
        return path;
    }

    private static T? Retry<T>(Func<T> action)
    {
        for (int attempt = 0; ; attempt++)
        {
            try { return action(); }
            catch (COMException) when (attempt < 10) { Thread.Sleep(40); }
            catch (COMException) { return default; }
            catch (ExternalException) when (attempt < 10) { Thread.Sleep(40); }
            catch (ExternalException) { return default; }
        }
    }
}
