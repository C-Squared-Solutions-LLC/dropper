using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;
using Microsoft.Win32;

namespace Dropper.App.Services;

/// <summary>Start-with-Windows, Explorer "Send to", firewall rules, and shell helpers.</summary>
internal static class WindowsIntegration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "Dropper";

    public static string ExePath => Environment.ProcessPath ?? throw new InvalidOperationException("Unknown executable path");

    private static string ExplorerPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");

    // ------------------------------------------------------------ startup

    public static bool IsStartupEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(RunValue) is string s && s.Contains(ExePath, StringComparison.OrdinalIgnoreCase);
    }

    public static void SetStartup(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled) key.SetValue(RunValue, $"\"{ExePath}\" --minimized");
        else key.DeleteValue(RunValue, throwOnMissingValue: false);
    }

    // ------------------------------------------------------------ Explorer "Send to"

    public static string SendToShortcutPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SendTo), "Dropper (phone).lnk");

    public static bool IsSendToEnabled() => File.Exists(SendToShortcutPath);

    public static void SetSendTo(bool enabled)
    {
        if (!enabled)
        {
            if (File.Exists(SendToShortcutPath)) File.Delete(SendToShortcutPath);
            return;
        }
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows Script Host is unavailable.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        try
        {
            dynamic link = shell.CreateShortcut(SendToShortcutPath);
            try
            {
                link.TargetPath = ExePath;
                link.Arguments = "--send";
                link.WorkingDirectory = Path.GetDirectoryName(ExePath);
                link.IconLocation = ExePath + ",0";
                link.Description = "Send to your phone with Dropper";
                link.Save();
            }
            finally { Marshal.FinalReleaseComObject(link); }
        }
        finally { Marshal.FinalReleaseComObject(shell); }
    }

    // ------------------------------------------------------------ firewall

    public static bool FirewallRulesPresent() => Firewall.RulesPresent(ExePath);

    /// <summary>
    /// Runs this same program elevated (one UAC prompt) with --configure-firewall, which
    /// writes the rules through the firewall COM API. No shell or command string involved.
    /// </summary>
    public static (bool Ok, string Message) ConfigureFirewall(int tcpPort)
    {
        try
        {
            var psi = new ProcessStartInfo(ExePath)
            {
                UseShellExecute = true,
                Verb = "runas",
                ArgumentList = { "--configure-firewall", tcpPort.ToString() },
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit(60_000);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (false, "Cancelled.");
        }
        catch (Win32Exception ex)
        {
            return (false, ex.Message);
        }
        return FirewallRulesPresent()
            ? (true, "Dropper is allowed on your local network only.")
            : (false, "The firewall rules could not be created.");
    }

    // ------------------------------------------------------------ shell

    /// <summary>Opens a received file, but never one that runs code (those are only shown in their folder).</summary>
    public static void OpenFile(string path)
    {
        if (FileNames.IsExecutableType(path))
        {
            ShowInFolder(path);
            return;
        }
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    public static void OpenFolder(string folder)
    {
        Directory.CreateDirectory(folder);
        Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
    }

    public static void ShowInFolder(string path)
    {
        if (File.Exists(path))
        {
            // Windows paths can't contain '"', so this documented form can't be broken out of.
            Process.Start(new ProcessStartInfo(ExplorerPath, $"/select,\"{path}\"") { UseShellExecute = false });
        }
        else if (Path.GetDirectoryName(path) is { } dir && Directory.Exists(dir))
        {
            OpenFolder(dir);
        }
    }

    /// <summary>Opens only plain http(s) links (never other URI schemes).</summary>
    public static void OpenLink(string? text)
    {
        if (!LinkDetector.IsSingleWebLink(text)) return;
        var uri = new Uri(text!.Trim());
        Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }
}
