using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace Dropper.App.Services;

/// <summary>Follows the Windows light/dark app setting, including the title bar.</summary>
internal static class ThemeManager
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    public static bool IsDark { get; private set; }
    public static event Action? Changed;

    public static void Initialize(Application app)
    {
        Apply(app, ReadSystemDark());
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category != UserPreferenceCategory.General) return;
            bool dark = ReadSystemDark();
            if (dark != IsDark) app.Dispatcher.BeginInvoke(() => Apply(app, dark));
        };
    }

    public static void Attach(Window window) =>
        window.SourceInitialized += (_, _) => ApplyTitleBar(window);

    private static bool ReadSystemDark()
    {
        if (DevMode.Enabled && Environment.GetEnvironmentVariable("DROPPER_DEV_THEME") is "light" or "dark")
            return Environment.GetEnvironmentVariable("DROPPER_DEV_THEME") == "dark";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (System.Security.SecurityException) { return false; }
    }

    private static void Apply(Application app, bool dark)
    {
        IsDark = dark;
        var colors = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/Theme/Colors.{(dark ? "Dark" : "Light")}.xaml"),
        };
        var dicts = app.Resources.MergedDictionaries;
        int index = -1;
        for (int i = 0; i < dicts.Count; i++)
            if (dicts[i].Source?.OriginalString.Contains("/Colors.", StringComparison.Ordinal) == true
                || dicts[i].Source?.OriginalString.StartsWith("Theme/Colors.", StringComparison.Ordinal) == true)
                index = i;
        if (index >= 0) dicts[index] = colors;
        else dicts.Insert(0, colors);

        foreach (Window w in app.Windows) ApplyTitleBar(w);
        Changed?.Invoke();
    }

    private static void ApplyTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        int value = IsDark ? 1 : 0;
        _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref value, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
