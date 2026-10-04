using System.Windows;
using WinForms = System.Windows.Forms;

namespace Dropper.App.Services;

/// <summary>The notification-area icon, its menu, and balloon notifications.</summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly WinForms.NotifyIcon _icon;
    private Action? _balloonClick;

    public TrayIcon(Action open, Action sendClipboard, Action sendFiles, Action pair, Action settings, Action quit)
    {
        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/Dropper.ico"))!.Stream;
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Open Dropper", null, (_, _) => open());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Send clipboard to phone", null, (_, _) => sendClipboard());
        menu.Items.Add("Send files…", null, (_, _) => sendFiles());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Pair a phone…", null, (_, _) => pair());
        menu.Items.Add("Settings", null, (_, _) => settings());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Quit Dropper", null, (_, _) => quit());
        ((WinForms.ToolStripMenuItem)menu.Items[0]).Font = new System.Drawing.Font(menu.Font, System.Drawing.FontStyle.Bold);

        _icon = new WinForms.NotifyIcon
        {
            Icon = new System.Drawing.Icon(stream, WinForms.SystemInformation.SmallIconSize),
            Text = "Dropper",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Left) open();
        };
        _icon.BalloonTipClicked += (_, _) => _balloonClick?.Invoke();
    }

    public void Notify(string title, string text, Action? onClick)
    {
        _balloonClick = onClick;
        _icon.ShowBalloonTip(5000, title, string.IsNullOrEmpty(text) ? " " : text, WinForms.ToolTipIcon.None);
    }

    public void SetTooltip(string text) => _icon.Text = text.Length > 63 ? text[..63] : text;

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
