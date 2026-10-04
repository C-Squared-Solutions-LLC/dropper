using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Dropper.App.Services;

public sealed record IpcMessage(string Command, string[] Paths);

/// <summary>
/// One Dropper per Windows user. Later launches (Explorer "Send to", a second
/// double-click) hand their request to the running instance over a named pipe
/// that only this user's processes can open (PipeOptions.CurrentUserOnly).
/// </summary>
internal sealed class SingleInstance : IDisposable
{
    private const int MaxMessageBytes = 1 << 20;
    private readonly Mutex _mutex;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _cts = new();

    public SingleInstance(string variant = "")
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        string tag = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("Dropper|" + variant + "|" + sid)))[..16];
        _mutex = new Mutex(true, $"Local\\Dropper-{tag}", out bool created);
        IsPrimary = created;
        _pipeName = $"Dropper-{tag}";
    }

    public bool IsPrimary { get; }

    public bool SendToPrimary(IpcMessage message)
    {
        try
        {
            AllowSetForegroundWindow(-1); // let the running instance bring its window to the front
            using var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect(3000);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
            client.Write(bytes);
            client.Flush();
            return true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void Listen(Action<IpcMessage> onMessage) => _ = ListenLoopAsync(onMessage, _cts.Token);

    private async Task ListenLoopAsync(Action<IpcMessage> onMessage, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(_pipeName, PipeDirection.In, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(ct);
                using var buffer = new MemoryStream();
                var chunk = new byte[16 * 1024];
                int n;
                using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    t.CancelAfter(5000);
                    while ((n = await server.ReadAsync(chunk, t.Token)) > 0)
                    {
                        buffer.Write(chunk, 0, n);
                        if (buffer.Length > MaxMessageBytes) break;
                    }
                }
                if (buffer.Length is 0 or > MaxMessageBytes) continue;
                var msg = JsonSerializer.Deserialize<IpcMessage>(buffer.ToArray());
                if (msg is not null) onMessage(Sanitize(msg));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is IOException or JsonException or OperationCanceledException or UnauthorizedAccessException)
            {
                await Task.Delay(200, CancellationToken.None);
            }
        }
    }

    private static IpcMessage Sanitize(IpcMessage m) => new(
        m.Command is "show" or "send" or "pair" ? m.Command : "show",
        (m.Paths ?? Array.Empty<string>()).Where(p => !string.IsNullOrWhiteSpace(p) && Path.IsPathFullyQualified(p)).Take(1000).ToArray());

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(int processId);

    public void Dispose()
    {
        _cts.Cancel();
        if (IsPrimary)
        {
            try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }
        }
        _mutex.Dispose();
    }
}
