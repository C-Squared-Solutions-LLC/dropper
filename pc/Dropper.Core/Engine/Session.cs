using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;

namespace Dropper.Core.Engine;

/// <summary>
/// One authenticated connection (mode 1): a phone or PC that connected to us, or, in
/// the client role, another PC that this PC connected to. Runs three loops: a reader that
/// handles incoming frames, a sender that drains this device's outbox, and an
/// idle watchdog. Whichever ends first ends the session.
/// </summary>
internal sealed class Session
{
    private readonly DropperEngine _engine;
    private readonly TcpClient _tcp;
    private readonly SslStream _ssl;
    private readonly FrameReader _reader;
    private readonly FrameWriter _writer;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _outboxSignal = new(0, int.MaxValue);
    private readonly TaskCompletionSource _helloReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _replyGate = new();
    private long _lastReceived = Stopwatch.GetTimestamp();
    private long _lastPing = Stopwatch.GetTimestamp();
    private static readonly TimeSpan ClientPingInterval = TimeSpan.FromSeconds(45);
    private IncomingTransfer? _incoming;
    private string? _awaitingId;
    private TaskCompletionSource<ReplyMessage>? _awaitingReply;

    public Session(DropperEngine engine, TcpClient tcp, SslStream ssl, PairedDevice device, IPEndPoint remote, bool clientRole = false)
    {
        IsClient = clientRole;
        _engine = engine;
        _tcp = tcp;
        _ssl = ssl;
        _reader = new FrameReader(ssl);
        _writer = new FrameWriter(ssl);
        Device = device;
        Remote = remote;
    }

    public PairedDevice Device { get; }
    /// <summary>This PC opened the connection (to another PC), so it sends the keep-alive pings.</summary>
    public bool IsClient { get; }
    public IPEndPoint Remote { get; }
    public HelloMessage? PeerHello { get; private set; }
    public string EndReason { get; private set; } = "";

    public void SignalOutbox() => _outboxSignal.Release();

    public void Close(string reason)
    {
        if (EndReason.Length == 0) EndReason = reason;
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
    }

    /// <summary>Sends BYE and closes (used when the user unpairs this phone).</summary>
    public async Task SayByeAsync(string reason)
    {
        try
        {
            using var t = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await _writer.WriteAsync(FrameType.Bye, Messages.Bye(reason), t.Token).ConfigureAwait(false);
        }
        catch (Exception) { /* best effort */ }
        Close("bye: " + reason);
    }

    public async Task RunAsync()
    {
        var ct = _cts.Token;
        Task? reader = null, sender = null, watchdog = null;
        try
        {
            var hello = IsClient
                ? Messages.ClientPcHello(_engine.PcName)
                : Messages.PcHello(_engine.PcName, _engine.AdvertisedEndpoints().Select(e => e.ToString()));
            await _writer.WriteAsync(FrameType.Hello, hello, ct).ConfigureAwait(false);
            reader = ReadLoopAsync(ct);
            sender = SendLoopAsync(ct);
            watchdog = WatchdogAsync(ct);
            var first = await Task.WhenAny(reader, sender, watchdog).ConfigureAwait(false);
            if (EndReason.Length == 0)
                EndReason = first.Exception?.GetBaseException() is { } ex ? Describe(ex) : "closed";
        }
        catch (Exception ex)
        {
            if (EndReason.Length == 0) EndReason = Describe(ex);
        }
        finally
        {
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
            _ssl.Dispose();
            _tcp.Dispose();
            foreach (var t in new[] { reader, sender, watchdog })
            {
                if (t is null) continue;
                try { await t.ConfigureAwait(false); } catch (Exception) { /* already reported via EndReason */ }
            }
            if (_incoming is { } inc)
            {
                _incoming = null;
                inc.Dispose();
                _engine.FailItem(inc.Item, "Connection lost");
            }
            _writer.Dispose();
            _engine.OnSessionEnded(this);
            _cts.Dispose();
        }
    }

    private static string Describe(Exception ex) => ex switch
    {
        EndOfStreamException => "phone disconnected",
        IOException { InnerException: SocketException se } => $"network error ({se.SocketErrorCode})",
        IOException => "connection lost",
        ProtocolException pe => "protocol error: " + pe.Message,
        TimeoutException te => te.Message,
        OperationCanceledException => "closed",
        _ => ex.GetType().Name + ": " + ex.Message,
    };

    // ------------------------------------------------------------------ reader

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        using (var helloTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            helloTimeout.CancelAfter(Wire.HelloTimeout);
            (FrameType type, ReadOnlyMemory<byte> body) first;
            try { first = await _reader.ReadAsync(helloTimeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("no HELLO from phone"); }
            if (first.type != FrameType.Hello) throw new ProtocolException("expected HELLO");
            if (IsClient)
            {
                var (hello, addrs) = Messages.ParseServerHello(first.body);
                PeerHello = hello;
                _engine.RememberAddresses(Device, addrs.Prepend(Remote));
            }
            else
            {
                PeerHello = Messages.ParseClientHello(first.body);
            }
        }
        Touch();
        _engine.OnSessionReady(this);
        _helloReceived.TrySetResult();

        while (true)
        {
            var (type, body) = await _reader.ReadAsync(ct).ConfigureAwait(false);
            Touch();
            switch (type)
            {
                case FrameType.Ping:
                    await _writer.WriteAsync(FrameType.Pong, ct).ConfigureAwait(false);
                    break;
                case FrameType.Pong:
                    break;
                case FrameType.Bye:
                    string reason = Messages.ParseBye(body);
                    EndReason = "phone said bye: " + reason;
                    // Authenticated session, so only this phone can say it unpaired itself.
                    if (reason == "unpaired") _engine.ForgetDevice(Device.FpHex, "The phone unpaired itself");
                    return;
                case FrameType.Offer:
                    await OnOfferAsync(body, ct).ConfigureAwait(false);
                    break;
                case FrameType.Data:
                    await OnDataAsync(body, ct).ConfigureAwait(false);
                    break;
                case FrameType.End:
                    await OnEndAsync(body, ct).ConfigureAwait(false);
                    break;
                case FrameType.Cancel:
                    OnCancel(body);
                    break;
                case FrameType.Accept:
                case FrameType.Reject:
                case FrameType.Result:
                    OnReply(type, body);
                    break;
                default:
                    throw new ProtocolException($"unexpected {type} in a session");
            }
        }
    }

    private void Touch() => Interlocked.Exchange(ref _lastReceived, Stopwatch.GetTimestamp());

    private async Task OnOfferAsync(ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        if (_incoming is not null) throw new ProtocolException("OFFER while another item is in progress");
        var (offer, id) = Messages.ParseOffer(body);
        if (offer is null)
        {
            await _writer.WriteAsync(FrameType.Reject, Messages.Reject(id, "invalid"), ct).ConfigureAwait(false);
            return;
        }
        string? refusal = _engine.CheckIncoming(offer);
        if (refusal is not null)
        {
            await _writer.WriteAsync(FrameType.Reject, Messages.Reject(id, refusal), ct).ConfigureAwait(false);
            return;
        }
        var item = _engine.BeginReceive(offer, Device);
        try
        {
            _incoming = IncomingTransfer.Create(offer, item, _engine.ReceiveFolder);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _engine.FailItem(item, "Can't write to the receive folder");
            await _writer.WriteAsync(FrameType.Reject, Messages.Reject(id, "io"), ct).ConfigureAwait(false);
            return;
        }
        await _writer.WriteAsync(FrameType.Accept, Messages.IdOnly(id), ct).ConfigureAwait(false);
    }

    private async Task OnDataAsync(ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        var inc = _incoming ?? throw new ProtocolException("DATA outside a transfer");
        if (body.IsEmpty) throw new ProtocolException("empty DATA frame");
        await inc.WriteAsync(body, ct).ConfigureAwait(false);
        _engine.ReportProgress(inc.Item, inc.Received);
    }

    private async Task OnEndAsync(ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        var inc = _incoming ?? throw new ProtocolException("END outside a transfer");
        if (body.Length != 32) throw new ProtocolException("END must carry a 32-byte SHA-256");
        _incoming = null;
        string id = inc.Offer.Id;
        string? error = null;
        // Finish all local work (commit, or delete the partial file) before replying,
        // so the phone never hears "done" while a temp file still exists.
        using (inc)
        {
            if (inc.LocalError is not null)
            {
                _engine.FailItem(inc.Item, "Couldn't save: " + inc.LocalError);
                error = "io";
            }
            else if (!inc.Verify(body.Span))
            {
                _engine.FailItem(inc.Item, "Integrity check failed");
                error = "integrity";
            }
            else
            {
                try
                {
                    if (inc.Offer.Kind == ItemKind.File)
                    {
                        var (path, tagged) = inc.CommitFile(_engine.ReceiveFolder);
                        _engine.CompleteIncomingFile(inc.Item, path, tagged);
                    }
                    else
                        _engine.CompleteIncomingText(inc.Item, inc.CommitText());
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    _engine.FailItem(inc.Item, "Couldn't save: " + ex.Message);
                    error = "io";
                }
            }
        }
        await _writer.WriteAsync(FrameType.Result, Messages.Result(id, error is null, error), ct).ConfigureAwait(false);
    }

    private void OnCancel(ReadOnlyMemory<byte> body)
    {
        string id = Messages.ParseIdOnly(body);
        if (_incoming is not { } inc || inc.Offer.Id != id) return; // stale; nothing in flight
        _incoming = null;
        inc.Dispose();
        _engine.CancelIncoming(inc.Item);
    }

    private void OnReply(FrameType type, ReadOnlyMemory<byte> body)
    {
        var reply = Messages.ParseReply(type, body);
        TaskCompletionSource<ReplyMessage>? tcs;
        lock (_replyGate)
        {
            if (_awaitingId != reply.Id) throw new ProtocolException($"unexpected {type}");
            tcs = _awaitingReply;
        }
        tcs?.TrySetResult(reply);
    }

    // ------------------------------------------------------------------ sender

    private async Task SendLoopAsync(CancellationToken ct)
    {
        await _helloReceived.Task.WaitAsync(ct).ConfigureAwait(false);
        while (!ct.IsCancellationRequested)
        {
            var item = _engine.NextOutgoing(Device.FpHex);
            if (item is null)
            {
                await _outboxSignal.WaitAsync(ct).ConfigureAwait(false);
                continue;
            }
            await SendItemAsync(item, ct).ConfigureAwait(false);
        }
    }

    private async Task SendItemAsync(ActivityItem item, CancellationToken ct)
    {
        Stream source;
        try
        {
            if (item.Kind == ItemKind.Text)
                source = new MemoryStream(Encoding.UTF8.GetBytes(item.Text ?? ""), writable: false);
            else
                source = new FileStream(item.LocalPath!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                    1 << 16, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            _engine.FailItem(item, "Can't read the file: " + ex.Message);
            return;
        }

        await using (source.ConfigureAwait(false))
        {
            long size = source.Length;
            long limit = item.Kind == ItemKind.Text ? Wire.MaxTextBytes : Wire.MaxFileBytes;
            if (size > limit)
            {
                _engine.FailItem(item, "Too large");
                return;
            }
            _engine.BeginSend(item, size);

            var offer = new OfferMessage(item.Id, item.Kind,
                item.Kind == ItemKind.File ? item.Name : "",
                item.Kind == ItemKind.Text ? "text/plain" : item.Mime,
                size);
            var reply = await RequestAsync(FrameType.Offer, Messages.Offer(offer), item.Id, Wire.AcceptTimeout, ct).ConfigureAwait(false);
            if (reply.Type == FrameType.Reject)
            {
                if (reply.Error == "duplicate") _engine.CompleteOutgoing(item);
                else _engine.FailItem(item, RejectText(reply.Error));
                return;
            }
            if (reply.Type != FrameType.Accept) throw new ProtocolException("expected ACCEPT or REJECT");

            byte[] buffer = ArrayPool<byte>.Shared.Rent(Wire.SendChunk);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            try
            {
                long sent = 0;
                while (sent < size)
                {
                    int want = (int)Math.Min(Wire.SendChunk, size - sent);
                    int n;
                    try { n = await source.ReadAsync(buffer.AsMemory(0, want), ct).ConfigureAwait(false); }
                    catch (IOException) { n = 0; }
                    if (n <= 0)
                    {
                        await _writer.WriteAsync(FrameType.Cancel, Messages.IdOnly(item.Id), ct).ConfigureAwait(false);
                        _engine.FailItem(item, "The file changed or became unreadable while sending");
                        return;
                    }
                    hash.AppendData(buffer, 0, n);
                    await _writer.WriteAsync(FrameType.Data, buffer.AsMemory(0, n), ct).ConfigureAwait(false);
                    sent += n;
                    _engine.ReportProgress(item, sent);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            var result = await RequestAsync(FrameType.End, hash.GetHashAndReset(), item.Id, Wire.ResultTimeout, ct).ConfigureAwait(false);
            if (result.Type != FrameType.Result) throw new ProtocolException("expected RESULT");
            if (result.Ok) _engine.CompleteOutgoing(item);
            else _engine.RetryOrFail(item, result.Error == "integrity" ? "Integrity check failed on the phone" : "The phone couldn't save it");
        }
    }

    private static string RejectText(string? error) => error switch
    {
        "no_space" => "Not enough space on the phone",
        "too_large" => "Too large for the phone",
        "invalid" => "The phone rejected the item",
        "io" => "The phone couldn't save it",
        _ => "Rejected by the phone",
    };

    private async Task<ReplyMessage> RequestAsync(FrameType type, byte[] body, string id, TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<ReplyMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_replyGate)
        {
            _awaitingId = id;
            _awaitingReply = tcs;
        }
        try
        {
            await _writer.WriteAsync(type, body, ct).ConfigureAwait(false);
            try
            {
                return await tcs.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException($"no reply to {type} within {timeout.TotalSeconds:0} s");
            }
        }
        finally
        {
            lock (_replyGate)
            {
                _awaitingId = null;
                _awaitingReply = null;
            }
        }
    }

    // ------------------------------------------------------------------ watchdog

    private async Task WatchdogAsync(CancellationToken ct)
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            if (IsClient && Stopwatch.GetElapsedTime(_lastPing) >= ClientPingInterval)
            {
                _lastPing = Stopwatch.GetTimestamp();
                await _writer.WriteAsync(FrameType.Ping, ct).ConfigureAwait(false);
            }
            var idle = Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastReceived));
            if (idle > Wire.IdleTimeout) throw new TimeoutException($"no traffic from the phone for {idle.TotalSeconds:0} s");
        }
    }
}
