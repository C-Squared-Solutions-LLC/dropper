using System.ComponentModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dropper.Core.Crypto;
using Dropper.Core.Net;
using Dropper.Core.Protocol;

namespace Dropper.Core.Engine;

/// <summary>
/// TCP listeners on the LAN addresses. Every connection must pass, in order:
/// LAN-subnet check → per-IP throttle → pre-auth slot → 61-byte HMAC preamble
/// (before a single TLS byte is parsed) → TLS 1.3 with a pinned client key.
/// </summary>
internal sealed class Server : IAsyncDisposable
{
    private readonly DropperEngine _engine;
    private readonly SslStreamCertificateContext _certContext;
    private readonly List<TcpListener> _listeners = new();
    private readonly List<Task> _acceptLoops = new();
    private readonly PreAuthSlots _slots = new(Wire.MaxPreAuthConnections, Wire.MaxPreAuthPerIp);
    private readonly IpThrottle _gateFailures = new(10, TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(5));
    private readonly CancellationTokenSource _cts = new();

    public Server(DropperEngine engine, X509Certificate2 serverCert)
    {
        _engine = engine;
        _certContext = SslStreamCertificateContext.Create(serverCert, null, offline: true);
    }

    /// <summary>Binds every address or none (throws <see cref="SocketException"/>).</summary>
    public void Start(IReadOnlyList<LanAddress> lans, int port)
    {
        try
        {
            foreach (var lan in lans)
            {
                // No SO_EXCLUSIVEADDRUSE: it blocks re-binding while old connections sit in TIME_WAIT,
                // and Windows' default socket security already stops other accounts taking the port.
                var listener = new TcpListener(lan.Address, port);
                listener.Start(64);
                _listeners.Add(listener);
                _acceptLoops.Add(AcceptLoopAsync(listener, lan, _cts.Token));
            }
        }
        catch
        {
            foreach (var l in _listeners) l.Stop();
            throw;
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener, LanAddress lan, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) when (ct.IsCancellationRequested) { break; }
            catch (SocketException ex)
            {
                _engine.Log($"Accept failed: {ex.SocketErrorCode}");
                continue;
            }
            _ = Task.Run(() => HandleAsync(client, lan, ct), CancellationToken.None);
        }
    }

    private async Task HandleAsync(TcpClient client, LanAddress lan, CancellationToken ct)
    {
        var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
        var ip = remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address;
        var now = _engine.Now;

        if (!lan.Contains(ip))
        {
            _engine.Log($"Refused {ip}: not on the local subnet {lan.Address}/{lan.PrefixLength}");
            client.Dispose();
            return;
        }
        if (_gateFailures.IsBlocked(ip, now))
        {
            client.Dispose();
            return;
        }

        var slot = _slots.Admit(ip, ct);
        bool handedOff = false;
        try
        {
            client.NoDelay = true;
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            var net = client.GetStream();

            // 1. Authenticated preamble. Nothing is ever sent back on failure.
            var preamble = new byte[Wire.PreambleLength];
            try
            {
                using var t = CancellationTokenSource.CreateLinkedTokenSource(slot.Token);
                t.CancelAfter(Wire.PreambleTimeout);
                await net.ReadExactlyAsync(preamble, t.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or EndOfStreamException or IOException)
            {
                // A silent or truncated greeting counts as a failed attempt (unless we evicted it ourselves).
                if (!slot.Evicted && !ct.IsCancellationRequested) RecordFailure(ip, "no valid greeting");
                return;
            }
            var gate = _engine.CheckGate(preamble, ip);
            if (!gate.Ok)
            {
                RecordFailure(ip, gate.Reason);
                return;
            }

            // 2. TLS 1.3, mutual authentication, keys pinned.
            var ssl = new SslStream(net, leaveInnerStreamOpen: false);
            var options = new SslServerAuthenticationOptions
            {
                ServerCertificateContext = _certContext,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                AllowTlsResume = false,
                AllowRenegotiation = false,
                // The client chain is built (then ignored: we pin the key) before our callback
                // runs. Never let that touch the network or the machine's trust store.
                CertificateChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    DisableCertificateDownloads = true,
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                },
                RemoteCertificateValidationCallback = (_, cert, _, _) => ValidateClient(cert, gate),
            };
            try
            {
                using var t = CancellationTokenSource.CreateLinkedTokenSource(slot.Token);
                t.CancelAfter(Wire.HandshakeTimeout);
                await ssl.AuthenticateAsServerAsync(options, t.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException or Win32Exception)
            {
                if (!slot.Evicted && !ct.IsCancellationRequested)
                    RecordFailure(ip, "TLS handshake failed: " + ex.GetBaseException().Message);
                await ssl.DisposeAsync().ConfigureAwait(false);
                return;
            }

            using var peer = ssl.RemoteCertificate is null ? null : new X509Certificate2(ssl.RemoteCertificate);
            if (ssl.SslProtocol != SslProtocols.Tls13 || peer is null)
            {
                await ssl.DisposeAsync().ConfigureAwait(false);
                return;
            }
            var peerFp = Fingerprint.Of(peer);
            slot.Complete();

            if (gate.Mode == Wire.ModePcPairing)
            {
                await using (ssl.ConfigureAwait(false))
                    await _engine.HandlePcPairingAsync(ssl, peer, peerFp, ip, ct).ConfigureAwait(false);
                return;
            }

            if (gate.Mode == Wire.ModePairing)
            {
                await using (ssl.ConfigureAwait(false))
                    await HandlePairingAsync(ssl, peer, peerFp, gate.Ticket!, ip, ct).ConfigureAwait(false);
                return;
            }

            // Re-check after the handshake: right key, and still paired right now.
            var device = gate.Device!;
            if (!Kdf.FixedTimeEquals(peerFp, device.Fp) || !_engine.IsPaired(device))
            {
                await ssl.DisposeAsync().ConfigureAwait(false);
                return;
            }
            handedOff = true;
            await _engine.RunSessionAsync(client, ssl, device, new IPEndPoint(ip, remote.Port)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Dropped mid-preamble or similar: nothing useful to report.
        }
        catch (Exception ex)
        {
            _engine.Log($"Connection from {ip} failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            slot.Dispose();
            if (!handedOff) client.Dispose();
        }
    }

    private void RecordFailure(IPAddress ip, string reason)
    {
        bool blocked = _gateFailures.Record(ip, _engine.Now);
        _engine.LogThrottled(ip, blocked
            ? $"Ignoring {ip} for 5 minutes after repeated failed connection attempts (last: {reason})"
            : $"Refused {ip}: {reason}");
    }

    private static bool ValidateClient(X509Certificate? cert, GateDecision gate)
    {
        if (cert is null) return false;
        using var c2 = new X509Certificate2(cert);
        if (!Fingerprint.IsP256(c2)) return false;
        // Pairing modes: bound afterwards by the QR proof (phone) or the code comparison (PC).
        if (gate.Mode != Wire.ModeSession) return true;
        return Kdf.FixedTimeEquals(Fingerprint.Of(c2), gate.Device!.Fp);
    }

    private async Task HandlePairingAsync(SslStream ssl, X509Certificate2 peer, byte[] phoneFp,
        PairingTicket ticket, IPAddress ip, CancellationToken ct)
    {
        var reader = new FrameReader(ssl);
        using var writer = new FrameWriter(ssl);

        PairRequestMessage request;
        using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            t.CancelAfter(Wire.PairRequestTimeout);
            var (type, body) = await reader.ReadAsync(t.Token).ConfigureAwait(false);
            if (type != FrameType.PairRequest) throw new ProtocolException("expected PAIR_REQUEST");
            request = Messages.ParsePairRequest(body);
        }

        var pcFp = _engine.Identity.Fingerprint;
        var expected = Kdf.PairProof(ticket.ProofKey, pcFp, phoneFp);
        string? failure = _engine.TryConsumeTicket(ticket, Kdf.FixedTimeEquals(expected, request.Proof));
        if (failure is not null)
        {
            await writer.WriteAsync(FrameType.PairFail, Messages.PairFail(failure), ct).ConfigureAwait(false);
            _engine.Log($"Pairing attempt from {ip} refused: {failure}");
            return;
        }

        string sas = Kdf.FormatSas(Kdf.Sas(ticket.SasKey, pcFp, phoneFp));
        var pending = new PairingRequest(request.Name, request.Model, sas, Fingerprint.Display(phoneFp), ip);

        // A read completes only if the phone hangs up (it sends nothing else while waiting).
        using var watchCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var hangup = reader.ReadAsync(watchCts.Token).AsTask();
        _engine.RaisePairingRequested(pending);

        var finished = await Task.WhenAny(pending.Decision, hangup, Task.Delay(Wire.ApprovalTimeout, ct)).ConfigureAwait(false);
        bool approved = finished == pending.Decision && pending.Decision.Result;

        if (finished == hangup)
        {
            pending.Abandon();
            _engine.RaisePairingCompleted(new PairingOutcome(false, "The phone cancelled pairing.", request.Name));
        }
        else if (approved)
        {
            byte[] deviceSecret = RandomNumberGenerator.GetBytes(32);
            _engine.AddDevice(peer, phoneFp, request.Name, request.Model, deviceSecret);
            await writer.WriteAsync(FrameType.PairOk, Messages.PairOk(_engine.PcName, deviceSecret), ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(deviceSecret);
            _engine.RaisePairingCompleted(new PairingOutcome(true, $"Paired with {request.Name}.", request.Name));
        }
        else
        {
            bool timedOut = finished != pending.Decision;
            pending.Abandon();
            await writer.WriteAsync(FrameType.PairFail, Messages.PairFail(timedOut ? "timeout" : "rejected"), ct).ConfigureAwait(false);
            _engine.RaisePairingCompleted(new PairingOutcome(false,
                timedOut ? "Pairing timed out." : "Pairing rejected.", request.Name));
        }

        // Give the phone a moment to read PAIR_OK/PAIR_FAIL before the caller closes the stream,
        // which also ends the pending hang-up read.
        try { await Task.Delay(250, ct).ConfigureAwait(false); } catch (OperationCanceledException) { }
        watchCts.Cancel();
        _ = hangup.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
    }

    public async ValueTask DisposeAsync()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        foreach (var l in _listeners) l.Stop();
        try { await Task.WhenAll(_acceptLoops).ConfigureAwait(false); } catch (Exception) { }
        _cts.Dispose();
    }
}
