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

/// <summary>Another PC answering "who's accepting a PC pairing?".</summary>
public sealed record DiscoveredPc(string Name, IPEndPoint Endpoint);

/// <summary>
/// PC-to-PC: the host side of pairing by code comparison, the joiner side, and the
/// outbound connections a joiner keeps to the PCs it paired with (docs/PROTOCOL.md §8.4).
/// </summary>
public sealed partial class DropperEngine
{
    // ================================================================ host: pairing window

    private DateTimeOffset _pcWindowUntil = DateTimeOffset.MinValue;
    private bool _pcWindowBusy;
    private int _pcWindowFailures;

    /// <summary>Lets another PC on the LAN find this one and pair, for 3 minutes. Returns the expiry.</summary>
    public DateTimeOffset StartPcPairing()
    {
        if (AdvertisedEndpoints().Count == 0) throw new InvalidOperationException(NetworkError ?? "Not connected to a local network.");
        DateTimeOffset until;
        lock (_gate)
        {
            _pcWindowUntil = until = Now + Wire.PairingWindow;
            _pcWindowBusy = false;
            _pcWindowFailures = 0;
        }
        Log("PC pairing window opened");
        return until;
    }

    public void CancelPcPairing()
    {
        lock (_gate) _pcWindowUntil = DateTimeOffset.MinValue;
    }

    /// <summary>Open and not already in the middle of a pairing attempt.</summary>
    internal bool PcPairingOpen(DateTimeOffset now)
    {
        lock (_gate) return now < _pcWindowUntil && !_pcWindowBusy;
    }

    private bool TryBeginPcPairing()
    {
        lock (_gate)
        {
            if (Now >= _pcWindowUntil || _pcWindowBusy) return false;
            _pcWindowBusy = true;
            return true;
        }
    }

    /// <summary>A successful pairing closes the window; failures leave it open, up to 5.</summary>
    private void EndPcPairing(bool success)
    {
        lock (_gate)
        {
            _pcWindowBusy = false;
            if (success || ++_pcWindowFailures >= Wire.MaxPairingFailures) _pcWindowUntil = DateTimeOffset.MinValue;
        }
    }

    /// <summary>UDP: answer a PC-pairing query, only while the window is open.</summary>
    internal byte[]? AnswerPcQuery(ReadOnlySpan<byte> packet)
    {
        if (!PcQueryPacket.TryParseRequest(packet, out var nonce)) return null;
        if (!PcPairingOpen(Now)) return null;
        return PcQueryPacket.BuildResponse(nonce, Port, PcName);
    }

    // ================================================================ host: the exchange

    /// <summary>
    /// Host side of §8.4, after TLS (keys not pinned yet). Commit to Na before seeing Nb,
    /// reveal it, derive the 6-digit code from both nonces and both TLS keys, then require
    /// approval on BOTH PCs before issuing the device secret.
    /// </summary>
    internal async Task HandlePcPairingAsync(SslStream ssl, X509Certificate2 peer, byte[] joinerFp, IPAddress ip, CancellationToken ct)
    {
        var reader = new FrameReader(ssl);
        using var writer = new FrameWriter(ssl);

        var (type, body) = await ReadWithinAsync(reader, Wire.PairRequestTimeout, ct).ConfigureAwait(false);
        if (type != FrameType.SasHello) throw new ProtocolException("expected SAS_HELLO");
        var (name, model) = Messages.ParseSasHello(body);
        if (!TryBeginPcPairing())
        {
            await writer.WriteAsync(FrameType.PairFail, Messages.PairFail("busy"), ct).ConfigureAwait(false);
            return;
        }

        bool success = false;
        using var watch = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            byte[] hostFp = Identity.Fingerprint;
            byte[] na = RandomNumberGenerator.GetBytes(32);
            await writer.WriteAsync(FrameType.SasCommit, Messages.Bytes("commit", Kdf.PcSasCommit(na, hostFp, joinerFp)), ct).ConfigureAwait(false);

            (type, body) = await ReadWithinAsync(reader, Wire.PairRequestTimeout, ct).ConfigureAwait(false);
            if (type != FrameType.SasNonce) throw new ProtocolException("expected SAS_NONCE");
            byte[] nb = Messages.ParseBytes32(body, "nonce");
            await writer.WriteAsync(FrameType.SasReveal, Messages.Bytes("nonce", na), ct).ConfigureAwait(false);

            string sas = Kdf.FormatSas(Kdf.PcSas(na, nb, hostFp, joinerFp));
            var request = new PairingRequest(name, string.IsNullOrEmpty(model) ? "Windows PC" : model, sas, Fingerprint.Display(joinerFp), ip, isPc: true);
            var remote = ReadConfirmAsync(reader, watch.Token);
            RaisePairingRequested(request);
            var timeout = Task.Delay(Wire.ApprovalTimeout, ct);

            // Wait for both answers, but stop at the first "no".
            while (true)
            {
                var pending = new List<Task> { timeout };
                if (!request.Decision.IsCompleted) pending.Add(request.Decision);
                if (!remote.IsCompleted) pending.Add(remote);
                if (pending.Count == 1) break;
                var done = await Task.WhenAny(pending).ConfigureAwait(false);
                if (done == timeout) break;
                if (request.Decision.IsCompleted && !request.Decision.Result) break;
                if (remote.IsCompleted && !remote.Result) break;
            }

            bool localOk = request.Decision.IsCompletedSuccessfully && request.Decision.Result;
            bool remoteOk = remote.IsCompletedSuccessfully && remote.Result;
            if (localOk && remoteOk)
            {
                byte[] secret = RandomNumberGenerator.GetBytes(32);
                AddDevice(peer, joinerFp, name, "Windows PC", secret, kind: "pc");
                await writer.WriteAsync(FrameType.PairOk, Messages.PairOk(PcName, secret), ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(secret);
                success = true;
                RaisePairingCompleted(new PairingOutcome(true, $"Paired with {name}.", name));
            }
            else
            {
                string reason = !request.Decision.IsCompleted || !remote.IsCompleted ? "timeout" : "rejected";
                request.Abandon();
                try { await writer.WriteAsync(FrameType.PairFail, Messages.PairFail(reason), ct).ConfigureAwait(false); }
                catch (IOException) { }
                string message = remote.IsCompleted && !remote.Result ? $"{name} declined, or the codes didn't match there."
                    : reason == "timeout" ? "Pairing timed out." : "Pairing rejected.";
                RaisePairingCompleted(new PairingOutcome(false, message, name));
            }
            try { await Task.Delay(250, ct).ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
        finally
        {
            watch.Cancel();
            EndPcPairing(success);
        }
    }

    private static async Task<bool> ReadConfirmAsync(FrameReader reader, CancellationToken ct)
    {
        try
        {
            var (type, body) = await reader.ReadAsync(ct).ConfigureAwait(false);
            return type == FrameType.SasConfirm && Messages.ParseSasConfirm(body);
        }
        catch (Exception)
        {
            return false; // hung up or misbehaved: treat as "no"
        }
    }

    // ================================================================ joiner

    /// <summary>Asks the LAN which PCs have their PC-pairing window open.</summary>
    public async Task<IReadOnlyList<DiscoveredPc>> FindPcsAsync(TimeSpan listen, CancellationToken ct = default)
    {
        var lans = Lans;
        var found = new Dictionary<string, DiscoveredPc>();
        if (lans.Count == 0) return Array.Empty<DiscoveredPc>();
        using var udp = new UdpClient(new IPEndPoint(LoopbackOnly(lans) ? IPAddress.Loopback : IPAddress.Any, 0)) { EnableBroadcast = true };
        var nonce = RandomNumberGenerator.GetBytes(16);
        var request = PcQueryPacket.BuildRequest(nonce);
        foreach (var target in BroadcastTargets(lans, null))
        {
            try { await udp.SendAsync(request, new IPEndPoint(target, _options.PeerDiscoveryPort), ct).ConfigureAwait(false); }
            catch (SocketException) { }
        }

        var deadline = DateTime.UtcNow + listen;
        while (DateTime.UtcNow < deadline)
        {
            UdpReceiveResult r;
            using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                t.CancelAfter(deadline - DateTime.UtcNow);
                try { r = await udp.ReceiveAsync(t.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { break; }
                catch (SocketException) { continue; }
            }
            if (!PcQueryPacket.TryParseResponse(r.Buffer, out var echoed, out int port, out string name)) continue;
            if (!Kdf.FixedTimeEquals(echoed, nonce)) continue;
            var ip = r.RemoteEndPoint.Address.MapToIPv4();
            if (FindLanFor(ip) is null) continue;
            if (port == Port && lans.Any(l => l.Address.Equals(ip))) continue; // ourselves
            var ep = new IPEndPoint(ip, port);
            found[ep.ToString()] = new DiscoveredPc(name.Length == 0 ? ip.ToString() : name, ep);
        }
        return found.Values.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    /// <summary>
    /// Joiner side of §8.4. <paramref name="confirm"/> shows the 6-digit code and returns the
    /// user's answer. On success the host is stored as an outbound peer and connected to.
    /// </summary>
    public async Task<PairingOutcome> PairWithPcAsync(IPEndPoint host, Func<string, Task<bool>> confirm, CancellationToken ct = default)
    {
        if (FindLanFor(host.Address) is null)
            return new PairingOutcome(false, "That PC isn't on this computer's local network.", null);

        using var tcp = new TcpClient();
        try
        {
            using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                t.CancelAfter(TimeSpan.FromSeconds(5));
                await tcp.ConnectAsync(host.Address, host.Port, t.Token).ConfigureAwait(false);
            }
            var net = tcp.GetStream();
            await net.WriteAsync(Preamble.Build(Wire.ModePcPairing, Kdf.PcPairingGateKey, Now.ToUnixTimeMilliseconds()), ct).ConfigureAwait(false);
            var (ssl, hostCert) = await ClientHandshakeAsync(net, pin: null, ct).ConfigureAwait(false);
            await using (ssl.ConfigureAwait(false))
            using (hostCert)
            {
                byte[] hostFp = Fingerprint.Of(hostCert);
                byte[] myFp = Identity.Fingerprint;
                if (Kdf.FixedTimeEquals(hostFp, myFp)) return new PairingOutcome(false, "That's this PC.", null);

                var reader = new FrameReader(ssl);
                using var writer = new FrameWriter(ssl);
                await writer.WriteAsync(FrameType.SasHello, Messages.SasHello(PcName), ct).ConfigureAwait(false);

                var (type, body) = await ReadWithinAsync(reader, Wire.PairRequestTimeout, ct).ConfigureAwait(false);
                if (type == FrameType.PairFail) return Failed(Messages.ParsePairFail(body));
                if (type != FrameType.SasCommit) throw new ProtocolException("expected SAS_COMMIT");
                byte[] commit = Messages.ParseBytes32(body, "commit");

                byte[] nb = RandomNumberGenerator.GetBytes(32);
                await writer.WriteAsync(FrameType.SasNonce, Messages.Bytes("nonce", nb), ct).ConfigureAwait(false);
                (type, body) = await ReadWithinAsync(reader, Wire.PairRequestTimeout, ct).ConfigureAwait(false);
                if (type != FrameType.SasReveal) throw new ProtocolException("expected SAS_REVEAL");
                byte[] na = Messages.ParseBytes32(body, "nonce");

                if (!Kdf.FixedTimeEquals(Kdf.PcSasCommit(na, hostFp, myFp), commit))
                    return new PairingOutcome(false, "The other PC's answer didn't match its commitment. Something may be interfering; pairing was stopped.", null);

                string sas = Kdf.FormatSas(Kdf.PcSas(na, nb, hostFp, myFp));
                bool ok = await confirm(sas).ConfigureAwait(false);
                await writer.WriteAsync(FrameType.SasConfirm, Messages.SasConfirm(ok), ct).ConfigureAwait(false);
                if (!ok) return new PairingOutcome(false, "Pairing rejected.", null);

                (type, body) = await ReadWithinAsync(reader, Wire.ApprovalTimeout + TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
                if (type == FrameType.PairFail) return Failed(Messages.ParsePairFail(body));
                if (type != FrameType.PairOk) throw new ProtocolException("expected PAIR_OK");
                var (hostName, secret) = Messages.ParsePairOk(body);

                var device = AddDevice(hostCert, hostFp, hostName, "Windows PC", secret,
                    kind: "pc", outbound: true, addresses: new[] { host.ToString() });
                CryptographicOperations.ZeroMemory(secret);
                StartOutbound(device);
                return new PairingOutcome(true, $"Paired with {hostName}.", hostName);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or ProtocolException
                                       or TimeoutException or OperationCanceledException)
        {
            return new PairingOutcome(false, "Couldn't pair: " + (ex is OperationCanceledException ? "cancelled." : ex.Message), null);
        }

        static PairingOutcome Failed(string error) => new(false, error switch
        {
            "busy" => "That PC is already pairing with someone else, or its pairing window closed.",
            "rejected" => "Pairing was rejected on the other PC.",
            "timeout" => "Nobody approved on the other PC in time.",
            _ => $"Pairing failed ({error}).",
        }, null);
    }

    // ================================================================ joiner: staying connected

    private readonly Dictionary<string, CancellationTokenSource> _outbound = new();
    private TaskCompletionSource _outboundKick = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static readonly int[] BackoffSeconds = [2, 5, 15, 30, 60, 120];

    private void StartOutboundLoops()
    {
        List<PairedDevice> outbound;
        lock (_gate) outbound = _devices.Values.Where(d => d.Record.Outbound).ToList();
        foreach (var d in outbound) StartOutbound(d);
    }

    internal void StartOutbound(PairedDevice device)
    {
        if (!device.Record.Outbound) return;
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (_outbound.ContainsKey(device.FpHex)) return;
            cts = new CancellationTokenSource();
            _outbound[device.FpHex] = cts;
        }
        _ = Task.Run(() => OutboundLoopAsync(device, cts.Token));
    }

    internal void StopOutbound(string fpHex)
    {
        CancellationTokenSource? cts;
        lock (_gate) _outbound.Remove(fpHex, out cts);
        try { cts?.Cancel(); } catch (ObjectDisposedException) { }
    }

    private void StopAllOutbound()
    {
        List<CancellationTokenSource> all;
        lock (_gate)
        {
            all = _outbound.Values.ToList();
            _outbound.Clear();
        }
        foreach (var c in all)
            try { c.Cancel(); } catch (ObjectDisposedException) { }
    }

    /// <summary>Retry outbound connections now (network changed) instead of waiting out the backoff.</summary>
    internal void KickOutbound()
    {
        TaskCompletionSource old;
        lock (_gate)
        {
            old = _outboundKick;
            _outboundKick = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        old.TrySetResult();
    }

    private Task OutboundKickTask
    {
        get { lock (_gate) return _outboundKick.Task; }
    }

    private async Task OutboundLoopAsync(PairedDevice device, CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested && IsPaired(device))
        {
            bool connected = false;
            try
            {
                foreach (var ep in CandidateEndpoints(device))
                {
                    var conn = await TryConnectOutboundAsync(device, ep, ct).ConfigureAwait(false);
                    if (conn is null) continue;
                    connected = true;
                    failures = 0;
                    await RunSessionAsync(conn.Value.Tcp, conn.Value.Ssl, device, ep, clientRole: true).ConfigureAwait(false);
                    break;
                }
                if (!connected && !ct.IsCancellationRequested && await DiscoverPeerAsync(device, ct).ConfigureAwait(false) is { } found)
                {
                    var conn = await TryConnectOutboundAsync(device, found, ct).ConfigureAwait(false);
                    if (conn is not null)
                    {
                        connected = true;
                        failures = 0;
                        RememberAddresses(device, new[] { found });
                        await RunSessionAsync(conn.Value.Tcp, conn.Value.Ssl, device, found, clientRole: true).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { Log($"Connection to '{device.Record.Name}' failed: {ex.GetType().Name}"); }

            if (ct.IsCancellationRequested) break;
            var wait = connected ? TimeSpan.FromSeconds(1) : TimeSpan.FromSeconds(BackoffSeconds[Math.Min(failures++, BackoffSeconds.Length - 1)]);
            try { await Task.WhenAny(Task.Delay(wait, ct), OutboundKickTask).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
    }

    private List<IPEndPoint> CandidateEndpoints(PairedDevice device)
    {
        List<string> stored;
        lock (_gate) stored = device.Record.Addresses.ToList();
        return stored
            .Select(s => IPEndPoint.TryParse(s, out var ep) ? ep : null)
            .Where(ep => ep is not null && FindLanFor(ep.Address) is not null)
            .Select(ep => ep!)
            .Take(4)
            .ToList();
    }

    private async Task<(TcpClient Tcp, SslStream Ssl)?> TryConnectOutboundAsync(PairedDevice device, IPEndPoint ep, CancellationToken ct)
    {
        var tcp = new TcpClient();
        try
        {
            using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                t.CancelAfter(TimeSpan.FromSeconds(3));
                await tcp.ConnectAsync(ep.Address, ep.Port, t.Token).ConfigureAwait(false);
            }
            tcp.NoDelay = true;
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            var net = tcp.GetStream();
            await net.WriteAsync(Preamble.Build(Wire.ModeSession, device.GateKey, Now.ToUnixTimeMilliseconds()), ct).ConfigureAwait(false);
            var (ssl, peer) = await ClientHandshakeAsync(net, device.Fp, ct).ConfigureAwait(false);
            peer.Dispose();
            return (tcp, ssl);
        }
        catch (AuthenticationException)
        {
            LogThrottled(ep.Address, $"Refused {ep}: it didn't present the key of '{device.Record.Name}'");
            tcp.Dispose();
            return null;
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            tcp.Dispose();
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            return null;
        }
    }

    /// <summary>
    /// TLS 1.3 client with this PC's identity as the client certificate. With a pin, only
    /// that exact key is accepted; without one (pairing) any P-256 key is accepted and
    /// returned, to be bound by the code comparison.
    /// </summary>
    private async Task<(SslStream Ssl, X509Certificate2 Peer)> ClientHandshakeAsync(Stream net, byte[]? pin, CancellationToken ct)
    {
        var mine = Identity.Certificate;
        var ssl = new SslStream(net, leaveInnerStreamOpen: false);
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = "dropper",
            EnabledSslProtocols = SslProtocols.Tls13,
            AllowTlsResume = false,
            ClientCertificates = new X509CertificateCollection { mine },
            LocalCertificateSelectionCallback = (_, _, _, _, _) => mine,
            CertificateChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
                TrustMode = X509ChainTrustMode.CustomRootTrust,
            },
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                if (cert is null) return false;
                using var c2 = new X509Certificate2(cert);
                return Fingerprint.IsP256(c2) && (pin is null || Kdf.FixedTimeEquals(Fingerprint.Of(c2), pin));
            },
        };
        try
        {
            using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
            t.CancelAfter(Wire.HandshakeTimeout);
            await ssl.AuthenticateAsClientAsync(options, t.Token).ConfigureAwait(false);
            var peer = ssl.RemoteCertificate is null ? null : new X509Certificate2(ssl.RemoteCertificate);
            if (ssl.SslProtocol != SslProtocols.Tls13 || peer is null
                || (pin is not null && !Kdf.FixedTimeEquals(Fingerprint.Of(peer), pin)))
            {
                peer?.Dispose();
                throw new AuthenticationException("unexpected peer key");
            }
            return (ssl, peer);
        }
        catch
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Authenticated discovery (§10) for an outbound peer whose address changed.</summary>
    private async Task<IPEndPoint?> DiscoverPeerAsync(PairedDevice device, CancellationToken ct)
    {
        var lans = Lans;
        if (lans.Count == 0) return null;
        var last = CandidateEndpoints(device).Select(e => e.Address).FirstOrDefault();
        using var udp = new UdpClient(new IPEndPoint(LoopbackOnly(lans) ? IPAddress.Loopback : IPAddress.Any, 0)) { EnableBroadcast = true };
        var outstanding = new List<byte[]>();
        for (int round = 0; round < 3 && !ct.IsCancellationRequested; round++)
        {
            var nonce = RandomNumberGenerator.GetBytes(16);
            outstanding.Add(nonce);
            var req = DiscoveryPacket.BuildRequest(Now.ToUnixTimeMilliseconds(), nonce, device.DiscKey);
            foreach (var target in BroadcastTargets(lans, last))
            {
                try { await udp.SendAsync(req, new IPEndPoint(target, _options.PeerDiscoveryPort), ct).ConfigureAwait(false); }
                catch (SocketException) { }
            }
            var deadline = DateTime.UtcNow.AddSeconds(1);
            while (DateTime.UtcNow < deadline)
            {
                UdpReceiveResult r;
                using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    t.CancelAfter(deadline - DateTime.UtcNow);
                    try { r = await udp.ReceiveAsync(t.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { break; }
                    catch (SocketException) { continue; }
                }
                if (!DiscoveryPacket.TryParseResponse(r.Buffer, device.DiscKey, out var ip, out int port, out var echoed)) continue;
                if (!outstanding.Any(n => Kdf.FixedTimeEquals(n, echoed))) continue;
                if (FindLanFor(ip) is null) continue;
                return new IPEndPoint(ip, port);
            }
        }
        return null;
    }

    /// <summary>Keeps the newest working addresses first, LAN-private only, at most 4.</summary>
    internal void RememberAddresses(PairedDevice device, IEnumerable<IPEndPoint> endpoints)
    {
        if (!device.Record.Outbound) return;
        lock (_gate)
        {
            var merged = endpoints.Where(e => LanInterfaces.IsPrivate(e.Address)).Select(e => e.ToString())
                .Concat(device.Record.Addresses).Distinct().Take(4).ToList();
            if (merged.SequenceEqual(device.Record.Addresses)) return;
            device.Record.Addresses = merged;
            _configStore.Save(_config);
        }
    }

    private static bool LoopbackOnly(IReadOnlyList<LanAddress> lans) => lans.All(l => IPAddress.IsLoopback(l.Address));

    /// <summary>Limited broadcast, each LAN's directed broadcast, and (optionally) a last known address.</summary>
    private static IEnumerable<IPAddress> BroadcastTargets(IReadOnlyList<LanAddress> lans, IPAddress? last)
    {
        var targets = new List<IPAddress>();
        if (LoopbackOnly(lans))
        {
            targets.Add(IPAddress.Loopback); // tests and developer mode
        }
        else
        {
            targets.Add(IPAddress.Broadcast);
            foreach (var l in lans)
            {
                uint mask = l.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - l.PrefixLength);
                uint bcast = LanAddress.ToUInt(l.Address) | ~mask;
                targets.Add(new IPAddress(new[] { (byte)(bcast >> 24), (byte)(bcast >> 16), (byte)(bcast >> 8), (byte)bcast }));
            }
        }
        if (last is not null) targets.Add(last);
        return targets.Distinct();
    }

    private static async Task<(FrameType Type, ReadOnlyMemory<byte> Body)> ReadWithinAsync(FrameReader reader, TimeSpan timeout, CancellationToken ct)
    {
        using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
        t.CancelAfter(timeout);
        try { return await reader.ReadAsync(t.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("the other PC stopped answering"); }
    }
}
