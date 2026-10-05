using System.Net;
using System.Net.Sockets;
using Dropper.Core.Net;
using Dropper.Core.Protocol;

namespace Dropper.Core.Engine;

/// <summary>
/// Answers authenticated discovery requests (docs/PROTOCOL.md §10). Requests that
/// aren't from the LAN, aren't fresh, or don't carry a paired device's MAC get no
/// reply at all, so to everyone else the PC is silent on this port.
/// </summary>
internal sealed class DiscoveryResponder : IAsyncDisposable
{
    private const int SioUdpConnReset = -1744830452; // ignore ICMP port-unreachable resets on Windows

    private readonly DropperEngine _engine;
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private readonly ReplayCache _replay = new(Wire.ReplayWindow);
    private readonly IpThrottle _rate = new(20, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    private Task? _loop;

    public DiscoveryResponder(DropperEngine engine)
    {
        _engine = engine;
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
        try { _socket.IOControl(SioUdpConnReset, new byte[4], null); } catch (SocketException) { }
        // Report which adapter each datagram arrived on, so only the LAN adapter is answered.
        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
    }

    public void Start(IPAddress bindAddress, int port)
    {
        _socket.Bind(new IPEndPoint(bindAddress, port));
        _loop = LoopAsync(_cts.Token);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        var buffer = new byte[512];
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveMessageFromResult r;
            try
            {
                r = await _socket.ReceiveMessageFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { continue; }

            try
            {
                var reply = Answer(buffer.AsSpan(0, r.ReceivedBytes), (IPEndPoint)r.RemoteEndPoint, r.PacketInformation.Interface);
                if (reply is not null)
                    await _socket.SendToAsync(reply.Value.Packet, SocketFlags.None, reply.Value.To, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception)
            {
                // A hostile packet must never be able to stop discovery.
            }
        }
    }

    private (byte[] Packet, IPEndPoint To)? Answer(ReadOnlySpan<byte> packet, IPEndPoint from, int arrivedOnInterface)
    {
        var ip = from.Address.IsIPv4MappedToIPv6 ? from.Address.MapToIPv4() : from.Address;
        if (packet.Length is not (DiscoveryPacket.RequestLength or PcQueryPacket.RequestLength)) return null;
        var lan = _engine.FindLanFor(ip, arrivedOnInterface);
        if (lan is null) return null;
        if (packet.Length == PcQueryPacket.RequestLength)
        {
            // Unauthenticated by nature (the PCs share nothing yet), so only while this PC's
            // PC-pairing window is open, rate-limited, and never larger than the request.
            var answer = _engine.AnswerPcQuery(packet);
            if (answer is null || _rate.Record(ip, _engine.Now)) return null;
            return (answer, new IPEndPoint(ip, from.Port));
        }
        if (!DiscoveryPacket.TryParseRequest(packet, out long ts, out byte[] nonce)) return null;
        var now = _engine.Now;
        if (!Wire.IsFresh(ts, now)) return null;

        foreach (var device in _engine.PairedDevicesSnapshot())
        {
            if (!DiscoveryPacket.VerifyRequest(packet, device.DiscKey)) continue;
            if (!_replay.TryAdd(nonce, now)) return null;
            if (_rate.Record(ip, now)) return null;
            var response = DiscoveryPacket.BuildResponse(lan.Advertised, _engine.Port, nonce, device.DiscKey);
            return (response, new IPEndPoint(ip, from.Port));
        }
        return null;
    }

    public async ValueTask DisposeAsync()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        _socket.Dispose();
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch (Exception) { }
        }
        _cts.Dispose();
    }
}
