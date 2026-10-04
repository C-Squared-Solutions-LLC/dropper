using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dropper.Core.Crypto;
using Dropper.Core.Engine;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;

namespace Dropper.Tests;

/// <summary>Real engine on loopback vs. a fake phone speaking the wire protocol.</summary>
public class EndToEndTests
{
    [Fact]
    public async Task Pairing_then_text_and_files_flow_both_ways()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        Assert.Single(pc.Engine.GetDevices());

        var (conn, hello) = await phone.OpenSessionAsync();
        using (conn)
        {
            Assert.Equal("pc", hello.GetProperty("role").GetString());
            Assert.Equal("TEST-PC", hello.GetProperty("name").GetString());
            await TestEngine.WaitUntil(() => pc.Engine.GetDevices()[0].Connected);

            // PC -> phone: text
            var textItem = pc.Engine.QueueText("Hello from the PC 👋");
            var (offer, content) = await FakePhone.ReceiveItemAsync(conn);
            Assert.Equal("text", offer.GetProperty("kind").GetString());
            Assert.Equal("Hello from the PC 👋", System.Text.Encoding.UTF8.GetString(content));
            await TestEngine.WaitUntil(() => textItem.State == ItemState.Delivered);

            // PC -> phone: a 3 MB file (several DATA frames)
            var src = Path.Combine(pc.Root, "big.bin");
            Directory.CreateDirectory(pc.Root);
            var bytes = RandomNumberGenerator.GetBytes(3_000_000);
            await File.WriteAllBytesAsync(src, bytes);
            var fileItem = pc.Engine.QueueFiles(new[] { src }).Single();
            (offer, content) = await FakePhone.ReceiveItemAsync(conn);
            Assert.Equal("big.bin", offer.GetProperty("name").GetString());
            Assert.Equal(bytes, content);
            await TestEngine.WaitUntil(() => fileItem.State == ItemState.Delivered);

            // phone -> PC: file with a hostile name lands sanitized, intact, with Mark-of-the-Web
            var received = new List<ActivityItem>();
            pc.Engine.ItemReceived += received.Add;
            var payload = RandomNumberGenerator.GetBytes(1_234_567);
            var (rtype, reply) = await FakePhone.SendItemAsync(conn, "file", "../../evil‮gnp.exe", payload);
            Assert.Equal(FrameType.Result, rtype);
            Assert.True(reply.GetProperty("ok").GetBoolean());
            var got = await TestEngine.WaitFor(() => received.FirstOrDefault());
            Assert.Equal(pc.ReceiveDir, Path.GetDirectoryName(got.LocalPath));
            Assert.Equal("evilgnp.exe", Path.GetFileName(got.LocalPath));
            Assert.Equal(payload, await File.ReadAllBytesAsync(got.LocalPath!));
            Assert.Contains("ZoneId=3", await File.ReadAllTextAsync(got.LocalPath + ":Zone.Identifier"));
            Assert.Empty(Directory.GetFiles(pc.ReceiveDir, ".dropper-*"));

            // phone -> PC: text
            received.Clear();
            (rtype, reply) = await FakePhone.SendItemAsync(conn, "text", "", FakePhone.Utf8("https://example.com/x"));
            Assert.True(reply.GetProperty("ok").GetBoolean());
            var text = await TestEngine.WaitFor(() => received.FirstOrDefault());
            Assert.Equal("https://example.com/x", text.Text);
            Assert.True(text.IsLink);

            // keep-alive
            await conn.Writer.WriteAsync(FrameType.Ping, CancellationToken.None);
            var (ptype, _) = await FakePhone.ReadAsync(conn);
            Assert.Equal(FrameType.Pong, ptype);
        }
    }

    [Fact]
    public async Task Corrupted_content_is_discarded_and_duplicates_are_recognized()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var (conn, _) = await phone.OpenSessionAsync();
        using (conn)
        {
            var (type, reply) = await FakePhone.SendItemAsync(conn, "file", "bad.bin", RandomNumberGenerator.GetBytes(5000), corruptHash: true);
            Assert.Equal(FrameType.Result, type);
            Assert.False(reply.GetProperty("ok").GetBoolean());
            Assert.Equal("integrity", reply.GetProperty("error").GetString());
            Assert.False(Directory.Exists(pc.ReceiveDir) && Directory.EnumerateFiles(pc.ReceiveDir).Any());

            string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            (type, reply) = await FakePhone.SendItemAsync(conn, "file", "once.txt", FakePhone.Utf8("hi"), id);
            Assert.True(reply.GetProperty("ok").GetBoolean());
            (type, reply) = await FakePhone.SendItemAsync(conn, "file", "once.txt", FakePhone.Utf8("hi"), id);
            Assert.Equal(FrameType.Reject, type);
            Assert.Equal("duplicate", reply.GetProperty("error").GetString());
            Assert.Single(Directory.GetFiles(pc.ReceiveDir));
        }
    }

    [Fact]
    public async Task Outgoing_item_waits_for_phone_and_duplicate_reject_counts_as_delivered()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var item = pc.Engine.QueueText("queued while offline");
        Assert.Equal(ItemState.Queued, item.State);

        var (conn, _) = await phone.OpenSessionAsync();
        using (conn)
        {
            await FakePhone.ReceiveItemAsync(conn, acceptIt: false); // answers REJECT "duplicate"
            await TestEngine.WaitUntil(() => item.State == ItemState.Delivered);
        }
    }

    [Fact]
    public async Task Wrong_gate_key_gets_silence_not_tls()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, pc.Port);
        var net = tcp.GetStream();
        await net.WriteAsync(Preamble.Build(Wire.ModeSession, RandomNumberGenerator.GetBytes(32), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        var buf = new byte[16];
        using var t = new CancellationTokenSource(5000);
        int n = await net.ReadAsync(buf, t.Token);
        Assert.Equal(0, n); // closed without a single byte (no ServerHello, no certificate)
    }

    [Fact]
    public async Task Garbage_and_plain_tls_clients_get_silence()
    {
        await using var pc = await TestEngine.StartAsync();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, pc.Port);
        var net = tcp.GetStream();
        // A TLS ClientHello-looking start instead of a preamble.
        var junk = new byte[61];
        junk[0] = 0x16; junk[1] = 0x03; junk[2] = 0x01;
        await net.WriteAsync(junk);
        using var t = new CancellationTokenSource(5000);
        Assert.Equal(0, await net.ReadAsync(new byte[16], t.Token));
    }

    [Fact]
    public async Task Replayed_preamble_is_refused()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var preamble = Preamble.Build(Wire.ModeSession, Kdf.Hkdf32(phone.DeviceSecret!, Kdf.GateInfo), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        using (await phone.ConnectAsync(Wire.ModeSession, Array.Empty<byte>(), rawPreamble: preamble)) { }
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectAsync(Wire.ModeSession, Array.Empty<byte>(), rawPreamble: preamble);
        });
    }

    [Fact]
    public async Task Stale_timestamp_is_refused()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var old = Preamble.Build(Wire.ModeSession, Kdf.Hkdf32(phone.DeviceSecret!, Kdf.GateInfo),
            DateTimeOffset.UtcNow.AddMinutes(-11).ToUnixTimeMilliseconds());
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectAsync(Wire.ModeSession, Array.Empty<byte>(), rawPreamble: old);
        });
    }

    [Fact]
    public async Task Right_gate_key_but_wrong_tls_key_is_refused()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        using var impostor = new FakePhone(); // a different key pair
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectAsync(Wire.ModeSession, Kdf.Hkdf32(phone.DeviceSecret!, Kdf.GateInfo),
                clientCertOverride: impostor.Certificate);
            // If the handshake raced to completion on the client side, the server still drops it.
            await FakePhone.ReadAsync(c, 3000);
        });
    }

    [Fact]
    public async Task Phone_rejects_a_pc_with_a_different_key()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        // Pretend the QR had carried another PC's fingerprint: the phone's pin check must fail.
        var realFp = phone.PcFp!;
        typeof(FakePhone).GetProperty(nameof(FakePhone.PcFp))!.SetValue(phone, SHA256.HashData(new byte[] { 1 }));
        await Assert.ThrowsAsync<AuthenticationException>(async () =>
        {
            using var c = await phone.ConnectSessionAsync();
        });
        typeof(FakePhone).GetProperty(nameof(FakePhone.PcFp))!.SetValue(phone, realFp);
        using var ok = await phone.ConnectSessionAsync();
    }

    [Fact]
    public async Task Pairing_requires_open_window_valid_proof_and_approval()
    {
        await using var pc = await TestEngine.StartAsync();

        // Bad proof -> PAIR_FAIL bad_proof, and the window survives for the real phone.
        var ticket = pc.Engine.StartPairing();
        using (var attacker = new FakePhone())
        {
            var r = await attacker.PairAsync(ticket.Uri, corruptProof: true);
            Assert.False(r.Ok);
            Assert.Equal("bad_proof", r.Error);
        }

        // User rejects -> PAIR_FAIL rejected, and the window is now consumed.
        void Reject(PairingRequest r) => r.Reject();
        pc.Engine.PairingRequested += Reject;
        using (var phone = new FakePhone())
        {
            var r = await phone.PairAsync(ticket.Uri);
            Assert.False(r.Ok);
            Assert.Equal("rejected", r.Error);
        }
        pc.Engine.PairingRequested -= Reject;
        Assert.Empty(pc.Engine.GetDevices());

        // Same QR again: window is single-use -> silently refused at the gate.
        using (var late = new FakePhone())
            await Assert.ThrowsAnyAsync<Exception>(() => late.PairAsync(ticket.Uri));

        // Cancelled window -> refused.
        var t2 = pc.Engine.StartPairing();
        pc.Engine.CancelPairing();
        using (var p = new FakePhone())
            await Assert.ThrowsAnyAsync<Exception>(() => p.PairAsync(t2.Uri));
    }

    [Fact]
    public async Task Five_bad_proofs_close_the_window()
    {
        await using var pc = await TestEngine.StartAsync();
        var ticket = pc.Engine.StartPairing();
        for (int i = 0; i < Wire.MaxPairingFailures; i++)
        {
            using var attacker = new FakePhone();
            var r = await attacker.PairAsync(ticket.Uri, corruptProof: true);
            Assert.Equal("bad_proof", r.Error);
        }
        using var phone = new FakePhone();
        await Assert.ThrowsAnyAsync<Exception>(() => phone.PairAsync(ticket.Uri));
    }

    [Fact]
    public async Task Unpairing_sends_bye_and_locks_the_phone_out()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var (conn, _) = await phone.OpenSessionAsync();
        using (conn)
        {
            await TestEngine.WaitUntil(() => pc.Engine.GetDevices()[0].Connected);
            await pc.Engine.RemoveDeviceAsync(pc.Engine.GetDevices()[0].FpHex);
            var (type, body) = await FakePhone.ReadAsync(conn);
            Assert.Equal(FrameType.Bye, type);
            Assert.Contains("unpaired", System.Text.Encoding.UTF8.GetString(body));
        }
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectSessionAsync();
        });
    }

    [Fact]
    public async Task Phone_initiated_unpair_removes_the_device()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var (conn, _) = await phone.OpenSessionAsync();
        using (conn)
        {
            await TestEngine.WaitUntil(() => pc.Engine.GetDevices()[0].Connected);
            await conn.Writer.WriteAsync(FrameType.Bye, Messages.Bye("unpaired"), CancellationToken.None);
            await TestEngine.WaitUntil(() => pc.Engine.GetDevices().Count == 0);
        }
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectSessionAsync();
        });
    }

    [Fact]
    public async Task Discovery_answers_only_paired_devices()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var discKey = Kdf.Hkdf32(phone.DeviceSecret!, Kdf.DiscoveryInfo);

        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var nonce = RandomNumberGenerator.GetBytes(16);
        var req = DiscoveryPacket.BuildRequest(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), nonce, discKey);
        await udp.SendAsync(req, new IPEndPoint(IPAddress.Loopback, pc.DiscoveryPort));
        using (var t = new CancellationTokenSource(5000))
        {
            var res = await udp.ReceiveAsync(t.Token);
            Assert.True(DiscoveryPacket.TryParseResponse(res.Buffer, discKey, out var ip, out var port, out var echoed));
            Assert.Equal(IPAddress.Loopback, ip);
            Assert.Equal(pc.Port, port);
            Assert.Equal(nonce, echoed);
            Assert.True(res.Buffer.Length < req.Length); // no amplification
        }

        // Replay of the same request, and a request with an unknown key: silence.
        await udp.SendAsync(req, new IPEndPoint(IPAddress.Loopback, pc.DiscoveryPort));
        var stranger = DiscoveryPacket.BuildRequest(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32));
        await udp.SendAsync(stranger, new IPEndPoint(IPAddress.Loopback, pc.DiscoveryPort));
        using (var t = new CancellationTokenSource(1500))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await udp.ReceiveAsync(t.Token));
    }

    [Fact]
    public async Task Identity_survives_restart_and_pairing_persists()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var fp = pc.Engine.Identity.Fingerprint;
        var dataDir = pc.Engine.DataDirectory;

        // Same data dir + key name, second engine instance: must load the same key and device.
        await pc.Engine.DisposeAsync();
        var keyName = (string)typeof(TestEngine).GetField("_keyName", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(pc)!;
        await using var again = new DropperEngine(new EngineOptions
        {
            DataDirectory = dataDir,
            KeyName = keyName,
            AllowTpm = false,
            ListenOverride = [new Dropper.Core.Net.LanAddress(IPAddress.Loopback, 8, "lo", "lo")],
            PortOverride = pc.Port,
            DiscoveryPort = pc.DiscoveryPort,
            DiscoveryBindAddress = IPAddress.Loopback,
            ReceiveFolderOverride = pc.ReceiveDir,
        });
        await again.StartAsync();
        Assert.Equal(fp, again.Identity.Fingerprint);
        Assert.Single(again.GetDevices());
        var (conn, _) = await phone.OpenSessionAsync();
        conn.Dispose();
    }
}
