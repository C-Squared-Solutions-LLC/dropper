using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Dropper.Core.Crypto;
using Dropper.Core.Net;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;

namespace Dropper.Tests;

/// <summary>Regression tests for the independent security review's findings.</summary>
public class ReviewFindingsTests
{
    // Finding 1: shell-trigger names must be caught on the FINAL (truncated) name.
    [Theory]
    [InlineData(".lnk")]
    [InlineData(".url")]
    [InlineData(".scf")]
    [InlineData(".library-ms")]
    [InlineData(".searchconnector-ms")]
    [InlineData(".website")]
    public void Truncation_cannot_expose_a_shell_trigger_extension(string ext)
    {
        // Try every padding so the cut lands exactly after the dangerous extension at least once.
        for (int pad = 120; pad <= 150; pad++)
        {
            var name = new string('x', pad) + ext + "." + new string('a', 25);
            var safe = FileNames.Sanitize(name);
            Assert.NotEqual(ext, Path.GetExtension(safe), StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Reviewer_proof_of_concept_is_blocked()
    {
        var safe = FileNames.Sanitize(new string('x', 145) + ".lnk." + new string('a', 25));
        Assert.EndsWith(".lnk.blocked", safe);
    }

    [Theory]
    [InlineData("desktop.ini", "desktop.ini.blocked")]
    [InlineData("AUTORUN.INF", "AUTORUN.INF.blocked")]
    [InlineData("setup.pif", "setup.pif.blocked")]
    [InlineData("notes.ini", "notes.ini")]
    public void Shell_trigger_names_are_neutralized(string input, string expected) =>
        Assert.Equal(expected, FileNames.Sanitize(input));

    [Theory]
    [InlineData("a­b؜c᠎d￹e.txt", "abcde.txt")] // soft hyphen, Arabic mark, Mongolian separator, annotation anchor
    [InlineData("ㅤname.txt", "name.txt")]                       // Hangul filler
    [InlineData("pay\U000E0041\U000E0042.pdf", "pay.pdf")]           // Unicode tag characters
    [InlineData("in⁦voice⁩.pdf", "invoice.pdf")]           // bidi isolates
    public void Every_invisible_code_point_is_stripped_from_names(string input, string expected) =>
        Assert.Equal(expected, FileNames.Sanitize(input));

    [Fact]
    public void Display_names_drop_invisible_code_points_too() =>
        Assert.Equal("Phone", TextSafety.CleanDisplayName("P­h\U000E0020oㅤne", 64));

    [Theory]
    [InlineData("tool.exe", true)]
    [InlineData("script.PS1", true)]
    [InlineData("x.lnk.blocked", true)]
    [InlineData("photo.jpg", false)]
    [InlineData("report.pdf", false)]
    public void Executable_types_are_recognized(string name, bool expected) =>
        Assert.Equal(expected, FileNames.IsExecutableType(name));

    // Finding 3: hostile timestamps must not overflow.
    [Theory]
    [InlineData(long.MinValue)]
    [InlineData(long.MaxValue)]
    [InlineData(0L)]
    public void Freshness_check_never_overflows(long ts)
    {
        var now = DateTimeOffset.UtcNow;
        Assert.False(Wire.IsFresh(ts, now));
        Assert.False(Wire.IsFresh(now.ToUnixTimeMilliseconds() + long.MinValue, now));
        Assert.True(Wire.IsFresh(now.ToUnixTimeMilliseconds() - 599_000, now));
    }

    [Fact]
    public async Task Discovery_survives_an_overflow_packet()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var discKey = Kdf.Hkdf32(phone.DeviceSecret!, Kdf.DiscoveryInfo);
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var target = new IPEndPoint(IPAddress.Loopback, pc.DiscoveryPort);

        long evil = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + long.MinValue;
        for (int i = -3; i <= 3; i++)
            await udp.SendAsync(DiscoveryPacket.BuildRequest(evil + i, RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32)), target);

        var nonce = RandomNumberGenerator.GetBytes(16);
        await udp.SendAsync(DiscoveryPacket.BuildRequest(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), nonce, discKey), target);
        using var t = new CancellationTokenSource(5000);
        var res = await udp.ReceiveAsync(t.Token);
        Assert.True(DiscoveryPacket.TryParseResponse(res.Buffer, discKey, out _, out _, out var echoed));
        Assert.Equal(nonce, echoed);
    }

    [Fact]
    public async Task Gate_refuses_an_overflow_timestamp_cleanly()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        long evil = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + long.MinValue;
        var pre = Preamble.Build(Wire.ModeSession, evil, RandomNumberGenerator.GetBytes(16), Kdf.Hkdf32(phone.DeviceSecret!, Kdf.GateInfo));
        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, pc.Port);
            await tcp.GetStream().WriteAsync(pre);
            using var t = new CancellationTokenSource(5000);
            Assert.Equal(0, await tcp.GetStream().ReadAsync(new byte[8], t.Token));
        }
        // ...and the engine still works.
        var (conn, _) = await phone.OpenSessionAsync();
        conn.Dispose();
    }

    // Finding 4: an idle flood can't hold the slots.
    [Fact]
    public void Pre_auth_slots_evict_the_oldest()
    {
        var slots = new PreAuthSlots(max: 3, perIp: 2);
        var a = IPAddress.Parse("192.168.2.10");
        var b = IPAddress.Parse("192.168.2.11");
        var a1 = slots.Admit(a, CancellationToken.None);
        var a2 = slots.Admit(a, CancellationToken.None);
        var a3 = slots.Admit(a, CancellationToken.None);   // per-IP cap: evicts a1
        Assert.True(a1.Evicted && a1.Token.IsCancellationRequested);
        Assert.False(a2.Evicted || a3.Evicted);
        var b1 = slots.Admit(b, CancellationToken.None);   // reaches the global cap (3)
        var b2 = slots.Admit(b, CancellationToken.None);   // global cap: evicts the oldest (a2)
        Assert.True(a2.Evicted);
        Assert.False(a3.Evicted || b1.Evicted || b2.Evicted);
        b1.Complete();                                     // authenticated: no longer counts
        Assert.Equal(2, slots.Count);
    }

    [Fact]
    public async Task Phone_still_connects_during_an_idle_connection_flood()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var idle = new List<TcpClient>();
        try
        {
            for (int i = 0; i < 40; i++)
            {
                var c = new TcpClient();
                await c.ConnectAsync(IPAddress.Loopback, pc.Port);
                idle.Add(c);
            }
            var (conn, hello) = await phone.OpenSessionAsync();
            using (conn) Assert.Equal("pc", hello.GetProperty("role").GetString());
        }
        finally
        {
            foreach (var c in idle) c.Dispose();
        }
    }

    [Fact]
    public async Task Repeated_bad_greetings_lock_the_address_out()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        for (int i = 0; i < 10; i++)
        {
            using var c = new TcpClient();
            await c.ConnectAsync(IPAddress.Loopback, pc.Port);
            await c.GetStream().WriteAsync(new byte[Wire.PreambleLength]); // garbage
            using var t = new CancellationTokenSource(5000);
            await c.GetStream().ReadAsync(new byte[1], t.Token);
        }
        // Even the real phone is ignored from that address for a while.
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var conn = await phone.ConnectSessionAsync();
        });
    }

    // Finding 5: the received file is tagged, and the tag is recorded.
    [Fact]
    public async Task Received_files_are_tagged_before_they_appear()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        var received = new List<ActivityItem>();
        pc.Engine.ItemReceived += received.Add;
        var (conn, _) = await phone.OpenSessionAsync();
        using (conn)
        {
            var (_, reply) = await FakePhone.SendItemAsync(conn, "file", "tool.exe", RandomNumberGenerator.GetBytes(4096));
            Assert.True(reply.GetProperty("ok").GetBoolean());
        }
        var item = await TestEngine.WaitFor(() => received.FirstOrDefault());
        Assert.True(item.Tagged);
        Assert.Contains("ZoneId=3", File.ReadAllText(item.LocalPath + ":Zone.Identifier"));
        Assert.True(FileNames.IsExecutableType(item.Name));
    }
}
