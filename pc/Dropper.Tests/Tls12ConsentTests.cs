using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using Dropper.Core.Engine;
using Dropper.Core.Storage;
using Dropper.Core.Protocol;

namespace Dropper.Tests;

/// <summary>
/// TLS 1.2 exists only for Windows 10 PCs and only with consent on both PCs (docs/PROTOCOL.md §6.2).
/// The "Windows 10" engine here is a real engine that won't offer TLS 1.3.
/// </summary>
public class Tls12ConsentTests
{
    private static async Task<(TestEngine Host, TestEngine Old)> HostAndWindows10Async()
    {
        var host = await TestEngine.StartAsync(pcName: "WIN11-PC");
        var old = await TestEngine.StartAsync(peerDiscoveryPort: host.DiscoveryPort, pcName: "WIN10-PC", windows10: true);
        return (host, old);
    }

    [Fact]
    public async Task Windows10_pc_pairs_over_tls12_only_when_both_users_allow_it()
    {
        var (host, old) = await HostAndWindows10Async();
        await using var _h = host;
        await using var _o = old;
        host.Engine.StartPcPairing();
        var target = Assert.Single(await old.Engine.FindPcsAsync(TimeSpan.FromSeconds(1)));

        bool hostSawLegacy = false, joinerSawLegacy = false;
        host.Engine.PairingRequested += r => { hostSawLegacy = r.LegacyTls; r.Approve(allowLegacyTls: true); };
        var outcome = await old.Engine.PairWithPcAsync(target.Endpoint, code => { joinerSawLegacy = code.LegacyTls; return Task.FromResult(true); });

        Assert.True(outcome.Success, outcome.Message);
        Assert.True(hostSawLegacy);
        Assert.True(joinerSawLegacy);
        Assert.True(Assert.Single(host.Engine.GetDevices()).Tls12Allowed);
        Assert.True(Assert.Single(old.Engine.GetDevices()).Tls12Allowed);

        // The stored consent carries the session too, and files still arrive intact.
        await TestEngine.WaitUntil(() => host.Engine.GetDevices()[0].Connected && old.Engine.GetDevices()[0].Connected);
        var received = new List<ActivityItem>();
        host.Engine.ItemReceived += received.Add;
        var src = Path.Combine(old.Root, "from-win10.bin");
        var bytes = RandomNumberGenerator.GetBytes(300_000);
        await File.WriteAllBytesAsync(src, bytes);
        old.Engine.QueueFiles(new[] { src });
        var file = await TestEngine.WaitFor(() => received.FirstOrDefault());
        Assert.Equal(bytes, await File.ReadAllBytesAsync(file.LocalPath!));
    }

    [Fact]
    public async Task Approving_without_allowing_tls12_is_a_rejection()
    {
        var (host, old) = await HostAndWindows10Async();
        await using var _h = host;
        await using var _o = old;
        host.Engine.StartPcPairing();
        var target = Assert.Single(await old.Engine.FindPcsAsync(TimeSpan.FromSeconds(1)));
        host.Engine.PairingRequested += r => r.Approve(); // codes match, but TLS 1.2 not allowed

        var outcome = await old.Engine.PairWithPcAsync(target.Endpoint, _ => Task.FromResult(true));
        Assert.False(outcome.Success);
        Assert.Empty(host.Engine.GetDevices());
        Assert.Empty(old.Engine.GetDevices());
    }

    [Fact]
    public async Task Joiner_declining_tls12_stores_nothing()
    {
        var (host, old) = await HostAndWindows10Async();
        await using var _h = host;
        await using var _o = old;
        host.Engine.StartPcPairing();
        var target = Assert.Single(await old.Engine.FindPcsAsync(TimeSpan.FromSeconds(1)));
        host.Engine.PairingRequested += r => r.Approve(allowLegacyTls: true);

        // What the UI returns when the code matches but "Allow TLS 1.2" stays off.
        var outcome = await old.Engine.PairWithPcAsync(target.Endpoint, code => Task.FromResult(!code.LegacyTls));
        Assert.False(outcome.Success);
        Assert.Empty(host.Engine.GetDevices());
        Assert.Empty(old.Engine.GetDevices());
    }

    [Fact]
    public async Task A_paired_phone_offering_only_tls12_is_refused()
    {
        await using var pc = await TestEngine.StartAsync();
        using var phone = await pc.PairPhoneAsync();
        phone.Protocols = SslProtocols.Tls12;
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var c = await phone.ConnectSessionAsync();
            await FakePhone.ReadAsync(c); // if the client side raced to completion, the PC still drops it
        });
    }

    [Fact]
    public async Task Windows10_pc_cannot_show_a_phone_pairing_code()
    {
        await using var old = await TestEngine.StartAsync(windows10: true);
        Assert.False(old.Engine.Tls13Available);
        Assert.Throws<InvalidOperationException>(() => old.Engine.StartPairing());
    }

    [Theory]
    [InlineData(SslProtocols.Tls13, TlsCipherSuite.TLS_AES_128_GCM_SHA256, false, true)]
    [InlineData(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, true)]
    [InlineData(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, false, false)]
    [InlineData(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, false)]
    [InlineData(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, true, false)]
    [InlineData(SslProtocols.Tls12, TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, true, false)]
#pragma warning disable SYSLIB0039 // obsolete on purpose: it must be refused
    [InlineData(SslProtocols.Tls11, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, false)]
#pragma warning restore SYSLIB0039
    public void Only_tls13_or_consented_tls12_aead_is_acceptable(SslProtocols p, TlsCipherSuite suite, bool allowTls12, bool ok) =>
        Assert.Equal(ok, TlsPolicy.IsAcceptable(p, suite, allowTls12));

    [Fact]
    public void Nothing_offered_means_no_handshake_not_os_defaults()
    {
        Assert.Null(TlsPolicy.Offer(allowTls12: false, tls13Available: false));
        Assert.Equal(SslProtocols.Tls13, TlsPolicy.Offer(allowTls12: false, tls13Available: true));
        Assert.Equal(SslProtocols.Tls12, TlsPolicy.Offer(allowTls12: true, tls13Available: false));
    }
}
