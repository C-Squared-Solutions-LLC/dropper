using System.Security.Cryptography;
using Dropper.Core.Crypto;
using Dropper.Core.Engine;
using Dropper.Core.Storage;

namespace Dropper.Tests;

/// <summary>Two real engines on loopback: PC-to-PC pairing by code comparison, then transfers both ways.</summary>
public class PcToPcTests
{
    private static async Task<(TestEngine Host, TestEngine Joiner)> TwoPcsAsync()
    {
        var host = await TestEngine.StartAsync(pcName: "HOST-PC");
        var joiner = await TestEngine.StartAsync(peerDiscoveryPort: host.DiscoveryPort, pcName: "JOINER-PC");
        return (host, joiner);
    }

    private static async Task<DiscoveredPc> FindHostAsync(TestEngine joiner)
    {
        var found = await joiner.Engine.FindPcsAsync(TimeSpan.FromSeconds(1));
        return Assert.Single(found);
    }

    [Fact]
    public async Task Pcs_pair_by_comparing_codes_and_transfer_both_ways()
    {
        var (host, joiner) = await TwoPcsAsync();
        await using var _h = host;
        await using var _j = joiner;

        host.Engine.StartPcPairing();
        var target = await FindHostAsync(joiner);
        Assert.Equal("HOST-PC", target.Name);

        string? hostSas = null, joinerSas = null;
        host.Engine.PairingRequested += r => { hostSas = r.Sas; r.Approve(); };
        var outcome = await joiner.Engine.PairWithPcAsync(target.Endpoint, code => { joinerSas = code.Sas; Assert.False(code.LegacyTls); return Task.FromResult(true); });

        Assert.True(outcome.Success, outcome.Message);
        Assert.NotNull(hostSas);
        Assert.Equal(hostSas, joinerSas);
        Assert.Equal("pc", Assert.Single(host.Engine.GetDevices()).Kind);
        Assert.Equal("pc", Assert.Single(joiner.Engine.GetDevices()).Kind);

        // The joiner connects on its own and both sides see each other.
        await TestEngine.WaitUntil(() => host.Engine.GetDevices()[0].Connected && joiner.Engine.GetDevices()[0].Connected);

        var atJoiner = new List<ActivityItem>();
        var atHost = new List<ActivityItem>();
        joiner.Engine.ItemReceived += atJoiner.Add;
        host.Engine.ItemReceived += atHost.Add;

        host.Engine.QueueText("hello from the host");
        var text = await TestEngine.WaitFor(() => atJoiner.FirstOrDefault());
        Assert.Equal("hello from the host", text.Text);

        var src = Path.Combine(joiner.Root, "report.bin");
        var bytes = RandomNumberGenerator.GetBytes(2_000_000);
        await File.WriteAllBytesAsync(src, bytes);
        joiner.Engine.QueueFiles(new[] { src });
        var file = await TestEngine.WaitFor(() => atHost.FirstOrDefault());
        Assert.Equal(bytes, await File.ReadAllBytesAsync(file.LocalPath!));
        Assert.True(file.Tagged);
    }

    [Fact]
    public async Task Host_rejecting_creates_nothing_on_either_side()
    {
        var (host, joiner) = await TwoPcsAsync();
        await using var _h = host;
        await using var _j = joiner;
        host.Engine.StartPcPairing();
        var target = await FindHostAsync(joiner);
        host.Engine.PairingRequested += r => r.Reject();

        var outcome = await joiner.Engine.PairWithPcAsync(target.Endpoint, _ => Task.FromResult(true));
        Assert.False(outcome.Success);
        Assert.Empty(host.Engine.GetDevices());
        Assert.Empty(joiner.Engine.GetDevices());
    }

    [Fact]
    public async Task Joiner_rejecting_creates_nothing_on_either_side()
    {
        var (host, joiner) = await TwoPcsAsync();
        await using var _h = host;
        await using var _j = joiner;
        host.Engine.StartPcPairing();
        var target = await FindHostAsync(joiner);
        PairingOutcome? hostOutcome = null;
        host.Engine.PairingRequested += r => r.Approve();
        host.Engine.PairingCompleted += o => hostOutcome = o;

        var outcome = await joiner.Engine.PairWithPcAsync(target.Endpoint, _ => Task.FromResult(false));
        Assert.False(outcome.Success);
        await TestEngine.WaitUntil(() => hostOutcome is not null);
        Assert.False(hostOutcome!.Success);
        Assert.Empty(host.Engine.GetDevices());
        Assert.Empty(joiner.Engine.GetDevices());
    }

    [Fact]
    public async Task Pcs_are_invisible_and_unpairable_without_an_open_window()
    {
        var (host, joiner) = await TwoPcsAsync();
        await using var _h = host;
        await using var _j = joiner;
        Assert.Empty(await joiner.Engine.FindPcsAsync(TimeSpan.FromSeconds(1)));

        var hostEndpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, host.Port);
        var outcome = await joiner.Engine.PairWithPcAsync(hostEndpoint, _ => Task.FromResult(true));
        Assert.False(outcome.Success);
        Assert.Empty(host.Engine.GetDevices());
    }

    [Fact]
    public async Task Removing_the_pairing_on_one_pc_removes_it_on_the_other()
    {
        var (host, joiner) = await TwoPcsAsync();
        await using var _h = host;
        await using var _j = joiner;
        host.Engine.StartPcPairing();
        var target = await FindHostAsync(joiner);
        host.Engine.PairingRequested += r => r.Approve();
        Assert.True((await joiner.Engine.PairWithPcAsync(target.Endpoint, _ => Task.FromResult(true))).Success);
        await TestEngine.WaitUntil(() => host.Engine.GetDevices()[0].Connected);

        await host.Engine.RemoveDeviceAsync(host.Engine.GetDevices()[0].FpHex);
        await TestEngine.WaitUntil(() => joiner.Engine.GetDevices().Count == 0);
    }

    [Fact]
    public void Commitment_binds_the_nonce_and_both_keys()
    {
        var na = RandomNumberGenerator.GetBytes(32);
        var a = RandomNumberGenerator.GetBytes(32);
        var b = RandomNumberGenerator.GetBytes(32);
        var commit = Kdf.PcSasCommit(na, a, b);
        Assert.Equal(commit, Kdf.PcSasCommit(na, a, b));
        Assert.NotEqual(commit, Kdf.PcSasCommit(RandomNumberGenerator.GetBytes(32), a, b));
        Assert.NotEqual(commit, Kdf.PcSasCommit(na, b, a));
        var nb = RandomNumberGenerator.GetBytes(32);
        Assert.NotEqual(Kdf.PcSas(na, nb, a, b), Kdf.PcSas(na, RandomNumberGenerator.GetBytes(32), a, b));
    }
}
