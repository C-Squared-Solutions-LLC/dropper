using System.Net;
using System.Net.Sockets;
using Dropper.Core.Crypto;
using Dropper.Core.Engine;
using Dropper.Core.Net;
using Dropper.Core.Protocol;

namespace Dropper.Tests;

/// <summary>An engine on loopback with its own temp data dir, key and ports.</summary>
internal sealed class TestEngine : IAsyncDisposable
{
    public DropperEngine Engine { get; }
    public string Root { get; }
    public string ReceiveDir { get; }
    public int Port { get; }
    public int DiscoveryPort { get; }
    private readonly string _keyName = "DropperTest-PC-" + Guid.NewGuid().ToString("N");

    private TestEngine(int? peerDiscoveryPort, string pcName)
    {
        Root = Path.Combine(Path.GetTempPath(), "dropper-test-" + Guid.NewGuid().ToString("N"));
        ReceiveDir = Path.Combine(Root, "received");
        Port = FreeTcpPort();
        DiscoveryPort = FreeUdpPort();
        Engine = new DropperEngine(new EngineOptions
        {
            DataDirectory = Path.Combine(Root, "data"),
            KeyName = _keyName,
            AllowTpm = false,
            ListenOverride = [new LanAddress(IPAddress.Loopback, 8, "loopback", "lo")],
            PortOverride = Port,
            DiscoveryPort = DiscoveryPort,
            DiscoveryBindAddress = IPAddress.Loopback,
            ReceiveFolderOverride = ReceiveDir,
            PeerDiscoveryPort = peerDiscoveryPort ?? Wire.DiscoveryPort,
            PcName = pcName,
        });
    }

    public static async Task<TestEngine> StartAsync(int? peerDiscoveryPort = null, string pcName = "TEST-PC")
    {
        var t = new TestEngine(peerDiscoveryPort, pcName);
        await t.Engine.StartAsync();
        Assert.True(t.Engine.IsListening, t.Engine.NetworkError);
        return t;
    }

    /// <summary>Pairs a fake phone, auto-approving and checking that both sides computed the same SAS.</summary>
    public async Task<FakePhone> PairPhoneAsync(string name = "Test Phone")
    {
        var phone = new FakePhone { Name = name };
        string? pcSas = null;
        void Approve(PairingRequest r) { pcSas = r.Sas; r.Approve(); }
        Engine.PairingRequested += Approve;
        try
        {
            var ticket = Engine.StartPairing();
            var result = await phone.PairAsync(ticket.Uri);
            Assert.True(result.Ok, result.Error);
            Assert.Equal(Kdf.FormatSas(result.Sas!), pcSas);
        }
        finally
        {
            Engine.PairingRequested -= Approve;
        }
        return phone;
    }

    public static async Task<T> WaitFor<T>(Func<T?> probe, int timeoutMs = 10000) where T : class
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            var v = probe();
            if (v is not null) return v;
            await Task.Delay(25);
        }
        throw new TimeoutException("condition not met");
    }

    public static async Task WaitUntil(Func<bool> probe, int timeoutMs = 10000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (probe()) return;
            await Task.Delay(25);
        }
        throw new TimeoutException("condition not met");
    }

    private static int FreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static int FreeUdpPort()
    {
        using var u = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)u.Client.LocalEndPoint!).Port;
    }

    public async ValueTask DisposeAsync()
    {
        await Engine.DisposeAsync();
        Identity.Delete(Path.Combine(Root, "data", "identity.cer"), _keyName);
        try { Directory.Delete(Root, recursive: true); } catch (IOException) { }
    }
}
