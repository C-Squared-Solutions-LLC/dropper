using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dropper.Core.Crypto;
using Dropper.Core.Protocol;

namespace Dropper.Tests;

/// <summary>Test-only implementation of the phone side of the protocol.</summary>
internal sealed class FakePhone : IDisposable
{
    private readonly string _keyName = "DropperTest-Phone-" + Guid.NewGuid().ToString("N");
    private readonly ECDsaCng _key;

    public FakePhone()
    {
        _key = new ECDsaCng(CngKey.Create(CngAlgorithm.ECDsaP256, _keyName, new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyUsage = CngKeyUsages.Signing,
        }));
        var req = new CertificateRequest("CN=Dropper Phone", _key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var self = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        Certificate = new X509Certificate2(self.Export(X509ContentType.Cert)).CopyWithPrivateKey(_key);
        Fp = Fingerprint.Of(Certificate);
    }

    public X509Certificate2 Certificate { get; }
    public byte[] Fp { get; }
    public byte[]? PcFp { get; private set; }
    public IPEndPoint? PcEndpoint { get; private set; }
    public byte[]? DeviceSecret { get; set; }
    public string Name { get; init; } = "Test Phone";

    public sealed record QrInfo(IPEndPoint Endpoint, byte[] PcFp, byte[] Secret, string Name);

    public static QrInfo ParseQr(string uri)
    {
        var q = new Uri(uri.Replace("dropper://pair", "http://pair"));
        var parts = q.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));
        Assert.Equal("1", parts["v"]);
        var first = parts["a"].Split(',')[0].Split(':');
        Assert.True(Base64Url.TryDecode(parts["k"], out var k));
        Assert.True(Base64Url.TryDecode(parts["s"], out var s));
        return new QrInfo(new IPEndPoint(IPAddress.Parse(first[0]), int.Parse(first[1])), k, s, parts["n"]);
    }

    // ------------------------------------------------------------------ pairing

    public sealed record PairResult(bool Ok, string? Error, string? Sas);

    public async Task<PairResult> PairAsync(string uri, bool corruptProof = false)
    {
        var qr = ParseQr(uri);
        PcFp = qr.PcFp;
        PcEndpoint = qr.Endpoint;
        string sas = Kdf.Sas(Kdf.Hkdf32(qr.Secret, Kdf.SasInfo), qr.PcFp, Fp);

        using var conn = await ConnectAsync(Wire.ModePairing, Kdf.Hkdf32(qr.Secret, Kdf.PairGateInfo));
        var proof = Kdf.PairProof(Kdf.Hkdf32(qr.Secret, Kdf.PairProofInfo), qr.PcFp, Fp);
        if (corruptProof) proof[0] ^= 0xFF;
        await conn.Writer.WriteAsync(FrameType.PairRequest, Messages.Object(w =>
        {
            w.WriteNumber("v", 1);
            w.WriteString("name", Name);
            w.WriteString("model", "FakePhone 1");
            w.WriteString("proof", Base64Url.Encode(proof));
        }), CancellationToken.None);

        using var t = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var (type, body) = await conn.Reader.ReadAsync(t.Token);
        using var doc = JsonDocument.Parse(body);
        if (type == FrameType.PairOk)
        {
            Assert.True(Base64Url.TryDecode(doc.RootElement.GetProperty("secret").GetString(), out var secret));
            Assert.Equal(32, secret.Length);
            DeviceSecret = secret;
            return new PairResult(true, null, sas);
        }
        Assert.Equal(FrameType.PairFail, type);
        return new PairResult(false, doc.RootElement.GetProperty("error").GetString(), sas);
    }

    // ------------------------------------------------------------------ connections

    public sealed class Connection : IDisposable
    {
        public required TcpClient Tcp { get; init; }
        public required SslStream Ssl { get; init; }
        public required FrameReader Reader { get; init; }
        public required FrameWriter Writer { get; init; }

        public void Dispose()
        {
            Writer.Dispose();
            Ssl.Dispose();
            Tcp.Dispose();
        }
    }

    public Task<Connection> ConnectSessionAsync() =>
        ConnectAsync(Wire.ModeSession, Kdf.Hkdf32(DeviceSecret!, Kdf.GateInfo));

    /// <summary>Connects, sends the preamble, completes TLS. Throws if the PC refuses.</summary>
    public async Task<Connection> ConnectAsync(byte mode, byte[] gateKey, byte[]? rawPreamble = null,
        X509Certificate2? clientCertOverride = null)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(PcEndpoint!.Address, PcEndpoint.Port);
        var net = tcp.GetStream();
        var preamble = rawPreamble ?? Preamble.Build(mode, gateKey, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        await net.WriteAsync(preamble);

        var cert = clientCertOverride ?? Certificate;
        var ssl = new SslStream(net, false);
        try
        {
            using var t = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "dropper",
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = new X509CertificateCollection { cert },
                LocalCertificateSelectionCallback = (_, _, _, _, _) => cert,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, c, _, _) =>
                    c is not null && Fingerprint.Of(new X509Certificate2(c)).AsSpan().SequenceEqual(PcFp),
            }, t.Token);
        }
        catch
        {
            ssl.Dispose();
            tcp.Dispose();
            throw;
        }
        return new Connection { Tcp = tcp, Ssl = ssl, Reader = new FrameReader(ssl), Writer = new FrameWriter(ssl) };
    }

    /// <summary>Opens a session and does the HELLO exchange. Returns the PC's HELLO JSON.</summary>
    public async Task<(Connection Conn, JsonElement PcHello)> OpenSessionAsync()
    {
        var conn = await ConnectSessionAsync();
        await conn.Writer.WriteAsync(FrameType.Hello, Messages.Object(w =>
        {
            w.WriteNumber("v", 1);
            w.WriteString("role", "phone");
            w.WriteString("name", Name);
            w.WriteString("model", "FakePhone 1");
            w.WriteString("app", "1.0.0");
        }), CancellationToken.None);
        var (type, body) = await ReadAsync(conn);
        Assert.Equal(FrameType.Hello, type);
        using var doc = JsonDocument.Parse(body);
        return (conn, doc.RootElement.Clone());
    }

    public static async Task<(FrameType Type, byte[] Body)> ReadAsync(Connection c, int timeoutMs = 15000)
    {
        using var t = new CancellationTokenSource(timeoutMs);
        var (type, body) = await c.Reader.ReadAsync(t.Token);
        return (type, body.ToArray());
    }

    /// <summary>Receives one item the PC sends (answers ACCEPT and RESULT).</summary>
    public static async Task<(JsonElement Offer, byte[] Content)> ReceiveItemAsync(Connection c, bool acceptIt = true)
    {
        var (type, body) = await ReadAsync(c);
        Assert.Equal(FrameType.Offer, type);
        JsonElement offer;
        using (var doc = JsonDocument.Parse(body)) offer = doc.RootElement.Clone();
        string id = offer.GetProperty("id").GetString()!;
        if (!acceptIt)
        {
            await c.Writer.WriteAsync(FrameType.Reject, Messages.Reject(id, "duplicate"), CancellationToken.None);
            return (offer, Array.Empty<byte>());
        }
        await c.Writer.WriteAsync(FrameType.Accept, Messages.IdOnly(id), CancellationToken.None);

        var content = new MemoryStream();
        while (true)
        {
            var (t2, b2) = await ReadAsync(c);
            if (t2 == FrameType.Data) { content.Write(b2); continue; }
            Assert.Equal(FrameType.End, t2);
            Assert.Equal(SHA256.HashData(content.ToArray()), b2);
            break;
        }
        await c.Writer.WriteAsync(FrameType.Result, Messages.Result(id, true), CancellationToken.None);
        return (offer, content.ToArray());
    }

    /// <summary>Sends one item to the PC. Returns the PC's final reply (REJECT or RESULT).</summary>
    public static async Task<(FrameType Type, JsonElement Body)> SendItemAsync(Connection c, string kind, string name,
        byte[] content, string? id = null, bool corruptHash = false)
    {
        id ??= Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        await c.Writer.WriteAsync(FrameType.Offer, Messages.Offer(new OfferMessage(id,
            kind == "text" ? ItemKind.Text : ItemKind.File, name, kind == "text" ? "text/plain" : "application/octet-stream",
            content.Length)), CancellationToken.None);
        var (type, body) = await ReadAsync(c);
        JsonElement reply;
        using (var doc = JsonDocument.Parse(body)) reply = doc.RootElement.Clone();
        if (type == FrameType.Reject) return (type, reply);
        Assert.Equal(FrameType.Accept, type);

        for (int off = 0; off < content.Length; off += 100_000)
            await c.Writer.WriteAsync(FrameType.Data, content.AsMemory(off, Math.Min(100_000, content.Length - off)), CancellationToken.None);
        var hash = SHA256.HashData(content);
        if (corruptHash) hash[0] ^= 1;
        await c.Writer.WriteAsync(FrameType.End, hash, CancellationToken.None);

        (type, body) = await ReadAsync(c);
        using (var doc = JsonDocument.Parse(body)) reply = doc.RootElement.Clone();
        return (type, reply);
    }

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public void Dispose()
    {
        Certificate.Dispose();
        try { _key.Key.Delete(); } catch (CryptographicException) { }
        _key.Dispose();
    }
}
