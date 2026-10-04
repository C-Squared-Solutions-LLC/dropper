using System.Net;
using System.Text.Json;
using Dropper.Core.Crypto;
using Dropper.Core.Protocol;

namespace Dropper.Tests;

/// <summary>Byte-exact checks against docs/test-vectors.json (made by the independent Python reference).</summary>
public class VectorTests
{
    private static readonly JsonElement V = JsonDocument.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-vectors.json"))).RootElement;

    private static byte[] Hex(string path)
    {
        JsonElement e = V;
        foreach (var part in path.Split('.')) e = e.GetProperty(part);
        return Convert.FromHexString(e.GetString()!);
    }

    private static string HexOf(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void Hkdf_matches_rfc5869_case3()
    {
        Assert.Equal(Hex("rfc5869_case3.okm32"), Kdf.Hkdf32(Hex("rfc5869_case3.ikm"), ""));
    }

    [Fact]
    public void Key_schedule_matches()
    {
        var ps = Hex("inputs.pairing_secret");
        var ds = Hex("inputs.device_secret");
        Assert.Equal(Hex("keys.pair_gate_key"), Kdf.Hkdf32(ps, Kdf.PairGateInfo));
        Assert.Equal(Hex("keys.pair_proof_key"), Kdf.Hkdf32(ps, Kdf.PairProofInfo));
        Assert.Equal(Hex("keys.sas_key"), Kdf.Hkdf32(ps, Kdf.SasInfo));
        Assert.Equal(Hex("keys.gate_key"), Kdf.Hkdf32(ds, Kdf.GateInfo));
        Assert.Equal(Hex("keys.disc_key"), Kdf.Hkdf32(ds, Kdf.DiscoveryInfo));
    }

    [Fact]
    public void Proof_and_sas_match()
    {
        var pcFp = Hex("inputs.pc_fp");
        var phoneFp = Hex("inputs.phone_fp");
        var proof = Kdf.PairProof(Hex("keys.pair_proof_key"), pcFp, phoneFp);
        Assert.Equal(Hex("pair_proof"), proof);
        Assert.Equal(V.GetProperty("pair_proof_b64u").GetString(), Base64Url.Encode(proof));
        Assert.Equal(V.GetProperty("sas").GetString(), Kdf.Sas(Hex("keys.sas_key"), pcFp, phoneFp));
    }

    [Fact]
    public void Preambles_match_and_verify()
    {
        long ts = V.GetProperty("inputs").GetProperty("ts_ms").GetInt64();
        var nonce = Hex("inputs.nonce");
        var session = Preamble.Build(Wire.ModeSession, ts, nonce, Hex("keys.gate_key"));
        var pairing = Preamble.Build(Wire.ModePairing, ts, nonce, Hex("keys.pair_gate_key"));
        Assert.Equal(Hex("preamble_session"), session);
        Assert.Equal(Hex("preamble_pairing"), pairing);

        Assert.True(Preamble.TryParse(session, out var mode, out var parsedTs, out var parsedNonce));
        Assert.Equal(Wire.ModeSession, mode);
        Assert.Equal(ts, parsedTs);
        Assert.Equal(nonce, parsedNonce);
        Assert.True(Preamble.VerifyMac(session, Hex("keys.gate_key")));
        Assert.False(Preamble.VerifyMac(session, Hex("keys.pair_gate_key")));

        session[20] ^= 1;
        Assert.False(Preamble.VerifyMac(session, Hex("keys.gate_key")));
        var badMagic = (byte[])pairing.Clone();
        badMagic[0] = (byte)'X';
        Assert.False(Preamble.TryParse(badMagic, out _, out _, out _));
        var badMode = (byte[])pairing.Clone();
        badMode[4] = 0x07;
        Assert.False(Preamble.TryParse(badMode, out _, out _, out _));
    }

    [Fact]
    public void Discovery_packets_match()
    {
        long ts = V.GetProperty("inputs").GetProperty("ts_ms").GetInt64();
        var nonce = Hex("inputs.nonce");
        var disc = Hex("keys.disc_key");
        var req = DiscoveryPacket.BuildRequest(ts, nonce, disc);
        Assert.Equal(Hex("disc_request"), req);
        Assert.True(DiscoveryPacket.TryParseRequest(req, out var pts, out var pn));
        Assert.Equal(ts, pts);
        Assert.Equal(nonce, pn);
        Assert.True(DiscoveryPacket.VerifyRequest(req, disc));
        Assert.False(DiscoveryPacket.VerifyRequest(req, Hex("keys.gate_key")));

        var ip = IPAddress.Parse(V.GetProperty("inputs").GetProperty("pc_ip").GetString()!);
        int port = V.GetProperty("inputs").GetProperty("port").GetInt32();
        var resp = DiscoveryPacket.BuildResponse(ip, port, nonce, disc);
        Assert.Equal(Hex("disc_response"), resp);
        Assert.True(DiscoveryPacket.TryParseResponse(resp, disc, out var rip, out var rport, out var rn));
        Assert.Equal(ip, rip);
        Assert.Equal(port, rport);
        Assert.Equal(nonce, rn);
        resp[5] ^= 1;
        Assert.False(DiscoveryPacket.TryParseResponse(resp, disc, out _, out _, out _));
    }

    [Fact]
    public async Task Frames_match()
    {
        var hello = V.GetProperty("frame_hello");
        var ms = new MemoryStream();
        var writer = new FrameWriter(ms);
        await writer.WriteAsync(FrameType.Hello, System.Text.Encoding.UTF8.GetBytes(hello.GetProperty("body_utf8").GetString()!), CancellationToken.None);
        Assert.Equal(hello.GetProperty("bytes").GetString(), HexOf(ms.ToArray()));

        var ping = new MemoryStream();
        await new FrameWriter(ping).WriteAsync(FrameType.Ping, CancellationToken.None);
        Assert.Equal(V.GetProperty("frame_ping").GetString(), HexOf(ping.ToArray()));

        ms.Position = 0;
        var (type, body) = await new FrameReader(ms).ReadAsync(CancellationToken.None);
        Assert.Equal(FrameType.Hello, type);
        Assert.Equal(hello.GetProperty("body_utf8").GetString(), System.Text.Encoding.UTF8.GetString(body.Span));
    }

    [Fact]
    public async Task Frame_reader_rejects_oversize_and_unknown_types()
    {
        var huge = new MemoryStream(new byte[] { 0x00, 0x20, 0x00, 0x00, 0x13 });
        await Assert.ThrowsAsync<ProtocolException>(async () => await new FrameReader(huge).ReadAsync(CancellationToken.None));
        var zero = new MemoryStream(new byte[] { 0, 0, 0, 0, 0x02 });
        await Assert.ThrowsAsync<ProtocolException>(async () => await new FrameReader(zero).ReadAsync(CancellationToken.None));
        var unknown = new MemoryStream(new byte[] { 0, 0, 0, 1, 0x7F });
        await Assert.ThrowsAsync<ProtocolException>(async () => await new FrameReader(unknown).ReadAsync(CancellationToken.None));
    }

    [Fact]
    public void Qr_uri_and_fingerprint_display_match()
    {
        var uri = PairingUri.Build(
            new[] { new IPEndPoint(IPAddress.Parse("192.168.2.131"), 47823) },
            Hex("inputs.pc_fp"), Hex("inputs.pairing_secret"), "MY-PC");
        Assert.Equal(V.GetProperty("qr_uri").GetString(), uri);
        Assert.Equal(V.GetProperty("fp_display_pc").GetString(), Fingerprint.Display(Hex("inputs.pc_fp")));
    }

    [Fact]
    public void Base64url_round_trips_and_rejects_garbage()
    {
        for (int n = 0; n < 40; n++)
        {
            var data = System.Security.Cryptography.RandomNumberGenerator.GetBytes(n);
            Assert.True(Base64Url.TryDecode(Base64Url.Encode(data), out var back));
            Assert.Equal(data, back);
        }
        Assert.False(Base64Url.TryDecode("abc=", out _));
        Assert.False(Base64Url.TryDecode("a+b/", out _));
        Assert.False(Base64Url.TryDecode("abcde", out _));
    }
}
