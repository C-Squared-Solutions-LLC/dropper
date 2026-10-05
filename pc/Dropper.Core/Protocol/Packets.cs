using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Dropper.Core.Crypto;

namespace Dropper.Core.Protocol;

/// <summary>The 61-byte authenticated preamble sent before TLS (docs/PROTOCOL.md §6.1).</summary>
public static class Preamble
{
    private static ReadOnlySpan<byte> Magic => "DRP1"u8;
    private const int HeaderLength = 29;

    public static byte[] Build(byte mode, long tsMs, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> key)
    {
        if (nonce16.Length != 16) throw new ArgumentException("nonce must be 16 bytes", nameof(nonce16));
        var p = new byte[Wire.PreambleLength];
        Magic.CopyTo(p);
        p[4] = mode;
        BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(5), tsMs);
        nonce16.CopyTo(p.AsSpan(13));
        Kdf.Hmac(key, p.AsSpan(0, HeaderLength)).CopyTo(p.AsSpan(HeaderLength));
        return p;
    }

    public static byte[] Build(byte mode, ReadOnlySpan<byte> key, long nowMs) =>
        Build(mode, nowMs, RandomNumberGenerator.GetBytes(16), key);

    /// <summary>Parses magic, mode, timestamp and nonce. Does not check the MAC.</summary>
    public static bool TryParse(ReadOnlySpan<byte> p, out byte mode, out long tsMs, out byte[] nonce)
    {
        mode = 0; tsMs = 0; nonce = Array.Empty<byte>();
        if (p.Length != Wire.PreambleLength || !p[..4].SequenceEqual(Magic)) return false;
        mode = p[4];
        if (mode is not (Wire.ModeSession or Wire.ModePairing or Wire.ModePcPairing)) return false;
        tsMs = BinaryPrimitives.ReadInt64BigEndian(p[5..]);
        nonce = p.Slice(13, 16).ToArray();
        return true;
    }

    public static bool VerifyMac(ReadOnlySpan<byte> p, ReadOnlySpan<byte> key) =>
        p.Length == Wire.PreambleLength &&
        Kdf.FixedTimeEquals(Kdf.Hmac(key, p[..HeaderLength]), p[HeaderLength..]);
}

/// <summary>UDP discovery request/response (docs/PROTOCOL.md §10).</summary>
public static class DiscoveryPacket
{
    private static ReadOnlySpan<byte> RequestMagic => "DRD1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "DRD2"u8;
    public const int RequestLength = 60;
    public const int ResponseLength = 58;

    public static byte[] BuildRequest(long tsMs, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> discKey)
    {
        var p = new byte[RequestLength];
        RequestMagic.CopyTo(p);
        BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(4), tsMs);
        nonce16.CopyTo(p.AsSpan(12));
        Kdf.Hmac(discKey, p.AsSpan(0, 28)).CopyTo(p.AsSpan(28));
        return p;
    }

    public static bool TryParseRequest(ReadOnlySpan<byte> p, out long tsMs, out byte[] nonce)
    {
        tsMs = 0; nonce = Array.Empty<byte>();
        if (p.Length != RequestLength || !p[..4].SequenceEqual(RequestMagic)) return false;
        tsMs = BinaryPrimitives.ReadInt64BigEndian(p[4..]);
        nonce = p.Slice(12, 16).ToArray();
        return true;
    }

    public static bool VerifyRequest(ReadOnlySpan<byte> p, ReadOnlySpan<byte> discKey) =>
        p.Length == RequestLength && Kdf.FixedTimeEquals(Kdf.Hmac(discKey, p[..28]), p[28..]);

    public static byte[] BuildResponse(IPAddress ip, int port, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> discKey)
    {
        var addr = ip.MapToIPv4().GetAddressBytes();
        var p = new byte[ResponseLength];
        ResponseMagic.CopyTo(p);
        addr.CopyTo(p, 4);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(8), (ushort)port);
        nonce16.CopyTo(p.AsSpan(10));
        Kdf.Hmac(discKey, p.AsSpan(0, 26)).CopyTo(p.AsSpan(26));
        return p;
    }

    public static bool TryParseResponse(ReadOnlySpan<byte> p, ReadOnlySpan<byte> discKey,
        out IPAddress ip, out int port, out byte[] nonce)
    {
        ip = IPAddress.None; port = 0; nonce = Array.Empty<byte>();
        if (p.Length != ResponseLength || !p[..4].SequenceEqual(ResponseMagic)) return false;
        if (!Kdf.FixedTimeEquals(Kdf.Hmac(discKey, p[..26]), p[26..])) return false;
        ip = new IPAddress(p.Slice(4, 4));
        port = BinaryPrimitives.ReadUInt16BigEndian(p[8..]);
        nonce = p.Slice(10, 16).ToArray();
        return true;
    }
}

/// <summary>
/// "Which PCs are accepting a PC pairing right now?" (docs/PROTOCOL.md §10.1). Only a PC
/// with its PC-pairing window open answers. The request is padded so the answer is
/// never larger than the question (no amplification).
/// </summary>
public static class PcQueryPacket
{
    private static ReadOnlySpan<byte> RequestMagic => "DRQ1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "DRQ2"u8;
    public const int RequestLength = 100;
    public const int MaxNameBytes = 64;

    public static byte[] BuildRequest(ReadOnlySpan<byte> nonce16)
    {
        var p = new byte[RequestLength];
        RequestMagic.CopyTo(p);
        nonce16.CopyTo(p.AsSpan(4));
        return p;
    }

    public static bool TryParseRequest(ReadOnlySpan<byte> p, out byte[] nonce)
    {
        nonce = Array.Empty<byte>();
        if (p.Length != RequestLength || !p[..4].SequenceEqual(RequestMagic)) return false;
        nonce = p.Slice(4, 16).ToArray();
        return true;
    }

    public static byte[] BuildResponse(ReadOnlySpan<byte> nonce16, int port, string name)
    {
        var nameBytes = System.Text.Encoding.UTF8.GetBytes(TextSafety.Truncate(name, 32));
        if (nameBytes.Length > MaxNameBytes) nameBytes = nameBytes[..MaxNameBytes];
        var p = new byte[4 + 16 + 2 + 1 + nameBytes.Length];
        ResponseMagic.CopyTo(p);
        nonce16.CopyTo(p.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)port);
        p[22] = (byte)nameBytes.Length;
        nameBytes.CopyTo(p, 23);
        return p;
    }

    public static bool TryParseResponse(ReadOnlySpan<byte> p, out byte[] nonce, out int port, out string name)
    {
        nonce = Array.Empty<byte>(); port = 0; name = "";
        if (p.Length < 23 || p.Length > 23 + MaxNameBytes || !p[..4].SequenceEqual(ResponseMagic)) return false;
        int len = p[22];
        if (p.Length != 23 + len) return false;
        nonce = p.Slice(4, 16).ToArray();
        port = BinaryPrimitives.ReadUInt16BigEndian(p[20..]);
        name = TextSafety.CleanDisplayName(System.Text.Encoding.UTF8.GetString(p.Slice(23, len)), 64);
        return port > 0;
    }
}
