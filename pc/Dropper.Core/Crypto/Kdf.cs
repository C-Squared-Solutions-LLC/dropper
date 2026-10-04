using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Dropper.Core.Crypto;

/// <summary>Key schedule and MAC helpers. See docs/PROTOCOL.md §2 and §4.</summary>
public static class Kdf
{
    public const string PairGateInfo = "dropper/v1/pair-gate";
    public const string PairProofInfo = "dropper/v1/pair-proof";
    public const string SasInfo = "dropper/v1/sas";
    public const string GateInfo = "dropper/v1/gate";
    public const string DiscoveryInfo = "dropper/v1/discovery";

    private static readonly byte[] ZeroSalt = new byte[32];

    /// <summary>HKDF-SHA256 with a 32-byte zero salt and a 32-byte output.</summary>
    public static byte[] Hkdf32(ReadOnlySpan<byte> ikm, string info)
    {
        var okm = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, okm, ZeroSalt, Encoding.ASCII.GetBytes(info));
        return okm;
    }

    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);

    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>proof = HMAC(pair_proof_key, pc_fp || phone_fp)</summary>
    public static byte[] PairProof(ReadOnlySpan<byte> pairProofKey, ReadOnlySpan<byte> pcFp, ReadOnlySpan<byte> phoneFp) =>
        Hmac(pairProofKey, Concat(pcFp, phoneFp));

    /// <summary>Six-digit short authentication string (unformatted, e.g. "074512").</summary>
    public static string Sas(ReadOnlySpan<byte> sasKey, ReadOnlySpan<byte> pcFp, ReadOnlySpan<byte> phoneFp)
    {
        var h = Hmac(sasKey, Concat(pcFp, phoneFp));
        uint n = BinaryPrimitives.ReadUInt32BigEndian(h) % 1_000_000;
        return n.ToString("D6");
    }

    public static string FormatSas(string sas) => sas.Length == 6 ? sas[..3] + " " + sas[3..] : sas;

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r);
        b.CopyTo(r.AsSpan(a.Length));
        return r;
    }
}

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool TryDecode(string? s, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (s is null || s.Length > 4096) return false;
        foreach (char c in s)
        {
            bool ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok) return false;
        }
        string b64 = s.Replace('-', '+').Replace('_', '/');
        switch (b64.Length % 4)
        {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
            case 1: return false;
        }
        try { bytes = Convert.FromBase64String(b64); return true; }
        catch (FormatException) { return false; }
    }
}
