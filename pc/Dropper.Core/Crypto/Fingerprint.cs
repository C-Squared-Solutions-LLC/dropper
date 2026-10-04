using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dropper.Core.Crypto;

/// <summary>fp = SHA-256 over the DER SubjectPublicKeyInfo (docs/PROTOCOL.md §3).</summary>
public static class Fingerprint
{
    public static byte[] Of(X509Certificate2 cert) =>
        SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo());

    public static string Hex(ReadOnlySpan<byte> fp) => Convert.ToHexString(fp).ToLowerInvariant();

    /// <summary>First 16 bytes, uppercase hex, 8 groups of 4: "A0A1 A2A3 …".</summary>
    public static string Display(ReadOnlySpan<byte> fp) => Group(Convert.ToHexString(fp[..16]));

    /// <summary>All 32 bytes, 16 groups of 4, for the "details" view.</summary>
    public static string DisplayFull(ReadOnlySpan<byte> fp) => Group(Convert.ToHexString(fp));

    private static string Group(string hex) =>
        string.Join(' ', Enumerable.Range(0, hex.Length / 4).Select(i => hex.Substring(i * 4, 4)));

    /// <summary>True when the certificate carries an ECDSA P-256 public key.</summary>
    public static bool IsP256(X509Certificate2 cert)
    {
        try
        {
            using var ec = cert.GetECDsaPublicKey();
            if (ec is null || ec.KeySize != 256) return false;
            var curve = ec.ExportParameters(false).Curve;
            return curve.Oid.Value == "1.2.840.10045.3.1.7"
                || curve.Oid.FriendlyName is "nistP256" or "ECDSA_P256" or "secp256r1";
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
