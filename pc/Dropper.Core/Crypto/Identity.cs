using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dropper.Core.Crypto;

/// <summary>
/// The PC's long-term identity: a persisted, non-exportable ECDSA P-256 CNG key
/// (in the TPM when available) plus a self-signed certificate used as the TLS
/// server certificate. Phones pin the SHA-256 of its SubjectPublicKeyInfo.
/// </summary>
public sealed class Identity : IDisposable
{
    public const string TpmProviderName = "Microsoft Platform Crypto Provider";

    private readonly ECDsaCng _key;

    public X509Certificate2 Certificate { get; }
    public byte[] Fingerprint { get; }
    public bool HardwareBacked { get; }
    public string StorageDescription => HardwareBacked
        ? "TPM (hardware, non-exportable)"
        : "Windows key storage (DPAPI-protected, non-exportable)";

    private Identity(X509Certificate2 cert, ECDsaCng key, bool hardware)
    {
        Certificate = cert;
        _key = key;
        HardwareBacked = hardware;
        Fingerprint = Crypto.Fingerprint.Of(cert);
    }

    public static Identity LoadOrCreate(string certPath, string keyName, bool allowTpm, Action<string> log)
    {
        var existing = TryLoad(certPath, keyName, log);
        if (existing is not null) return existing;

        log("Creating a new identity key");
        Create(certPath, keyName, allowTpm, log);
        return TryLoad(certPath, keyName, log)
            ?? throw new CryptographicException("Identity key was created but could not be loaded back.");
    }

    /// <summary>Deletes the key and certificate. Every paired phone must pair again afterwards.</summary>
    public static void Delete(string certPath, string keyName)
    {
        foreach (var provider in Providers())
        {
            try
            {
                if (CngKey.Exists(keyName, provider))
                    using (var k = CngKey.Open(keyName, provider)) k.Delete();
            }
            catch (CryptographicException) { /* provider unavailable */ }
        }
        if (File.Exists(certPath)) File.Delete(certPath);
    }

    private static IEnumerable<CngProvider> Providers() =>
        new[] { new CngProvider(TpmProviderName), CngProvider.MicrosoftSoftwareKeyStorageProvider };

    private static Identity? TryLoad(string certPath, string keyName, Action<string> log)
    {
        if (!File.Exists(certPath)) return null;
        X509Certificate2 pub;
        try { pub = new X509Certificate2(File.ReadAllBytes(certPath)); }
        catch (CryptographicException ex) { log($"Identity certificate unreadable: {ex.Message}"); return null; }

        using (pub)
        {
            foreach (var provider in Providers())
            {
                try
                {
                    if (!CngKey.Exists(keyName, provider)) continue;
                    var key = new ECDsaCng(CngKey.Open(keyName, provider));
                    if (!key.ExportSubjectPublicKeyInfo().AsSpan()
                            .SequenceEqual(pub.PublicKey.ExportSubjectPublicKeyInfo()))
                    {
                        log("Identity key does not match the stored certificate");
                        key.Dispose();
                        continue;
                    }
                    var withKey = pub.CopyWithPrivateKey(key);
                    bool hw = provider.Provider == TpmProviderName;
                    return new Identity(withKey, key, hw);
                }
                catch (CryptographicException ex)
                {
                    log($"Could not open identity key in '{provider.Provider}': {ex.Message}");
                }
            }
        }
        return null;
    }

    private static void Create(string certPath, string keyName, bool allowTpm, Action<string> log)
    {
        CngKey? key = null;
        if (allowTpm)
        {
            try
            {
                key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, Params(new CngProvider(TpmProviderName)));
                log("Identity key created in the TPM");
            }
            catch (CryptographicException ex)
            {
                log($"TPM unavailable ({ex.Message}); using software key storage");
            }
        }
        key ??= CngKey.Create(CngAlgorithm.ECDsaP256, keyName, Params(CngProvider.MicrosoftSoftwareKeyStorageProvider));

        using var ecdsa = new ECDsaCng(key);
        var req = new CertificateRequest("CN=Dropper PC", ecdsa, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        using var cert = req.CreateSelfSigned(now.AddDays(-1), now.AddYears(20));
        var dir = Path.GetDirectoryName(certPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllBytes(certPath, cert.Export(X509ContentType.Cert));
    }

    private static CngKeyCreationParameters Params(CngProvider provider) => new()
    {
        Provider = provider,
        ExportPolicy = CngExportPolicies.None,
        KeyUsage = CngKeyUsages.Signing,
        KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
    };

    public void Dispose()
    {
        Certificate.Dispose();
        _key.Dispose();
    }
}
