using System.Net.Security;
using System.Security.Authentication;

namespace Dropper.Core.Protocol;

/// <summary>
/// Which TLS versions a connection may use (docs/PROTOCOL.md §6.2).
///
/// TLS 1.3 is the rule. TLS 1.2 exists only because Windows 10's SChannel has no
/// TLS 1.3, and it is never automatic: a PC-to-PC pairing that can only run TLS 1.2
/// needs the user on each PC to allow it, and that consent is stored per device.
/// Phones, strangers and every other device stay TLS 1.3 only.
/// </summary>
public static class TlsPolicy
{
    /// <summary>Windows 11 and Server 2022 (build 20348) and later have TLS 1.3 in SChannel.</summary>
    public static bool OsHasTls13 { get; } = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348);

    /// <summary>
    /// What to offer: TLS 1.3, plus TLS 1.2 only when it was allowed for this connection.
    /// Null means nothing is allowed, so don't handshake at all. (Never pass
    /// <see cref="SslProtocols.None"/>: to .NET that means "whatever the OS likes".)
    /// </summary>
    public static SslProtocols? Offer(bool allowTls12, bool tls13Available)
    {
        var p = SslProtocols.None;
        if (tls13Available) p |= SslProtocols.Tls13;
        if (allowTls12) p |= SslProtocols.Tls12;
        return p == SslProtocols.None ? null : p;
    }

    /// <summary>TLS 1.2 suites we accept: ephemeral ECDH, ECDSA keys, AEAD only.</summary>
    private static readonly HashSet<TlsCipherSuite> Tls12Suites =
    [
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    /// <summary>Checked after every handshake, whatever was offered.</summary>
    public static bool IsAcceptable(SslProtocols negotiated, TlsCipherSuite suite, bool allowTls12) => negotiated switch
    {
        SslProtocols.Tls13 => true,
        SslProtocols.Tls12 => allowTls12 && Tls12Suites.Contains(suite),
        _ => false,
    };

    public static bool IsAcceptable(SslStream ssl, bool allowTls12) =>
        IsAcceptable(ssl.SslProtocol, ssl.NegotiatedCipherSuite, allowTls12);
}
