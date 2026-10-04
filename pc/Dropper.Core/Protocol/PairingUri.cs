using System.Net;
using Dropper.Core.Crypto;

namespace Dropper.Core.Protocol;

/// <summary>Builds the QR payload from docs/PROTOCOL.md §5.</summary>
public static class PairingUri
{
    public static string Build(IEnumerable<IPEndPoint> addresses, ReadOnlySpan<byte> pcFp,
        ReadOnlySpan<byte> pairingSecret, string pcName)
    {
        var a = string.Join(',', addresses.Take(4).Select(e => $"{e.Address.MapToIPv4()}:{e.Port}"));
        string name = TextSafety.CleanDisplayName(pcName, 64);
        return "dropper://pair?v=1"
            + "&a=" + a
            + "&k=" + Base64Url.Encode(pcFp)
            + "&s=" + Base64Url.Encode(pairingSecret)
            + "&n=" + Uri.EscapeDataString(name);
    }
}
