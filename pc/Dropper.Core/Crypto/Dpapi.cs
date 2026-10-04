using System.Security.Cryptography;

namespace Dropper.Core.Crypto;

/// <summary>
/// Windows DPAPI, CurrentUser scope: blobs can only be decrypted by this Windows
/// account on this machine (or its roaming credential set).
/// </summary>
public static class Dpapi
{
    private static readonly byte[] Entropy = "Dropper/v1/dpapi"u8.ToArray();

    public static byte[] Protect(byte[] data) =>
        ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser);

    public static byte[] Unprotect(byte[] blob) =>
        ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.CurrentUser);
}
