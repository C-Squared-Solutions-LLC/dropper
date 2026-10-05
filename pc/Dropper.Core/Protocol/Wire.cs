namespace Dropper.Core.Protocol;

/// <summary>Constants from docs/PROTOCOL.md §12.</summary>
public static class Wire
{
    public const int DefaultPort = 47823;
    public const int DiscoveryPort = 47823;
    public const int ProtocolVersion = 1;
    public const string AppVersion = "1.0.2";

    public const int PreambleLength = 61;
    public const byte ModeSession = 0x01;
    public const byte ModePairing = 0x02;

    public const int MaxFrameBody = 1_048_576;
    public const int MaxJson = 65_536;
    public const int SendChunk = 262_144;
    public const long MaxTextBytes = 4_194_304;
    public const long MaxFileBytes = 64L * 1024 * 1024 * 1024;
    public const int MaxNameChars = 255;
    public const int MaxDeviceNameChars = 64;

    public static readonly TimeSpan PreambleTimeout = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(120);
    public static readonly TimeSpan AcceptTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan ResultTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan StallTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan PairRequestTimeout = TimeSpan.FromSeconds(15);
    public const long ClockSkewMs = 600_000;
    public static readonly TimeSpan ReplayWindow = TimeSpan.FromMinutes(20);
    public static readonly TimeSpan PairingWindow = TimeSpan.FromSeconds(180);
    public static readonly TimeSpan ApprovalTimeout = TimeSpan.FromSeconds(120);
    public const int MaxPairingFailures = 5;
    public const int MaxPreAuthConnections = 16;
    public const int MaxPreAuthPerIp = 2;
    public const int CompletedIdMemory = 500;
    public const int MaxAttempts = 3;

    /// <summary>
    /// |now − ts| ≤ ClockSkewMs, written as two comparisons: subtracting an
    /// attacker-chosen timestamp could overflow (Math.Abs(long.MinValue) throws).
    /// </summary>
    public static bool IsFresh(long tsMs, DateTimeOffset now)
    {
        long nowMs = now.ToUnixTimeMilliseconds();
        return tsMs >= nowMs - ClockSkewMs && tsMs <= nowMs + ClockSkewMs;
    }
}

public enum FrameType : byte
{
    Hello = 0x01,
    Ping = 0x02,
    Pong = 0x03,
    Bye = 0x04,
    Offer = 0x10,
    Accept = 0x11,
    Reject = 0x12,
    Data = 0x13,
    End = 0x14,
    Result = 0x15,
    Cancel = 0x16,
    PairRequest = 0x20,
    PairOk = 0x21,
    PairFail = 0x22,
}

/// <summary>A peer broke the protocol. The connection is closed immediately.</summary>
public sealed class ProtocolException(string message) : Exception(message);
