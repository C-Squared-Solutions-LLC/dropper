using System.Net;
using Dropper.Core.Crypto;
using Dropper.Core.Net;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;

namespace Dropper.Core.Engine;

public sealed class EngineOptions
{
    public required string DataDirectory { get; init; }
    public string KeyName { get; init; } = "Dropper-Identity-v1";
    public bool AllowTpm { get; init; } = true;
    public string PcName { get; init; } = Environment.MachineName;

    /// <summary>Tests only: listen on these instead of the detected LAN interfaces.</summary>
    public IReadOnlyList<LanAddress>? ListenOverride { get; init; }
    public int? PortOverride { get; init; }
    public int DiscoveryPort { get; init; } = Wire.DiscoveryPort;
    /// <summary>UDP port other PCs answer discovery on (tests run several engines on one machine).</summary>
    public int PeerDiscoveryPort { get; init; } = Wire.DiscoveryPort;
    /// <summary>Tests only: behave like Windows 10, which has no TLS 1.3.</summary>
    public bool SimulateNoTls13 { get; init; }
    /// <summary>Tests only: bind discovery to loopback instead of all interfaces.</summary>
    public IPAddress DiscoveryBindAddress { get; init; } = IPAddress.Any;
    public bool EnableDiscovery { get; init; } = true;
    public string? ReceiveFolderOverride { get; init; }
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;
}

/// <summary>A paired phone with its decrypted per-device keys.</summary>
public sealed class PairedDevice
{
    internal PairedDevice(DeviceRecord record, byte[] deviceSecret)
    {
        Record = record;
        Fp = Convert.FromHexString(record.Fp);
        GateKey = Kdf.Hkdf32(deviceSecret, Kdf.GateInfo);
        DiscKey = Kdf.Hkdf32(deviceSecret, Kdf.DiscoveryInfo);
    }

    public DeviceRecord Record { get; }
    public byte[] Fp { get; }
    public string FpHex => Record.Fp;
    internal byte[] GateKey { get; }
    internal byte[] DiscKey { get; }
}

public sealed record DeviceStatus(
    string FpHex,
    string Name,
    string Model,
    bool Connected,
    string? RemoteAddress,
    DateTimeOffset? LastSeen,
    DateTimeOffset PairedAt,
    string FingerprintDisplay,
    string Kind = "phone",
    bool Tls12Allowed = false);

/// <summary>An open pairing window: the secret behind one QR code.</summary>
public sealed class PairingTicket
{
    internal PairingTicket(byte[] secret, string uri, DateTimeOffset expiresAt)
    {
        GateKey = Kdf.Hkdf32(secret, Kdf.PairGateInfo);
        ProofKey = Kdf.Hkdf32(secret, Kdf.PairProofInfo);
        SasKey = Kdf.Hkdf32(secret, Kdf.SasInfo);
        Uri = uri;
        ExpiresAt = expiresAt;
    }

    public string Uri { get; }
    public DateTimeOffset ExpiresAt { get; }
    internal byte[] GateKey { get; }
    internal byte[] ProofKey { get; }
    internal byte[] SasKey { get; }
    internal int Failures;
    internal bool Consumed;
    internal bool Closed;

    internal bool IsOpen(DateTimeOffset now) => !Consumed && !Closed && now < ExpiresAt;
}

/// <summary>A phone is asking to pair; the UI must call <see cref="Approve"/> or <see cref="Reject"/>.</summary>
public sealed class PairingRequest
{
    private readonly TaskCompletionSource<bool> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _abandoned = new();

    internal PairingRequest(string deviceName, string model, string sas, string fingerprint, IPAddress from,
        bool isPc = false, bool legacyTls = false)
    {
        DeviceName = deviceName;
        Model = model;
        Sas = sas;
        Fingerprint = fingerprint;
        From = from;
        IsPc = isPc;
        LegacyTls = legacyTls;
    }

    public string DeviceName { get; }
    public string Model { get; }
    /// <summary>Formatted "123 456"; the phone must be showing the same digits.</summary>
    public string Sas { get; }
    public string Fingerprint { get; }
    public IPAddress From { get; }
    /// <summary>True when another Dropper PC is asking; both sides compare the code.</summary>
    public bool IsPc { get; }
    /// <summary>
    /// The other PC can only do TLS 1.2 (Windows 10). Approving then also has to allow TLS 1.2
    /// for that PC, explicitly: <see cref="Approve(bool)"/> with true, or it counts as a rejection.
    /// </summary>
    public bool LegacyTls { get; }

    /// <summary>Fires if the phone disconnects or the approval times out, so the UI can close its prompt.</summary>
    public CancellationToken Abandoned => _abandoned.Token;

    public void Approve(bool allowLegacyTls = false) => _decision.TrySetResult(!LegacyTls || allowLegacyTls);
    public void Reject() => _decision.TrySetResult(false);

    internal Task<bool> Decision => _decision.Task;

    internal void Abandon()
    {
        _decision.TrySetResult(false);
        try { _abandoned.Cancel(); } catch (ObjectDisposedException) { }
    }
}

/// <summary>What the joiner's user is asked to confirm: the code, and whether TLS 1.2 would be needed.</summary>
public sealed record PcPairingCode(string Sas, bool LegacyTls);

public sealed record PairingOutcome(bool Success, string Message, string? DeviceName);

internal readonly record struct GateDecision(bool Ok, byte Mode, PairedDevice? Device, PairingTicket? Ticket, string Reason)
{
    public static GateDecision Fail(string reason) => new(false, 0, null, null, reason);
}
