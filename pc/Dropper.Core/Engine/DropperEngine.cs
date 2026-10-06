using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dropper.Core.Crypto;
using Dropper.Core.Net;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;

namespace Dropper.Core.Engine;

/// <summary>
/// Everything the UI talks to: identity, pairing, the TLS server, discovery,
/// the outbox and the activity history. Thread-safe; events fire on worker
/// threads, so UI handlers must marshal to their dispatcher.
/// </summary>
public sealed partial class DropperEngine : IAsyncDisposable
{
    private readonly EngineOptions _options;
    private readonly object _gate = new();
    private readonly ConfigStore _configStore;
    private readonly ActivityStore _activity;
    private readonly ReplayCache _replay = new(Wire.ReplayWindow);
    private readonly Dictionary<string, PairedDevice> _devices = new();
    private readonly Dictionary<string, Session> _sessions = new();
    private readonly LinkedList<string> _completedIncoming = new();
    private readonly HashSet<string> _completedIncomingSet = new();
    private readonly Dictionary<string, long> _progressStamp = new();
    private const long MaxLogBytes = 2_000_000;
    private readonly object _logGate = new();
    private readonly Dictionary<IPAddress, DateTimeOffset> _logThrottle = new();
    private StreamWriter? _logFile;
    private AppConfig _config = new();
    private Identity? _identity;
    private Server? _server;
    private DiscoveryResponder? _discovery;
    private PairingTicket? _ticket;
    private IReadOnlyList<LanAddress> _lans = Array.Empty<LanAddress>();
    private Timer? _networkDebounce;
    private bool _started;

    public DropperEngine(EngineOptions options)
    {
        _options = options;
        Directory.CreateDirectory(options.DataDirectory);
        _configStore = new ConfigStore(Path.Combine(options.DataDirectory, "config.json"));
        _activity = new ActivityStore(Path.Combine(options.DataDirectory, "activity.dat"));
        try
        {
            string logPath = Path.Combine(options.DataDirectory, "dropper.log");
            if (File.Exists(logPath) && new FileInfo(logPath).Length > 1_000_000)
                File.Move(logPath, logPath + ".old", overwrite: true);
            _logFile = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        }
        catch (IOException) { _logFile = null; }
    }

    // ------------------------------------------------------------------ events

    public event Action<ActivityItem>? ItemAdded;
    public event Action<ActivityItem>? ItemChanged;
    public event Action<ActivityItem>? ItemRemoved;
    /// <summary>An incoming item finished successfully (show a notification, auto-copy text...).</summary>
    public event Action<ActivityItem>? ItemReceived;
    public event Action? DevicesChanged;
    public event Action? NetworkChanged;
    public event Action<PairingRequest>? PairingRequested;
    public event Action<PairingOutcome>? PairingCompleted;
    public event Action<string>? LogWritten;

    // ------------------------------------------------------------------ state

    public string PcName => _options.PcName;
    public Identity Identity => _identity ?? throw new InvalidOperationException("Engine not started");
    public AppConfig Config { get { lock (_gate) return _config; } }
    public DateTimeOffset Now => _options.Clock();
    public int Port => _options.PortOverride ?? _config.Port;
    public string? NetworkError { get; private set; }
    public IReadOnlyList<LanAddress> Lans { get { lock (_gate) return _lans; } }
    public string DataDirectory => _options.DataDirectory;

    public string ReceiveFolder =>
        _options.ReceiveFolderOverride
        ?? (string.IsNullOrWhiteSpace(_config.ReceiveFolder)
            ? Path.Combine(KnownFolders.GetDownloads(), "Dropper")
            : _config.ReceiveFolder);

    public bool IsListening { get { lock (_gate) return _server is not null; } }

    // ------------------------------------------------------------------ lifecycle

    public async Task StartAsync()
    {
        if (_started) throw new InvalidOperationException("Already started");
        _started = true;
        _config = _configStore.Load();
        _identity = await Task.Run(() => Identity.LoadOrCreate(
            Path.Combine(_options.DataDirectory, "identity.cer"), _options.KeyName, _options.AllowTpm, Log)).ConfigureAwait(false);
        Log($"Identity {Fingerprint.Display(_identity.Fingerprint)} ({_identity.StorageDescription})");

        LoadDevices();
        _activity.Load(Log);
        foreach (var i in _activity.Where(i => i.Direction == Direction.Incoming && i.State == ItemState.Received))
            RememberCompleted(i.Id);
        CleanupTemp();

        await StartNetworkAsync().ConfigureAwait(false);
        if (_options.ListenOverride is null)
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
        StartOutboundLoops();
    }

    private void LoadDevices()
    {
        lock (_gate)
        {
            _devices.Clear();
            foreach (var rec in _config.Devices)
            {
                try
                {
                    var secret = Dpapi.Unprotect(Convert.FromBase64String(rec.SecretProtected));
                    _devices[rec.Fp] = new PairedDevice(rec, secret);
                    CryptographicOperations.ZeroMemory(secret);
                }
                catch (Exception ex) when (ex is CryptographicException or FormatException)
                {
                    Log($"Paired device '{rec.Name}' can't be decrypted on this account; it must pair again");
                }
            }
        }
    }

    private void CleanupTemp()
    {
        try
        {
            if (Directory.Exists(ReceiveFolder))
                foreach (var f in Directory.EnumerateFiles(ReceiveFolder, ".dropper-*.partial"))
                    try { File.Delete(f); } catch (IOException) { }

            string tmp = Path.Combine(_options.DataDirectory, "tmp");
            if (Directory.Exists(tmp))
            {
                var keep = _activity.Where(i => i.IsPending && i.IsTemp && i.LocalPath is not null)
                    .Select(i => Path.GetDirectoryName(i.LocalPath!)!).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var d in Directory.EnumerateDirectories(tmp))
                    if (!keep.Contains(d))
                        try { Directory.Delete(d, recursive: true); } catch (IOException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private async Task StartNetworkAsync()
    {
        var scan = _options.ListenOverride is { } fixedLans
            ? new LanInterfaces.Scan(fixedLans, Array.Empty<string>())
            : LanInterfaces.Discover(_config.InterfaceOverride);
        var lans = scan.Addresses;
        Server? server = null;
        DiscoveryResponder? discovery = null;
        string? error = null;

        if (lans.Count == 0 && scan.SkippedPublicNetworks.Count > 0)
        {
            error = $"Your network “{string.Join("”, “", scan.SkippedPublicNetworks.Distinct())}” is set to Public in Windows, so Dropper won't listen on it. " +
                    "If it's your home network, set it to Private: Settings › Network & internet › your connection › Private network.";
        }
        else if (lans.Count == 0)
        {
            error = "No local network found. Connect this PC to your home Wi-Fi or Ethernet.";
        }
        else
        {
            try
            {
                server = new Server(this, Identity.Certificate);
                server.Start(lans, Port);
            }
            catch (SocketException ex)
            {
                if (server is not null) await server.DisposeAsync().ConfigureAwait(false);
                server = null;
                error = ex.SocketErrorCode == SocketError.AddressAlreadyInUse
                    ? $"Port {Port} is already in use. Pick another port in Settings."
                    : $"Can't listen on port {Port} ({ex.SocketErrorCode}).";
            }

            if (server is not null && _options.EnableDiscovery)
            {
                try
                {
                    discovery = new DiscoveryResponder(this);
                    discovery.Start(_options.DiscoveryBindAddress, _options.DiscoveryPort);
                }
                catch (SocketException ex)
                {
                    if (discovery is not null) await discovery.DisposeAsync().ConfigureAwait(false);
                    discovery = null;
                    Log($"Discovery disabled: UDP port {_options.DiscoveryPort} unavailable ({ex.SocketErrorCode})");
                }
            }
        }

        lock (_gate)
        {
            _lans = server is null ? Array.Empty<LanAddress>() : lans;
            _server = server;
            _discovery = discovery;
            NetworkError = error;
        }
        Log(error ?? $"Listening on {string.Join(", ", lans.Select(l => $"{l.Address}:{Port}"))}");
        Raise(NetworkChanged);
    }

    private async Task StopNetworkAsync()
    {
        Server? server;
        DiscoveryResponder? discovery;
        lock (_gate)
        {
            server = _server;
            discovery = _discovery;
            _server = null;
            _discovery = null;
            _lans = Array.Empty<LanAddress>();
        }
        if (server is not null) await server.DisposeAsync().ConfigureAwait(false);
        if (discovery is not null) await discovery.DisposeAsync().ConfigureAwait(false);
    }

    public async Task RestartNetworkAsync()
    {
        await StopNetworkAsync().ConfigureAwait(false);
        await StartNetworkAsync().ConfigureAwait(false);
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        _networkDebounce?.Dispose();
        _networkDebounce = new Timer(async _ =>
        {
            var fresh = LanInterfaces.Discover(_config.InterfaceOverride).Addresses;
            bool changed;
            lock (_gate)
                changed = NetworkError is not null || !fresh.Select(l => l.ToString()).SequenceEqual(_lans.Select(l => l.ToString()));
            if (!changed) return;
            Log("Network changed; restarting listeners");
            KickOutbound();
            try { await RestartNetworkAsync().ConfigureAwait(false); }
            catch (Exception ex) { Log($"Network restart failed: {ex.Message}"); }
        }, null, 2000, Timeout.Infinite);
    }

    public async ValueTask DisposeAsync()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        _networkDebounce?.Dispose();
        StopAllOutbound();
        List<Session> sessions;
        lock (_gate) sessions = _sessions.Values.ToList();
        await Task.WhenAll(sessions.Select(s => s.SayByeAsync("shutdown"))).ConfigureAwait(false);
        await StopNetworkAsync().ConfigureAwait(false);
        _activity.FlushIfDirty();
        _identity?.Dispose();
        _logFile?.Dispose();
    }

    // ------------------------------------------------------------------ config

    public void UpdateConfig(Action<AppConfig> change)
    {
        bool networkChanged;
        lock (_gate)
        {
            int port = _config.Port;
            string? iface = _config.InterfaceOverride;
            change(_config);
            _config.Port = Math.Clamp(_config.Port, 1024, 65535);
            networkChanged = port != _config.Port || iface != _config.InterfaceOverride;
            _configStore.Save(_config);
        }
        if (networkChanged) _ = RestartNetworkAsync();
    }

    // ------------------------------------------------------------------ devices

    /// <summary>Devices that connect TO this PC (phones, and PCs that paired with us as the joiner).</summary>
    internal IReadOnlyList<PairedDevice> PairedDevicesSnapshot()
    {
        lock (_gate) return _devices.Values.Where(d => !d.Record.Outbound).ToList();
    }

    internal bool IsPaired(PairedDevice device)
    {
        lock (_gate) return _devices.TryGetValue(device.FpHex, out var d) && ReferenceEquals(d, device);
    }

    public IReadOnlyList<DeviceStatus> GetDevices()
    {
        lock (_gate)
        {
            return _devices.Values
                .OrderBy(d => d.Record.PairedAt)
                .Select(d =>
                {
                    _sessions.TryGetValue(d.FpHex, out var s);
                    return new DeviceStatus(d.FpHex, d.Record.Name, d.Record.Model,
                        s?.PeerHello is not null, s?.Remote.Address.ToString(), d.Record.LastSeen,
                        d.Record.PairedAt, Fingerprint.Display(d.Fp), d.Record.Kind, d.Record.Tls12Allowed);
                })
                .ToList();
        }
    }

    internal PairedDevice AddDevice(X509Certificate2 cert, byte[] fp, string name, string model, byte[] deviceSecret,
        string kind = "phone", bool outbound = false, IEnumerable<string>? addresses = null, bool tls12Allowed = false)
    {
        string fpHex = Fingerprint.Hex(fp);
        var rec = new DeviceRecord
        {
            Fp = fpHex,
            CertDer = Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
            Name = name,
            Model = model,
            SecretProtected = Convert.ToBase64String(Dpapi.Protect(deviceSecret)),
            PairedAt = Now,
            Kind = kind,
            Outbound = outbound,
            Addresses = addresses?.ToList() ?? new(),
            Tls12Allowed = tls12Allowed,
        };
        PairedDevice added;
        List<Session> replaced = new();
        lock (_gate)
        {
            // A device that re-pairs (e.g. after reinstalling the app) has a new key; drop the stale
            // entry of the same kind and direction.
            foreach (var old in _config.Devices.Where(d => d.Fp == fpHex ||
                         (string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase) && d.Kind == kind && d.Outbound == outbound)).ToList())
            {
                _config.Devices.Remove(old);
                _devices.Remove(old.Fp);
                if (_sessions.TryGetValue(old.Fp, out var s)) replaced.Add(s);
            }
            _config.Devices.Add(rec);
            added = new PairedDevice(rec, deviceSecret);
            _devices[fpHex] = added;
            _configStore.Save(_config);
        }
        foreach (var s in replaced) s.Close("replaced by a new pairing");
        Log($"Paired with '{name}' ({Fingerprint.Display(fp)})");
        Raise(DevicesChanged);
        return added;
    }

    public async Task RemoveDeviceAsync(string fpHex)
    {
        var session = ForgetDevice(fpHex, "Removed a paired phone");
        if (session is not null) await session.SayByeAsync("unpaired").ConfigureAwait(false);
    }

    /// <summary>
    /// Drops the device record and fails its pending items. Returns the session that was
    /// live at that moment (if any) for the caller to close. The record and the session
    /// are read under the same lock that session registration takes, so no session for
    /// this device can start afterwards.
    /// </summary>
    internal Session? ForgetDevice(string fpHex, string logMessage)
    {
        bool removed;
        Session? session;
        lock (_gate)
        {
            removed = _config.Devices.RemoveAll(d => d.Fp == fpHex) > 0;
            _devices.Remove(fpHex);
            _sessions.TryGetValue(fpHex, out session);
            if (removed) _configStore.Save(_config);
        }
        StopOutbound(fpHex);
        if (!removed) return session;
        foreach (var item in _activity.Where(i => i.DeviceFp == fpHex && i.IsPending))
            FailItem(item, "Device was unpaired");
        Log(logMessage);
        Raise(DevicesChanged);
        return session;
    }

    /// <summary>Deletes this PC's identity key. All phones must pair again. Restart the engine afterwards.</summary>
    public async Task ResetIdentityAsync()
    {
        foreach (var d in GetDevices()) await RemoveDeviceAsync(d.FpHex).ConfigureAwait(false);
        await StopNetworkAsync().ConfigureAwait(false);
        _identity?.Dispose();
        Identity.Delete(Path.Combine(_options.DataDirectory, "identity.cer"), _options.KeyName);
        _identity = Identity.LoadOrCreate(Path.Combine(_options.DataDirectory, "identity.cer"), _options.KeyName, _options.AllowTpm, Log);
        await StartNetworkAsync().ConfigureAwait(false);
        Raise(DevicesChanged);
    }

    // ------------------------------------------------------------------ pairing

    public IReadOnlyList<IPEndPoint> AdvertisedEndpoints()
    {
        lock (_gate) return _lans.Select(l => new IPEndPoint(l.Advertised, Port)).Distinct().Take(4).ToList();
    }

    /// <summary>Opens a 3-minute, single-use pairing window and returns the QR payload.</summary>
    /// <summary>False on Windows 10, whose SChannel has no TLS 1.3.</summary>
    public bool Tls13Available => TlsPolicy.OsHasTls13 && !_options.SimulateNoTls13;

    public PairingTicket StartPairing()
    {
        // Phones only speak TLS 1.3, which Windows 10 doesn't have.
        if (!Tls13Available)
            throw new InvalidOperationException("Pairing a phone needs Windows 11: phones use TLS 1.3 only, and Windows 10 doesn't support it. You can still pair this PC with another PC.");
        var endpoints = AdvertisedEndpoints();
        if (endpoints.Count == 0) throw new InvalidOperationException(NetworkError ?? "Not connected to a local network.");
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var ticket = new PairingTicket(secret,
            PairingUri.Build(endpoints, Identity.Fingerprint, secret, PcName),
            Now + Wire.PairingWindow);
        CryptographicOperations.ZeroMemory(secret);
        lock (_gate)
        {
            if (_ticket is not null) _ticket.Closed = true;
            _ticket = ticket;
        }
        Log("Pairing window opened");
        return ticket;
    }

    public void CancelPairing()
    {
        lock (_gate)
        {
            if (_ticket is not null) _ticket.Closed = true;
            _ticket = null;
        }
    }

    /// <summary>Returns null if the ticket was consumed by this valid request, else a PAIR_FAIL reason.</summary>
    internal string? TryConsumeTicket(PairingTicket ticket, bool proofValid)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(_ticket, ticket) || !ticket.IsOpen(Now)) return "expired";
            if (!proofValid)
            {
                if (++ticket.Failures >= Wire.MaxPairingFailures) ticket.Closed = true;
                return "bad_proof";
            }
            ticket.Consumed = true;
            return null;
        }
    }

    internal void RaisePairingRequested(PairingRequest r)
    {
        Log($"Pairing request from '{r.DeviceName}' at {r.From}");
        Raise(PairingRequested, r);
    }

    internal void RaisePairingCompleted(PairingOutcome o) => Raise(PairingCompleted, o);

    // ------------------------------------------------------------------ gate

    internal GateDecision CheckGate(byte[] preamble, IPAddress ip)
    {
        if (!Preamble.TryParse(preamble, out byte mode, out long ts, out byte[] nonce))
            return GateDecision.Fail("not a Dropper connection");
        var now = Now;
        if (!Wire.IsFresh(ts, now))
            return GateDecision.Fail($"clock difference of {((double)now.ToUnixTimeMilliseconds() - ts) / 1000:0} s (check the phone's and PC's time)");

        if (mode == Wire.ModeSession)
        {
            foreach (var device in PairedDevicesSnapshot())
            {
                if (!Preamble.VerifyMac(preamble, device.GateKey)) continue;
                if (!_replay.TryAdd(nonce, now)) return GateDecision.Fail("replayed connection attempt");
                return new GateDecision(true, mode, device, null, "");
            }
            return GateDecision.Fail("unknown device");
        }

        if (mode == Wire.ModePcPairing)
        {
            if (!PcPairingOpen(now)) return GateDecision.Fail("PC pairing attempt while no PC pairing window is open");
            if (!Preamble.VerifyMac(preamble, Kdf.PcPairingGateKey)) return GateDecision.Fail("malformed PC pairing greeting");
            if (!_replay.TryAdd(nonce, now)) return GateDecision.Fail("replayed PC pairing attempt");
            return new GateDecision(true, mode, null, null, "");
        }

        PairingTicket? ticket;
        lock (_gate) ticket = _ticket;
        if (ticket is null || !ticket.IsOpen(now)) return GateDecision.Fail("pairing attempt while no pairing window is open");
        if (!Preamble.VerifyMac(preamble, ticket.GateKey)) return GateDecision.Fail("pairing attempt with the wrong code");
        if (!_replay.TryAdd(nonce, now)) return GateDecision.Fail("replayed pairing attempt");
        return new GateDecision(true, mode, null, ticket, "");
    }

    internal LanAddress? FindLanFor(IPAddress ip)
    {
        lock (_gate) return _lans.FirstOrDefault(l => l.Contains(ip));
    }

    /// <summary>The LAN a UDP packet belongs to: sender on its subnet AND received on its adapter.</summary>
    internal LanAddress? FindLanFor(IPAddress source, int arrivedOnInterface)
    {
        lock (_gate)
            return _lans.FirstOrDefault(l => l.Contains(source) && (l.InterfaceIndex < 0 || l.InterfaceIndex == arrivedOnInterface));
    }

    // ------------------------------------------------------------------ sessions

    internal async Task RunSessionAsync(TcpClient tcp, SslStream ssl, PairedDevice device, IPEndPoint remote, bool clientRole = false)
    {
        var session = new Session(this, tcp, ssl, device, remote, clientRole);
        Session? previous = null;
        bool stillPaired;
        lock (_gate)
        {
            // Re-check under the lock ForgetDevice takes: an unpair that raced with this
            // handshake must win.
            stillPaired = _devices.TryGetValue(device.FpHex, out var current) && ReferenceEquals(current, device);
            if (stillPaired)
            {
                _sessions.TryGetValue(device.FpHex, out previous);
                _sessions[device.FpHex] = session;
            }
        }
        if (!stillPaired)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            tcp.Dispose();
            return;
        }
        previous?.Close("replaced by a newer connection");
        await session.RunAsync().ConfigureAwait(false);
    }

    internal void OnSessionReady(Session session)
    {
        lock (_gate)
        {
            session.Device.Record.LastSeen = Now;
            if (session.PeerHello is { } hello && hello.Name.Length > 0 && hello.Name != session.Device.Record.Name)
                session.Device.Record.Name = hello.Name;
            _configStore.Save(_config);
        }
        Log($"'{session.Device.Record.Name}' connected from {session.Remote.Address}");
        Raise(DevicesChanged);
    }

    internal void OnSessionEnded(Session session)
    {
        bool wasCurrent;
        lock (_gate)
        {
            wasCurrent = _sessions.TryGetValue(session.Device.FpHex, out var s) && ReferenceEquals(s, session);
            if (wasCurrent) _sessions.Remove(session.Device.FpHex);
            if (session.PeerHello is not null) session.Device.Record.LastSeen = Now;
        }
        // Whatever was mid-send goes back in the queue (or fails after too many tries).
        foreach (var item in _activity.Where(i => i.DeviceFp == session.Device.FpHex && i.State == ItemState.Sending))
            RetryOrFail(item, "Connection lost");
        if (session.PeerHello is not null)
            Log($"'{session.Device.Record.Name}' disconnected ({session.EndReason})");
        Raise(DevicesChanged);
    }

    private void SignalSession(string deviceFp)
    {
        Session? s;
        lock (_gate) _sessions.TryGetValue(deviceFp, out s);
        s?.SignalOutbox();
    }

    // ------------------------------------------------------------------ outbox (UI side)

    public IReadOnlyList<ActivityItem> GetActivity() => _activity.Snapshot();

    private string ResolveTarget(string? deviceFp)
    {
        lock (_gate)
        {
            if (deviceFp is not null)
                return _devices.ContainsKey(deviceFp) ? deviceFp : throw new InvalidOperationException("That phone is no longer paired.");
            if (_devices.Count == 0) throw new InvalidOperationException("No phone is paired yet. Pair your phone first.");
            var connected = _devices.Values.FirstOrDefault(d => _sessions.ContainsKey(d.FpHex));
            return (connected ?? _devices.Values.OrderByDescending(d => d.Record.LastSeen ?? d.Record.PairedAt).First()).FpHex;
        }
    }

    private string DeviceName(string fp)
    {
        lock (_gate) return _devices.TryGetValue(fp, out var d) ? d.Record.Name : "Phone";
    }

    public ActivityItem QueueText(string text, string? deviceFp = null)
    {
        if (string.IsNullOrEmpty(text)) throw new ArgumentException("Nothing to send.");
        long bytes = Encoding.UTF8.GetByteCount(text);
        if (bytes > Wire.MaxTextBytes) throw new ArgumentException("That text is too long (4 MB max). Save it to a file and send the file instead.");
        string target = ResolveTarget(deviceFp);
        var item = new ActivityItem
        {
            Id = NewId(),
            Direction = Direction.Outgoing,
            Kind = ItemKind.Text,
            Text = text,
            Size = bytes,
            Mime = "text/plain",
            DeviceFp = target,
            DeviceName = DeviceName(target),
            Created = Now,
            State = ItemState.Queued,
        };
        AddItem(item);
        SignalSession(target);
        return item;
    }

    /// <summary>Queues files; folders are zipped first. <paramref name="temporary"/> files are deleted after delivery.</summary>
    public IReadOnlyList<ActivityItem> QueueFiles(IEnumerable<string> paths, string? deviceFp = null, bool temporary = false)
    {
        string target = ResolveTarget(deviceFp);
        var items = new List<ActivityItem>();
        foreach (var raw in paths)
        {
            string path;
            try { path = Path.GetFullPath(raw); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { continue; }

            var item = new ActivityItem
            {
                Id = NewId(),
                Direction = Direction.Outgoing,
                Kind = ItemKind.File,
                DeviceFp = target,
                DeviceName = DeviceName(target),
                Created = Now,
                IsTemp = temporary,
            };

            if (Directory.Exists(path))
            {
                string folderName = new DirectoryInfo(path).Name;
                item.Name = FileNames.Sanitize(folderName) + ".zip";
                item.Mime = "application/zip";
                item.State = ItemState.Preparing;
                AddItem(item);
                _ = Task.Run(() => ZipFolder(item, path));
            }
            else if (File.Exists(path))
            {
                var fi = new FileInfo(path);
                item.Name = fi.Name;
                item.Mime = Mime.FromName(fi.Name);
                item.LocalPath = fi.FullName;
                item.Size = fi.Length;
                item.State = ItemState.Queued;
                AddItem(item);
            }
            else
            {
                continue;
            }
            items.Add(item);
        }
        SignalSession(target);
        return items;
    }

    private void ZipFolder(ActivityItem item, string folder)
    {
        try
        {
            string dir = Path.Combine(_options.DataDirectory, "tmp", item.Id);
            Directory.CreateDirectory(dir);
            string zip = Path.Combine(dir, item.Name);
            ZipFile.CreateFromDirectory(folder, zip, CompressionLevel.Fastest, includeBaseDirectory: true);
            _activity.Update(item, i =>
            {
                i.LocalPath = zip;
                i.Size = new FileInfo(zip).Length;
                i.IsTemp = true;
                if (i.State == ItemState.Preparing) i.State = ItemState.Queued;
            });
            Raise(ItemChanged, item);
            SignalSession(item.DeviceFp);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            FailItem(item, "Couldn't zip the folder: " + ex.Message);
        }
    }

    public void Retry(string id)
    {
        var item = _activity.Find(id);
        if (item is null || item.Direction != Direction.Outgoing || item.State is not (ItemState.Failed or ItemState.Cancelled)) return;
        if (item.Kind == ItemKind.File && (item.LocalPath is null || !File.Exists(item.LocalPath)))
        {
            FailItem(item, "The file no longer exists");
            return;
        }
        lock (_gate)
            if (!_devices.ContainsKey(item.DeviceFp)) return;
        _activity.Update(item, i =>
        {
            i.State = ItemState.Queued;
            i.Attempts = 0;
            i.Error = null;
            i.Transferred = 0;
        });
        Raise(ItemChanged, item);
        SignalSession(item.DeviceFp);
    }

    /// <summary>Removes an item from the list. A queued item is cancelled; one being sent right now can't be.</summary>
    public bool RemoveItem(string id)
    {
        var item = _activity.Find(id);
        if (item is null || item.State is ItemState.Sending or ItemState.Receiving) return false;
        _activity.Remove(id);
        if (item.IsTemp && item.LocalPath is not null) DeleteTemp(item.LocalPath);
        Raise(ItemRemoved, item);
        return true;
    }

    public void ClearFinished()
    {
        foreach (var item in _activity.Where(i => !i.IsPending)) RemoveItem(item.Id);
    }

    // ------------------------------------------------------------------ outbox (session side)

    internal ActivityItem? NextOutgoing(string deviceFp) => _activity.NextQueued(deviceFp);

    internal void BeginSend(ActivityItem item, long size)
    {
        _activity.Update(item, i =>
        {
            i.State = ItemState.Sending;
            i.Attempts++;
            i.Size = size;
            i.Transferred = 0;
            i.Error = null;
        });
        Raise(ItemChanged, item);
    }

    internal void CompleteOutgoing(ActivityItem item)
    {
        _activity.Update(item, i =>
        {
            i.State = ItemState.Delivered;
            i.Transferred = i.Size;
            i.Error = null;
        });
        if (item.IsTemp && item.LocalPath is not null) DeleteTemp(item.LocalPath);
        ForgetProgress(item);
        Raise(ItemChanged, item);
    }

    internal void RetryOrFail(ActivityItem item, string error)
    {
        _activity.Update(item, i =>
        {
            if (i.Attempts >= Wire.MaxAttempts)
            {
                i.State = ItemState.Failed;
                i.Error = error;
            }
            else
            {
                i.State = ItemState.Queued;
                i.Error = null;
            }
            i.Transferred = 0;
        });
        ForgetProgress(item);
        Raise(ItemChanged, item);
    }

    internal void FailItem(ActivityItem item, string error)
    {
        _activity.Update(item, i =>
        {
            i.State = ItemState.Failed;
            i.Error = error;
        });
        ForgetProgress(item);
        Raise(ItemChanged, item);
    }

    internal void ReportProgress(ActivityItem item, long transferred)
    {
        item.Transferred = transferred;
        long now = Stopwatch.GetTimestamp();
        lock (_progressStamp)
        {
            if (_progressStamp.TryGetValue(item.Id, out long last) && Stopwatch.GetElapsedTime(last, now).TotalMilliseconds < 200)
                return;
            _progressStamp[item.Id] = now;
        }
        Raise(ItemChanged, item);
    }

    private void ForgetProgress(ActivityItem item)
    {
        lock (_progressStamp) _progressStamp.Remove(item.Id);
    }

    private static void DeleteTemp(string path)
    {
        try
        {
            File.Delete(path);
            var dir = Path.GetDirectoryName(path);
            if (dir is not null && Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    // ------------------------------------------------------------------ incoming (session side)

    /// <summary>Returns a REJECT reason, or null to accept.</summary>
    internal string? CheckIncoming(OfferMessage offer)
    {
        lock (_completedIncoming)
            if (_completedIncomingSet.Contains(offer.Id)) return "duplicate";
        if (offer.Kind == ItemKind.Text && offer.Size > Wire.MaxTextBytes) return "too_large";
        if (offer.Kind == ItemKind.File)
        {
            if (offer.Size > Wire.MaxFileBytes) return "too_large";
            if (!HasFreeSpace(ReceiveFolder, offer.Size)) return "no_space";
        }
        return null;
    }

    private static bool HasFreeSpace(string folder, long size)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(folder));
            if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal)) return true;
            return new DriveInfo(root).AvailableFreeSpace > size + 64L * 1024 * 1024;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    internal ActivityItem BeginReceive(OfferMessage offer, PairedDevice device)
    {
        var existing = _activity.Where(i => i.Direction == Direction.Incoming && i.Id == offer.Id).FirstOrDefault();
        if (existing is not null)
        {
            _activity.Update(existing, i =>
            {
                i.State = ItemState.Receiving;
                i.Error = null;
                i.Transferred = 0;
            });
            Raise(ItemChanged, existing);
            return existing;
        }
        var item = new ActivityItem
        {
            Id = offer.Id,
            Direction = Direction.Incoming,
            Kind = offer.Kind,
            Name = offer.Kind == ItemKind.File ? FileNames.Sanitize(offer.Name) : "",
            Size = offer.Size,
            Mime = TextSafety.CleanDisplayName(offer.Mime, 127),
            DeviceFp = device.FpHex,
            DeviceName = device.Record.Name,
            Created = Now,
            State = ItemState.Receiving,
        };
        AddItem(item);
        return item;
    }

    internal void CompleteIncomingFile(ActivityItem item, string path, bool tagged)
    {
        if (!tagged) Log("Saved a file where Mark-of-the-Web isn't supported; Dropper won't offer to open it");
        _activity.Update(item, i =>
        {
            i.State = ItemState.Received;
            i.LocalPath = path;
            i.Name = Path.GetFileName(path);
            i.Transferred = i.Size;
            i.Tagged = tagged;
        });
        RememberCompleted(item.Id);
        ForgetProgress(item);
        Raise(ItemChanged, item);
        Raise(ItemReceived, item);
    }

    internal void CompleteIncomingText(ActivityItem item, string text)
    {
        _activity.Update(item, i =>
        {
            i.State = ItemState.Received;
            i.Text = text;
            i.Transferred = i.Size;
        });
        RememberCompleted(item.Id);
        ForgetProgress(item);
        Raise(ItemChanged, item);
        Raise(ItemReceived, item);
    }

    internal void CancelIncoming(ActivityItem item)
    {
        _activity.Update(item, i =>
        {
            i.State = ItemState.Cancelled;
            i.Error = "Cancelled by the phone";
        });
        ForgetProgress(item);
        Raise(ItemChanged, item);
    }

    private void RememberCompleted(string id)
    {
        lock (_completedIncoming)
        {
            if (!_completedIncomingSet.Add(id)) return;
            _completedIncoming.AddLast(id);
            while (_completedIncoming.Count > Wire.CompletedIdMemory)
            {
                _completedIncomingSet.Remove(_completedIncoming.First!.Value);
                _completedIncoming.RemoveFirst();
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private void AddItem(ActivityItem item)
    {
        _activity.Add(item);
        Raise(ItemAdded, item);
    }

    private static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public void Log(string message)
    {
        string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}";
        try
        {
            lock (_logGate)
            {
                if (_logFile is not null && _logFile.BaseStream.Length > MaxLogBytes) RotateLog();
                _logFile?.WriteLine(line);
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        Raise(LogWritten, line);
    }

    /// <summary>Logs at most one line per minute per IP, so a flood can't fill the disk.</summary>
    internal void LogThrottled(IPAddress ip, string message)
    {
        var now = Now;
        lock (_logGate)
        {
            if (_logThrottle.Count > 1024) _logThrottle.Clear();
            if (_logThrottle.TryGetValue(ip, out var last) && now - last < TimeSpan.FromMinutes(1)) return;
            _logThrottle[ip] = now;
        }
        Log(message);
    }

    private void RotateLog()
    {
        string path = Path.Combine(_options.DataDirectory, "dropper.log");
        _logFile!.Dispose();
        File.Move(path, path + ".old", overwrite: true);
        _logFile = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
    }

    private void Raise(Action? handler)
    {
        if (handler is null) return;
        try { handler(); } catch (Exception ex) { Trace.WriteLine(ex); }
    }

    private void Raise<T>(Action<T>? handler, T arg)
    {
        if (handler is null) return;
        try { handler(arg); } catch (Exception ex) { Trace.WriteLine(ex); }
    }
}
