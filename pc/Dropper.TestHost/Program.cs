// Headless Dropper engine for end-to-end tests against the Android emulator.
// NOT shipped. Listens on loopback only (the emulator reaches the host's loopback
// at 10.0.2.2) and auto-approves pairing, printing the SAS so a test can compare it.
//
//   dotnet run --project Dropper.TestHost -- [--data DIR] [--port 47823] [--discovery-port 47823] [--advertise 10.0.2.2] [--reject-pairing]
//
// Control it by dropping files into DIR/cmd/ (one command per file):
//   pair | text <message> | file <path> | status | unpair | quit
using System.Net;
using System.Security.Cryptography;
using Dropper.Core.Crypto;
using Dropper.Core.Engine;
using Dropper.Core.Net;
using Dropper.Core.Storage;

string data = Path.Combine(Path.GetTempPath(), "dropper-testhost");
int port = 47823;
int discoveryPort = 47823;
var advertise = IPAddress.Parse("10.0.2.2");
bool rejectPairing = false;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--data": data = args[++i]; break;
        case "--port": port = int.Parse(args[++i]); break;
        case "--discovery-port": discoveryPort = int.Parse(args[++i]); break;
        case "--advertise": advertise = IPAddress.Parse(args[++i]); break;
        case "--reject-pairing": rejectPairing = true; break;
    }
}

Directory.CreateDirectory(data);
string cmdDir = Path.Combine(data, "cmd");
Directory.CreateDirectory(cmdDir);
string uriFile = Path.Combine(data, "pairing-uri.txt");

void Out(string s) => Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {s}");

await using var engine = new DropperEngine(new EngineOptions
{
    DataDirectory = data,
    // One key per data folder, so parallel test hosts never overwrite each other's identity.
    KeyName = "Dropper-TestHost-" + Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(data).ToLowerInvariant())))[..12],
    AllowTpm = false,
    PcName = "TESTHOST",
    ListenOverride = [new LanAddress(IPAddress.Loopback, 8, "loopback", "lo") { Advertised = advertise }],
    PortOverride = port,
    DiscoveryPort = discoveryPort,
    DiscoveryBindAddress = IPAddress.Loopback,
    ReceiveFolderOverride = Path.Combine(data, "received"),
});

engine.LogWritten += l => Out("LOG " + l[20..]);
engine.DevicesChanged += () =>
{
    foreach (var d in engine.GetDevices())
        Out($"DEVICE name='{d.Name}' connected={d.Connected} from={d.RemoteAddress} fp={d.FingerprintDisplay}");
};
engine.PairingRequested += r =>
{
    Out($"PAIRING-REQUEST name='{r.DeviceName}' model='{r.Model}' sas={r.Sas} fp={r.Fingerprint}");
    if (rejectPairing) r.Reject(); else r.Approve();
};
engine.PairingCompleted += o => Out($"PAIRING-DONE success={o.Success} msg='{o.Message}'");
engine.ItemChanged += i =>
{
    if (i.State is ItemState.Sending or ItemState.Receiving) return;
    Out($"ITEM {i.Direction} {i.Kind} state={i.State} id={i.Id} size={i.Size} error={i.Error}");
};
engine.ItemReceived += i =>
{
    if (i.Kind == Dropper.Core.Protocol.ItemKind.Text)
        Out($"RECEIVED-TEXT id={i.Id} text='{i.Text}'");
    else
        Out($"RECEIVED-FILE id={i.Id} name='{i.Name}' size={i.Size} sha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(i.LocalPath!))).ToLowerInvariant()}");
};

await engine.StartAsync();
Out($"READY fp={Fingerprint.Display(engine.Identity.Fingerprint)} listening={engine.IsListening} error={engine.NetworkError}");

void NewPairing()
{
    var t = engine.StartPairing();
    File.WriteAllText(uriFile, t.Uri);
    Out("PAIRING-URI " + t.Uri);
}
NewPairing();

while (true)
{
    foreach (var f in Directory.GetFiles(cmdDir).OrderBy(f => f))
    {
        string cmd;
        try { cmd = File.ReadAllText(f).Trim(); File.Delete(f); }
        catch (IOException) { continue; }
        Out("CMD " + cmd);
        try
        {
            if (cmd == "quit") return;
            if (cmd == "pair") NewPairing();
            else if (cmd == "status")
                foreach (var i in engine.GetActivity()) Out($"STATUS {i.Direction} {i.Kind} {i.State} {i.Name} {i.Size} {i.Error}");
            else if (cmd == "unpair")
                foreach (var d in engine.GetDevices()) await engine.RemoveDeviceAsync(d.FpHex);
            else if (cmd.StartsWith("text ")) engine.QueueText(cmd[5..]);
            else if (cmd.StartsWith("file ")) engine.QueueFiles(new[] { cmd[5..].Trim('"') });
        }
        catch (Exception ex) { Out("CMD-ERROR " + ex.Message); }
    }
    await Task.Delay(200);
}
