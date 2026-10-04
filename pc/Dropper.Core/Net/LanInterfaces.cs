using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Dropper.Core.Net;

/// <summary>An IPv4 address on a LAN interface together with its subnet.</summary>
public sealed record LanAddress(IPAddress Address, int PrefixLength, string InterfaceName, string InterfaceId)
{
    /// <summary>Address to give out in the QR / HELLO / discovery (normally <see cref="Address"/>).</summary>
    public IPAddress Advertised { get; init; } = Address;

    /// <summary>IPv4 interface index, used to check which adapter a UDP packet arrived on (-1 = don't check).</summary>
    public int InterfaceIndex { get; init; } = -1;

    public bool Contains(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        uint mask = PrefixLength == 0 ? 0 : uint.MaxValue << (32 - PrefixLength);
        return (ToUInt(Address) & mask) == (ToUInt(ip) & mask);
    }

    public override string ToString() => $"{Address}/{PrefixLength} ({InterfaceName})";

    internal static uint ToUInt(IPAddress ip) =>
        BinaryPrimitives.ReadUInt32BigEndian(ip.MapToIPv4().GetAddressBytes());
}

/// <summary>
/// Finds the physical LAN interfaces Dropper may listen on. Virtual switches (WSL,
/// Hyper-V, Docker), overlay/VPN adapters (Tailscale, WireGuard, ZeroTier, OpenVPN)
/// and public addresses are excluded, so the service is only ever reachable from
/// the local network the user is physically on.
/// </summary>
public static partial class LanInterfaces
{
    [GeneratedRegex(
        @"virtual|hyper-v|vethernet|wsl|vmware|virtualbox|vbox|docker|tailscale|wireguard|zerotier|openvpn|" +
        @"\btap\b|tap-|\btun\b|wintun|vpn|loopback|bluetooth|npcap|hamachi|radmin|nordlynx|anyconnect|fortinet|pangp|teredo|isatap",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VirtualAdapter();

    private static readonly HashSet<NetworkInterfaceType> PhysicalTypes =
    [
        NetworkInterfaceType.Ethernet,
        NetworkInterfaceType.Wireless80211,
        NetworkInterfaceType.GigabitEthernet,
        NetworkInterfaceType.FastEthernetT,
        NetworkInterfaceType.FastEthernetFx,
        NetworkInterfaceType.Ethernet3Megabit,
    ];

    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168);
    }

    /// <summary>Result of looking for LAN addresses: what to use, and Public networks that were skipped.</summary>
    public sealed record Scan(IReadOnlyList<LanAddress> Addresses, IReadOnlyList<string> SkippedPublicNetworks);

    /// <summary>
    /// Usable LAN addresses. Interfaces with a default gateway come first; if none have
    /// one, the rest are used. Networks Windows marks Public are never used.
    /// </summary>
    public static Scan Discover(string? interfaceIdOverride = null)
    {
        var withGateway = new List<LanAddress>();
        var withoutGateway = new List<LanAddress>();
        var skippedPublic = new List<string>();
        NetworkInterface[] all;
        try { all = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (NetworkInformationException) { return new Scan(Array.Empty<LanAddress>(), skippedPublic); }
        var categories = NetworkCategories.Get();

        foreach (var ni in all)
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (interfaceIdOverride is not null)
            {
                if (!string.Equals(ni.Id, interfaceIdOverride, StringComparison.OrdinalIgnoreCase)) continue;
            }
            else
            {
                if (!PhysicalTypes.Contains(ni.NetworkInterfaceType)) continue;
                if (VirtualAdapter().IsMatch(ni.Name + " " + ni.Description)) continue;
            }

            IPInterfaceProperties props;
            int index;
            try
            {
                props = ni.GetIPProperties();
                index = props.GetIPv4Properties()?.Index ?? -1;
            }
            catch (NetworkInformationException) { continue; }

            bool hasGateway = props.GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));

            var addresses = props.UnicastAddresses
                .Where(ua => ua.Address.AddressFamily == AddressFamily.InterNetwork && IsPrivate(ua.Address)
                             && ua.PrefixLength is >= 8 and <= 30)
                .Select(ua => new LanAddress(ua.Address, ua.PrefixLength, ni.Name, ni.Id) { InterfaceIndex = index })
                .ToList();
            if (addresses.Count == 0) continue;

            if (categories.TryGetValue(ni.Id, out var info) && info.Category == NetworkCategories.Category.Public)
            {
                skippedPublic.Add(string.IsNullOrEmpty(info.NetworkName) ? ni.Name : info.NetworkName);
                continue;
            }
            (hasGateway ? withGateway : withoutGateway).AddRange(addresses);
        }
        return new Scan(withGateway.Count > 0 ? withGateway : withoutGateway, skippedPublic);
    }

    /// <summary>All interfaces with a private IPv4 address, for the manual override picker.</summary>
    public static IReadOnlyList<(string Id, string Label)> ListCandidates()
    {
        var list = new List<(string, string)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var addrs = ni.GetIPProperties().UnicastAddresses
                    .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && IsPrivate(u.Address))
                    .Select(u => $"{u.Address}/{u.PrefixLength}").ToList();
                if (addrs.Count > 0) list.Add((ni.Id, $"{ni.Name} — {string.Join(", ", addrs)}"));
            }
        }
        catch (NetworkInformationException) { }
        return list;
    }
}
