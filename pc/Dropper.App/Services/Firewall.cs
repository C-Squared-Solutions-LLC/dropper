using System.Runtime.InteropServices;
using Dropper.Core.Protocol;

namespace Dropper.App.Services;

/// <summary>
/// Windows Defender Firewall rules for Dropper, through the firewall's COM API (no
/// shell, no command strings). Reading works for any user; changing rules needs an
/// elevated process, so the app relaunches itself with --configure-firewall.
/// </summary>
internal static class Firewall
{
    public const string TcpRuleName = "Dropper (TCP-In)";
    public const string UdpRuleName = "Dropper (UDP-In)";
    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;
    private const int DirectionIn = 1;
    private const int ActionAllow = 1;
    private const int ProfileDomain = 1;
    private const int ProfilePrivate = 2;

    private static dynamic Policy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;

    /// <summary>True when both allow rules exist for this exact program and are enabled.</summary>
    public static bool RulesPresent(string exe)
    {
        try
        {
            bool tcp = false, udp = false;
            dynamic policy = Policy();
            foreach (dynamic rule in policy.Rules)
            {
                string? app = rule.ApplicationName;
                if (app is null || !string.Equals(app, exe, StringComparison.OrdinalIgnoreCase)) continue;
                if (!(bool)rule.Enabled || (int)rule.Action != ActionAllow) continue;
                string name = rule.Name;
                if (name == TcpRuleName) tcp = true;
                if (name == UdpRuleName) udp = true;
            }
            return tcp && udp;
        }
        catch (COMException) { return false; }
    }

    /// <summary>
    /// Replaces every rule for this program, including ones Windows created from its own
    /// "allow access?" prompt (which accept any address), with two inbound allow rules
    /// limited to the local subnet on Private/Domain networks. Requires elevation.
    /// </summary>
    public static void Configure(string exe, int tcpPort)
    {
        dynamic policy = Policy();
        RemoveRulesFor(policy, exe);
        AddRule(policy, TcpRuleName, exe, ProtocolTcp, tcpPort);
        AddRule(policy, UdpRuleName, exe, ProtocolUdp, Wire.DiscoveryPort);
    }

    /// <summary>Removes Dropper's rules and any other rule for this program. Requires elevation.</summary>
    public static void Remove(string exe) => RemoveRulesFor(Policy(), exe);

    private static void RemoveRulesFor(dynamic policy, string exe)
    {
        for (int pass = 0; pass < 64; pass++)
        {
            string? victim = null;
            foreach (dynamic rule in policy.Rules)
            {
                string? app = rule.ApplicationName;
                string name = rule.Name;
                if (name is TcpRuleName or UdpRuleName ||
                    (app is not null && string.Equals(app, exe, StringComparison.OrdinalIgnoreCase)))
                {
                    victim = name;
                    break;
                }
            }
            if (victim is null) return;
            policy.Rules.Remove(victim);
        }
    }

    private static void AddRule(dynamic policy, string name, string exe, int protocol, int port)
    {
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
        rule.Name = name;
        rule.Description = "Dropper: accept your paired phone from the local subnet only.";
        rule.Grouping = "Dropper";
        rule.ApplicationName = exe;
        rule.Protocol = protocol; // must be set before LocalPorts
        rule.LocalPorts = port.ToString();
        rule.RemoteAddresses = "LocalSubnet";
        rule.Direction = DirectionIn;
        rule.Action = ActionAllow;
        rule.Profiles = ProfileDomain | ProfilePrivate;
        rule.Enabled = true;
        policy.Rules.Add(rule);
    }
}
