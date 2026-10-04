using System.Runtime.InteropServices;

namespace Dropper.Core.Net;

/// <summary>
/// Reads Windows' network category (Public / Private / Domain) per adapter from the
/// Network List Manager, so Dropper can refuse to listen on networks the user marked
/// Public (cafés, hotels, airports).
/// </summary>
public static class NetworkCategories
{
    public enum Category { Public = 0, Private = 1, Domain = 2 }

    public sealed record Info(Category Category, string NetworkName);

    /// <summary>Adapter GUID (as in NetworkInterface.Id, braces, upper-case) → category. Empty if NLM is unavailable.</summary>
    public static IReadOnlyDictionary<string, Info> Get()
    {
        var result = new Dictionary<string, Info>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var type = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"));
            if (type is null || Activator.CreateInstance(type) is not INetworkListManager nlm) return result;
            if (nlm.GetNetworkConnections(out var connections) != 0 || connections is null) return result;
            var one = new INetworkConnection[1];
            for (int guard = 0; guard < 256 && connections.Next(1, one, out uint fetched) == 0 && fetched == 1; guard++)
            {
                var conn = one[0];
                if (conn.GetAdapterId(out var adapter) != 0 || conn.GetNetwork(out var network) != 0 || network is null) continue;
                if (network.GetCategory(out int category) != 0) continue;
                network.GetName(out string? name);
                result[adapter.ToString("B")] = new Info((Category)category, name ?? "");
            }
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or UnauthorizedAccessException)
        {
            // NLM unavailable: callers treat every adapter as allowed.
        }
        return result;
    }

    // Minimal Network List Manager interop (netlistmgr.h). Slot order matters, so the
    // methods we never call are still declared, up to the last one we use.

    [ComImport, Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkListManager
    {
        [PreserveSig] int GetNetworks(int flags, out IntPtr enumNetworks);
        [PreserveSig] int GetNetwork(Guid id, out IntPtr network);
        [PreserveSig] int GetNetworkConnections(out IEnumNetworkConnections connections);
    }

    [ComImport, Guid("DCB00006-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IEnumNetworkConnections
    {
        [PreserveSig] int GetNewEnum(out IntPtr enumVariant);
        [PreserveSig] int Next(uint celt, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] INetworkConnection[] items, out uint fetched);
    }

    [ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkConnection
    {
        [PreserveSig] int GetNetwork(out INetwork network);
        [PreserveSig] int IsConnectedToInternet(out short value);
        [PreserveSig] int IsConnected(out short value);
        [PreserveSig] int GetConnectivity(out int connectivity);
        [PreserveSig] int GetConnectionId(out Guid id);
        [PreserveSig] int GetAdapterId(out Guid id);
    }

    [ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetwork
    {
        [PreserveSig] int GetName([MarshalAs(UnmanagedType.BStr)] out string name);
        [PreserveSig] int SetName([MarshalAs(UnmanagedType.BStr)] string name);
        [PreserveSig] int GetDescription([MarshalAs(UnmanagedType.BStr)] out string description);
        [PreserveSig] int SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
        [PreserveSig] int GetNetworkId(out Guid id);
        [PreserveSig] int GetDomainType(out int domainType);
        [PreserveSig] int GetNetworkConnections(out IntPtr enumConnections);
        [PreserveSig] int GetTimeCreatedAndConnected(out uint lowCreated, out uint highCreated, out uint lowConnected, out uint highConnected);
        [PreserveSig] int IsConnectedToInternet(out short value);
        [PreserveSig] int IsConnected(out short value);
        [PreserveSig] int GetConnectivity(out int connectivity);
        [PreserveSig] int GetCategory(out int category);
    }
}
