using System.Net;

namespace Dropper.Core.Net;

/// <summary>Remembers nonces for <see cref="Protocol.Wire.ReplayWindow"/> so a captured packet can't be reused.</summary>
public sealed class ReplayCache(TimeSpan window, int capacity = 50_000)
{
    private readonly Dictionary<UInt128, DateTimeOffset> _seen = new();
    private readonly object _gate = new();

    /// <summary>Returns false if the nonce was already used inside the window.</summary>
    public bool TryAdd(ReadOnlySpan<byte> nonce16, DateTimeOffset now)
    {
        var key = new UInt128(
            BitConverter.ToUInt64(nonce16[..8]),
            BitConverter.ToUInt64(nonce16[8..16]));
        lock (_gate)
        {
            if (_seen.Count >= capacity) Purge(now);
            if (_seen.TryGetValue(key, out var expires) && expires > now) return false;
            _seen[key] = now + window;
            return true;
        }
    }

    private void Purge(DateTimeOffset now)
    {
        foreach (var k in _seen.Where(p => p.Value <= now).Select(p => p.Key).ToList()) _seen.Remove(k);
        // Still full of live entries: something is flooding us. Refusing new
        // nonces would lock out the real phone too, so drop the oldest half.
        if (_seen.Count >= capacity)
            foreach (var k in _seen.OrderBy(p => p.Value).Take(capacity / 2).Select(p => p.Key).ToList())
                _seen.Remove(k);
    }
}

/// <summary>
/// Per-IP failure tracking: 10 failures within 60 s puts an IP on a 5-minute
/// ignore list (docs/PROTOCOL.md §6.1). Also a simple per-IP rate limiter.
/// </summary>
public sealed class IpThrottle(int maxEvents, TimeSpan window, TimeSpan blockFor)
{
    private readonly Dictionary<IPAddress, (Queue<DateTimeOffset> Events, DateTimeOffset BlockedUntil)> _state = new();
    private readonly object _gate = new();

    public bool IsBlocked(IPAddress ip, DateTimeOffset now)
    {
        lock (_gate)
            return _state.TryGetValue(ip, out var s) && s.BlockedUntil > now;
    }

    /// <summary>Records an event; returns true if the IP is now (or still) blocked.</summary>
    public bool Record(IPAddress ip, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_state.Count > 4096) Cleanup(now);
            if (!_state.TryGetValue(ip, out var s)) s = (new Queue<DateTimeOffset>(), DateTimeOffset.MinValue);
            if (s.BlockedUntil > now) return true;
            while (s.Events.Count > 0 && s.Events.Peek() <= now - window) s.Events.Dequeue();
            s.Events.Enqueue(now);
            if (s.Events.Count >= maxEvents)
            {
                s.BlockedUntil = now + blockFor;
                s.Events.Clear();
            }
            _state[ip] = s;
            return s.BlockedUntil > now;
        }
    }

    private void Cleanup(DateTimeOffset now)
    {
        foreach (var ip in _state.Where(p => p.Value.BlockedUntil <= now &&
                     (p.Value.Events.Count == 0 || p.Value.Events.Last() <= now - window))
                 .Select(p => p.Key).ToList())
            _state.Remove(ip);
    }
}

/// <summary>
/// Connections that have not authenticated yet. At most <c>max</c> in total and
/// <c>perIp</c> per address. When a limit is hit, the OLDEST pending connection is
/// dropped, so a flood of idle connections only pushes out the flood's own entries
/// and can never keep the real phone from getting a slot.
/// </summary>
public sealed class PreAuthSlots(int max, int perIp)
{
    private readonly LinkedList<Slot> _pending = new();
    private readonly object _gate = new();

    public int Count
    {
        get { lock (_gate) return _pending.Count; }
    }

    public Slot Admit(IPAddress ip, CancellationToken parent)
    {
        var slot = new Slot(this, ip, parent);
        var evicted = new List<Slot>();
        lock (_gate)
        {
            int sameIp = _pending.Count(s => s.Ip.Equals(ip));
            for (var node = _pending.First; node is not null && sameIp >= perIp;)
            {
                var next = node.Next;
                if (node.Value.Ip.Equals(ip))
                {
                    evicted.Add(node.Value);
                    _pending.Remove(node);
                    node.Value.Node = null;
                    sameIp--;
                }
                node = next;
            }
            while (_pending.Count >= max)
            {
                var first = _pending.First!;
                evicted.Add(first.Value);
                _pending.RemoveFirst();
                first.Value.Node = null;
            }
            slot.Node = _pending.AddLast(slot);
        }
        foreach (var e in evicted) e.Evict();
        return slot;
    }

    private void Leave(Slot slot)
    {
        lock (_gate)
        {
            if (slot.Node is null) return;
            _pending.Remove(slot.Node);
            slot.Node = null;
        }
    }

    public sealed class Slot : IDisposable
    {
        private readonly PreAuthSlots _owner;
        private readonly CancellationTokenSource _cts;

        internal Slot(PreAuthSlots owner, IPAddress ip, CancellationToken parent)
        {
            _owner = owner;
            Ip = ip;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(parent);
        }

        internal LinkedListNode<Slot>? Node { get; set; }
        public IPAddress Ip { get; }
        /// <summary>Cancelled if this connection is evicted to make room for a newer one.</summary>
        public CancellationToken Token => _cts.Token;
        public bool Evicted { get; private set; }

        internal void Evict()
        {
            Evicted = true;
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        }

        /// <summary>The connection authenticated: it no longer counts against the limits.</summary>
        public void Complete() => _owner.Leave(this);

        public void Dispose()
        {
            _owner.Leave(this);
            _cts.Dispose();
        }
    }
}
