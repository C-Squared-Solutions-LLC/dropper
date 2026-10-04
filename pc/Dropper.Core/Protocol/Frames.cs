using System.Buffers;
using System.Buffers.Binary;

namespace Dropper.Core.Protocol;

/// <summary>
/// Reads frames (docs/PROTOCOL.md §7). The returned body aliases an internal
/// buffer that is reused by the next call, so callers must finish with it first.
/// </summary>
public sealed class FrameReader(Stream stream)
{
    private readonly byte[] _header = new byte[5];
    private readonly byte[] _body = new byte[Wire.MaxFrameBody];

    public async ValueTask<(FrameType Type, ReadOnlyMemory<byte> Body)> ReadAsync(CancellationToken ct)
    {
        await stream.ReadExactlyAsync(_header, ct).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(_header);
        if (length < 1 || length > 1 + (uint)Wire.MaxFrameBody)
            throw new ProtocolException($"invalid frame length {length}");
        var type = (FrameType)_header[4];
        if (!Enum.IsDefined(type))
            throw new ProtocolException($"unknown frame type 0x{_header[4]:x2}");
        int bodyLength = (int)length - 1;
        if (bodyLength > 0)
            await stream.ReadExactlyAsync(_body.AsMemory(0, bodyLength), ct).ConfigureAwait(false);
        return (type, _body.AsMemory(0, bodyLength));
    }
}

/// <summary>Writes whole frames atomically; safe to call from several tasks at once.</summary>
public sealed class FrameWriter(Stream stream) : IDisposable
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task WriteAsync(FrameType type, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        if (body.Length > Wire.MaxFrameBody) throw new ArgumentException("frame body too large", nameof(body));
        int total = 5 + body.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)(1 + body.Length));
            buffer[4] = (byte)type;
            body.Span.CopyTo(buffer.AsSpan(5));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Wire.StallTimeout);
            await _lock.WaitAsync(timeout.Token).ConfigureAwait(false);
            try
            {
                await stream.WriteAsync(buffer.AsMemory(0, total), timeout.Token).ConfigureAwait(false);
                await stream.FlushAsync(timeout.Token).ConfigureAwait(false);
            }
            finally
            {
                _lock.Release();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public Task WriteAsync(FrameType type, CancellationToken ct) => WriteAsync(type, ReadOnlyMemory<byte>.Empty, ct);

    public void Dispose() => _lock.Dispose();
}
