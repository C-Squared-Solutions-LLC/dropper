using System.Security.Cryptography;
using System.Text;
using Dropper.Core.Crypto;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;

namespace Dropper.Core.Engine;

/// <summary>
/// Receives one item. Files stream into a hidden temp file next to the destination
/// and are only renamed into place after the SHA-256 checks out.
/// </summary>
internal sealed class IncomingTransfer : IDisposable
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private FileStream? _file;
    private string? _tempPath;
    private MemoryStream? _text;

    private IncomingTransfer(OfferMessage offer, ActivityItem item)
    {
        Offer = offer;
        Item = item;
    }

    public OfferMessage Offer { get; }
    public ActivityItem Item { get; }
    public long Received { get; private set; }
    /// <summary>Set when a local write failed; the rest of the stream is drained and RESULT "io" is sent.</summary>
    public string? LocalError { get; private set; }

    public static IncomingTransfer Create(OfferMessage offer, ActivityItem item, string receiveDir)
    {
        var t = new IncomingTransfer(offer, item);
        if (offer.Kind == ItemKind.File)
        {
            Directory.CreateDirectory(receiveDir);
            t._tempPath = Path.Combine(receiveDir, $".dropper-{offer.Id}.partial");
            t._file = new FileStream(t._tempPath, FileMode.Create, FileAccess.Write, FileShare.None,
                1 << 16, FileOptions.Asynchronous | FileOptions.SequentialScan);
            try { File.SetAttributes(t._tempPath, FileAttributes.Hidden); } catch (IOException) { }
        }
        else
        {
            t._text = new MemoryStream((int)Math.Min(offer.Size, Wire.MaxTextBytes));
        }
        return t;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        if (Received + data.Length > Offer.Size) throw new ProtocolException("more data than offered");
        _hash.AppendData(data.Span);
        Received += data.Length;
        if (LocalError is not null) return;

        if (_text is not null)
        {
            _text.Write(data.Span);
            return;
        }
        try
        {
            await _file!.WriteAsync(data, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            LocalError = ex.Message;
            DeleteTemp();
        }
    }

    public bool Verify(ReadOnlySpan<byte> sha256) =>
        Received == Offer.Size && Kdf.FixedTimeEquals(_hash.GetHashAndReset(), sha256);

    /// <summary>Tags the verified temp file with Mark-of-the-Web, then renames it into place.</summary>
    public (string Path, bool Tagged) CommitFile(string receiveDir)
    {
        _file!.Flush(flushToDisk: true);
        _file.Dispose();
        _file = null;
        bool tagged = Motw.Apply(_tempPath!); // before the rename, so the visible file is never untagged
        string final = FileNames.MoveToUnique(_tempPath!, receiveDir, FileNames.Sanitize(Offer.Name));
        _tempPath = null;
        try { File.SetAttributes(final, FileAttributes.Normal); } catch (IOException) { }
        return (final, tagged);
    }

    public string CommitText() =>
        new UTF8Encoding(false, false).GetString(_text!.GetBuffer(), 0, (int)_text.Length);

    private void DeleteTemp()
    {
        try { _file?.Dispose(); } catch (IOException) { }
        _file = null;
        if (_tempPath is null) return;
        try { File.Delete(_tempPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        _tempPath = null;
    }

    public void Dispose()
    {
        DeleteTemp();
        _text = null;
        _hash.Dispose();
    }
}
