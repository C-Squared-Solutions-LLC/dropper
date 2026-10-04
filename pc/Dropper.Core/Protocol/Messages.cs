using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Dropper.Core.Crypto;

namespace Dropper.Core.Protocol;

public enum ItemKind { File, Text }

public sealed record HelloMessage(string Name, string Model, string App);
public sealed record OfferMessage(string Id, ItemKind Kind, string Name, string Mime, long Size);
public sealed record ReplyMessage(FrameType Type, string Id, bool Ok, string? Error);
public sealed record PairRequestMessage(string Name, string Model, byte[] Proof);

/// <summary>
/// JSON bodies (docs/PROTOCOL.md §7–§9). Parsing is strict about required fields
/// and types; a malformed body raises <see cref="ProtocolException"/>.
/// </summary>
public static class Messages
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
    };

    private static readonly JsonDocumentOptions ReaderOptions = new() { MaxDepth = 8 };

    // ---------- writing ----------

    public static byte[] Object(Action<Utf8JsonWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buffer, WriterOptions))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    public static byte[] PcHello(string name, IEnumerable<string> addrs) => Object(w =>
    {
        w.WriteNumber("v", Wire.ProtocolVersion);
        w.WriteString("role", "pc");
        w.WriteString("name", name);
        w.WriteString("app", Wire.AppVersion);
        w.WriteStartArray("addrs");
        foreach (var a in addrs) w.WriteStringValue(a);
        w.WriteEndArray();
    });

    public static byte[] Offer(OfferMessage o) => Object(w =>
    {
        w.WriteString("id", o.Id);
        w.WriteString("kind", o.Kind == ItemKind.Text ? "text" : "file");
        w.WriteString("name", o.Name);
        w.WriteString("mime", o.Mime);
        w.WriteNumber("size", o.Size);
    });

    public static byte[] IdOnly(string id) => Object(w => w.WriteString("id", id));

    public static byte[] Reject(string id, string error) => Object(w =>
    {
        w.WriteString("id", id);
        w.WriteString("error", error);
    });

    public static byte[] Result(string id, bool ok, string? error = null) => Object(w =>
    {
        w.WriteString("id", id);
        w.WriteBoolean("ok", ok);
        if (error is not null) w.WriteString("error", error);
    });

    public static byte[] Bye(string reason) => Object(w => w.WriteString("reason", reason));

    public static byte[] PairOk(string pcName, ReadOnlySpan<byte> deviceSecret)
    {
        string secret = Base64Url.Encode(deviceSecret);
        return Object(w =>
        {
            w.WriteNumber("v", Wire.ProtocolVersion);
            w.WriteString("name", pcName);
            w.WriteString("secret", secret);
        });
    }

    public static byte[] PairFail(string error) => Object(w =>
    {
        w.WriteNumber("v", Wire.ProtocolVersion);
        w.WriteString("error", error);
    });

    // ---------- reading ----------

    public static JsonDocument Parse(ReadOnlyMemory<byte> body)
    {
        if (body.Length > Wire.MaxJson) throw new ProtocolException("JSON body too large");
        JsonDocument doc;
        try { doc = JsonDocument.Parse(body, ReaderOptions); }
        catch (JsonException) { throw new ProtocolException("invalid JSON"); }
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            doc.Dispose();
            throw new ProtocolException("JSON body is not an object");
        }
        return doc;
    }

    public static HelloMessage ParsePhoneHello(ReadOnlyMemory<byte> body)
    {
        using var doc = Parse(body);
        var r = doc.RootElement;
        if (RequireInt(r, "v") != Wire.ProtocolVersion) throw new ProtocolException("unsupported protocol version");
        if (RequireString(r, "role", 16) != "phone") throw new ProtocolException("unexpected role");
        string name = TextSafety.CleanDisplayName(RequireString(r, "name", 256), Wire.MaxDeviceNameChars);
        string model = TextSafety.CleanDisplayName(OptionalString(r, "model", 256), Wire.MaxDeviceNameChars);
        string app = TextSafety.CleanDisplayName(OptionalString(r, "app", 64), 32);
        return new HelloMessage(name.Length == 0 ? "Phone" : name, model, app);
    }

    /// <summary>
    /// Returns the offer, or (null, id) when the id is valid but the other fields are
    /// not, so the caller can answer REJECT "invalid" and keep the connection.
    /// </summary>
    public static (OfferMessage? Offer, string Id) ParseOffer(ReadOnlyMemory<byte> body)
    {
        using var doc = Parse(body);
        var r = doc.RootElement;
        string id = RequireId(r);
        try
        {
            string kindText = RequireString(r, "kind", 16);
            ItemKind kind = kindText switch
            {
                "file" => ItemKind.File,
                "text" => ItemKind.Text,
                _ => throw new ProtocolException("bad kind"),
            };
            string name = OptionalString(r, "name", Wire.MaxNameChars);
            string mime = OptionalString(r, "mime", 127);
            long size = RequireInt(r, "size");
            if (size < 0) throw new ProtocolException("negative size");
            return (new OfferMessage(id, kind, name, mime, size), id);
        }
        catch (ProtocolException)
        {
            return (null, id);
        }
    }

    public static ReplyMessage ParseReply(FrameType type, ReadOnlyMemory<byte> body)
    {
        using var doc = Parse(body);
        var r = doc.RootElement;
        string id = RequireId(r);
        return type switch
        {
            FrameType.Accept => new ReplyMessage(type, id, true, null),
            FrameType.Reject => new ReplyMessage(type, id, false, OptionalString(r, "error", 64)),
            FrameType.Result => new ReplyMessage(type, id, RequireBool(r, "ok"), OptionalStringOrNull(r, "error", 64)),
            _ => throw new ProtocolException("not a reply frame"),
        };
    }

    public static string ParseIdOnly(ReadOnlyMemory<byte> body)
    {
        using var doc = Parse(body);
        return RequireId(doc.RootElement);
    }

    public static string ParseBye(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty) return "";
        using var doc = Parse(body);
        return OptionalString(doc.RootElement, "reason", 64);
    }

    public static PairRequestMessage ParsePairRequest(ReadOnlyMemory<byte> body)
    {
        using var doc = Parse(body);
        var r = doc.RootElement;
        if (RequireInt(r, "v") != Wire.ProtocolVersion) throw new ProtocolException("unsupported protocol version");
        string name = TextSafety.CleanDisplayName(RequireString(r, "name", 256), Wire.MaxDeviceNameChars);
        string model = TextSafety.CleanDisplayName(OptionalString(r, "model", 256), Wire.MaxDeviceNameChars);
        if (!Base64Url.TryDecode(RequireString(r, "proof", 64), out var proof) || proof.Length != 32)
            throw new ProtocolException("bad proof encoding");
        return new PairRequestMessage(name.Length == 0 ? "Phone" : name, model, proof);
    }

    // ---------- field helpers ----------

    public static bool IsValidId(string? id)
    {
        if (id is null || id.Length != 32) return false;
        foreach (char c in id)
            if (!(c is (>= '0' and <= '9') or (>= 'a' and <= 'f'))) return false;
        return true;
    }

    private static string RequireId(JsonElement r)
    {
        string id = RequireString(r, "id", 32);
        if (!IsValidId(id)) throw new ProtocolException("bad id");
        return id;
    }

    private static string RequireString(JsonElement r, string name, int maxChars)
    {
        if (!r.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.String)
            throw new ProtocolException($"missing string '{name}'");
        string s = e.GetString()!;
        if (s.Length > maxChars) throw new ProtocolException($"'{name}' too long");
        return s;
    }

    private static string OptionalString(JsonElement r, string name, int maxChars) =>
        OptionalStringOrNull(r, name, maxChars) ?? "";

    private static string? OptionalStringOrNull(JsonElement r, string name, int maxChars)
    {
        if (!r.TryGetProperty(name, out var e) || e.ValueKind == JsonValueKind.Null) return null;
        if (e.ValueKind != JsonValueKind.String) throw new ProtocolException($"'{name}' is not a string");
        string s = e.GetString()!;
        if (s.Length > maxChars) throw new ProtocolException($"'{name}' too long");
        return s;
    }

    private static long RequireInt(JsonElement r, string name)
    {
        if (!r.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.Number || !e.TryGetInt64(out long v))
            throw new ProtocolException($"missing integer '{name}'");
        return v;
    }

    private static bool RequireBool(JsonElement r, string name)
    {
        if (!r.TryGetProperty(name, out var e)) throw new ProtocolException($"missing bool '{name}'");
        return e.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new ProtocolException($"'{name}' is not a bool"),
        };
    }
}

/// <summary>Display-string hygiene for anything a peer controls.</summary>
public static class TextSafety
{
    /// <summary>Letters that render as blank space (Hangul fillers, Braille blank, grapheme joiner).</summary>
    private static readonly HashSet<int> BlankLetters = [0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F];

    /// <summary>
    /// Strips control and invisible characters, collapses whitespace and caps the length.
    /// Invisible characters include zero-width marks, bidi overrides that disguise names
    /// (e.g. "invoice‮fdp.exe"), soft hyphens and tag characters.
    /// </summary>
    public static string CleanDisplayName(string? s, int maxChars)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(Math.Min(s.Length, maxChars));
        bool lastSpace = false;
        foreach (Rune r in s.EnumerateRunes())
        {
            if (Rune.IsWhiteSpace(r))
            {
                if (!lastSpace && sb.Length > 0) sb.Append(' ');
                lastSpace = true;
                continue;
            }
            if (IsInvisible(r) || r == Rune.ReplacementChar) continue;
            sb.Append(r.ToString());
            lastSpace = false;
        }
        return Truncate(sb.ToString().Trim(), maxChars);
    }

    /// <summary>
    /// True for code points that render as nothing or rearrange text: Unicode Control and
    /// Format categories (zero-width, bidi, soft hyphen, tags…), unassigned, private-use and
    /// surrogate code points, and letters that draw as blank space.
    /// </summary>
    public static bool IsInvisible(Rune r) =>
        Rune.GetUnicodeCategory(r) is UnicodeCategory.Control or UnicodeCategory.Format
            or UnicodeCategory.OtherNotAssigned or UnicodeCategory.PrivateUse or UnicodeCategory.Surrogate
        || BlankLetters.Contains(r.Value);

    /// <summary>Cuts to at most maxChars without splitting a surrogate pair.</summary>
    public static string Truncate(string s, int maxChars)
    {
        if (s.Length <= maxChars) return s;
        int cut = maxChars;
        if (cut > 0 && char.IsHighSurrogate(s[cut - 1])) cut--;
        return s[..cut];
    }
}
