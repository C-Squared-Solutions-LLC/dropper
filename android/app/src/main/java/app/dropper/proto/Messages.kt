package app.dropper.proto

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Strict-ish JSON handling for control frames (§7). */
object Json {
    fun parseObject(body: ByteArray): JSONObject {
        if (body.size > Limits.MAX_JSON) throw ProtocolException("json too large")
        val text = decodeUtf8Strict(body) ?: throw ProtocolException("json not utf-8")
        val tokener = JSONTokener(text)
        val value = try {
            tokener.nextValue()
        } catch (_: JSONException) {
            throw ProtocolException("bad json")
        }
        if (value !is JSONObject) throw ProtocolException("json not an object")
        val trailing = try {
            tokener.nextClean()
        } catch (_: JSONException) {
            throw ProtocolException("bad json")
        }
        if (trailing.code != 0) throw ProtocolException("trailing json")
        return value
    }

    fun decodeUtf8Strict(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }

    fun bytes(o: JSONObject): ByteArray = o.toString().toByteArray(Charsets.UTF_8)
}

private fun JSONObject.reqString(name: String, maxLen: Int): String {
    val v = opt(name)
    if (v !is String) throw ProtocolException("field '$name' missing or not a string")
    if (v.length > maxLen) throw ProtocolException("field '$name' too long")
    return v
}

private fun JSONObject.reqLong(name: String): Long = when (val v = opt(name)) {
    is Int -> v.toLong()
    is Long -> v
    else -> throw ProtocolException("field '$name' missing or not an integer")
}

private fun JSONObject.reqBool(name: String): Boolean {
    val v = opt(name)
    if (v !is Boolean) throw ProtocolException("field '$name' missing or not a boolean")
    return v
}

private fun JSONObject.reqId(): String {
    val id = reqString("id", 32)
    if (!Crypto.isValidItemId(id)) throw ProtocolException("bad item id")
    return id
}

/** Display-only strings from peers: drop control/bidi characters, trim, cap. */
object TextSanitizer {
    fun isControl(c: Char): Boolean = c.code < 0x20 || c.code in 0x7f..0x9f
    fun isBidiControl(c: Char): Boolean =
        c == '‎' || c == '‏' || c == '؜' || c in '‪'..'‮' || c in '⁦'..'⁩'

    fun displayName(s: String, max: Int = Limits.MAX_DISPLAY_NAME): String =
        s.filterNot { isControl(it) || isBidiControl(it) }.trim().take(max)

    /** Short single-line form of an error/reason string coming from the peer. */
    fun reason(s: String): String = displayName(s, 64)
}

object Messages {
    data class PcHello(val name: String, val app: String?, val addrs: List<HostPort>)

    data class Offer(val id: String, val kind: String, val name: String, val mime: String, val size: Long) {
        /** §9 semantic checks. null = acceptable; otherwise the REJECT error code. */
        fun semanticError(): String? {
            if (kind != KIND_FILE && kind != KIND_TEXT) return "invalid"
            if (size < 0) return "invalid"
            if (name.length > Limits.MAX_NAME) return "invalid"
            if (kind == KIND_TEXT && size > Limits.MAX_TEXT) return "too_large"
            if (kind == KIND_FILE && size > Limits.MAX_FILE) return "too_large"
            return null
        }
    }

    data class Reject(val id: String, val error: String)
    data class Result(val id: String, val ok: Boolean, val error: String?)
    data class PairOk(val name: String, val secret: ByteArray)

    const val KIND_FILE = "file"
    const val KIND_TEXT = "text"

    fun phoneHello(name: String, model: String, app: String): ByteArray = Json.bytes(
        JSONObject()
            .put("v", 1)
            .put("role", "phone")
            .put("name", name)
            .put("model", model)
            .put("app", app),
    )

    fun parsePcHello(body: ByteArray): PcHello {
        val o = Json.parseObject(body)
        if (o.reqLong("v") != 1L) throw ProtocolException("unsupported version")
        if (o.reqString("role", 16) != "pc") throw ProtocolException("unexpected role")
        val name = TextSanitizer.displayName(o.reqString("name", Limits.MAX_DISPLAY_NAME)).ifEmpty { "PC" }
        val app = (o.opt("app") as? String)?.let { TextSanitizer.displayName(it, 32) }
        val addrs = ArrayList<HostPort>()
        val arr = o.opt("addrs")
        if (arr is JSONArray) {
            for (i in 0 until minOf(arr.length(), 4)) {
                val s = arr.opt(i) as? String ?: continue
                HostPort.parsePrivate(s)?.let { addrs.add(it) }
            }
        }
        return PcHello(name, app, addrs)
    }

    fun encodeOffer(o: Offer): ByteArray = Json.bytes(
        JSONObject()
            .put("id", o.id)
            .put("kind", o.kind)
            .put("name", o.name)
            .put("mime", o.mime)
            .put("size", o.size),
    )

    /** Type-level validation only; see [Offer.semanticError] for the §9 rules. */
    fun parseOffer(body: ByteArray): Offer {
        val o = Json.parseObject(body)
        val id = o.reqId()
        val kind = o.reqString("kind", 16)
        val name = o.reqString("name", 4096)
        val mime = o.reqString("mime", 255)
        val size = o.reqLong("size")
        return Offer(id, kind, name, mime, size)
    }

    fun encodeId(id: String): ByteArray = Json.bytes(JSONObject().put("id", id))

    fun parseId(body: ByteArray): String = Json.parseObject(body).reqId()

    fun encodeReject(id: String, error: String): ByteArray =
        Json.bytes(JSONObject().put("id", id).put("error", error))

    fun parseReject(body: ByteArray): Reject {
        val o = Json.parseObject(body)
        return Reject(o.reqId(), TextSanitizer.reason(o.reqString("error", 256)))
    }

    fun encodeResult(id: String, ok: Boolean, error: String? = null): ByteArray {
        val o = JSONObject().put("id", id).put("ok", ok)
        if (error != null) o.put("error", error)
        return Json.bytes(o)
    }

    fun parseResult(body: ByteArray): Result {
        val o = Json.parseObject(body)
        val id = o.reqId()
        val ok = o.reqBool("ok")
        val error = (o.opt("error") as? String)?.let { TextSanitizer.reason(it) }
        return Result(id, ok, error)
    }

    fun pairRequest(name: String, model: String, proof: ByteArray): ByteArray = Json.bytes(
        JSONObject()
            .put("v", 1)
            .put("name", name)
            .put("model", model)
            .put("proof", Crypto.b64u(proof)),
    )

    fun parsePairOk(body: ByteArray): PairOk {
        val o = Json.parseObject(body)
        if (o.reqLong("v") != 1L) throw ProtocolException("unsupported version")
        val name = TextSanitizer.displayName(o.reqString("name", Limits.MAX_DISPLAY_NAME)).ifEmpty { "PC" }
        val secret = Crypto.b64uDecode(o.reqString("secret", 64), 32)
            ?: throw ProtocolException("bad device secret")
        return PairOk(name, secret)
    }

    fun parsePairFail(body: ByteArray): String {
        val o = Json.parseObject(body)
        return TextSanitizer.reason(o.reqString("error", 256))
    }

    fun encodeBye(reason: String): ByteArray = Json.bytes(JSONObject().put("reason", reason))

    /** BYE reason; an empty body is treated as "shutdown". */
    fun parseBye(body: ByteArray): String {
        if (body.isEmpty()) return "shutdown"
        val o = Json.parseObject(body)
        return TextSanitizer.reason(o.reqString("reason", 256))
    }
}

/** Receiver-side file name rules (§11), plus Android-specific byte-length cap. */
object FileNames {
    private val RESERVED: Set<String> =
        setOf("CON", "PRN", "AUX", "NUL") + (1..9).map { "COM$it" } + (1..9).map { "LPT$it" }
    private const val FORBIDDEN = "<>:\"/\\|?*"
    private const val MAX_CHARS = 150
    // ext4/f2fs limit file names to 255 bytes; leave headroom for " (12)" suffixes.
    private const val MAX_UTF8_BYTES = 240

    fun sanitize(raw: String): String {
        var n = raw
        val cut = maxOf(n.lastIndexOf('/'), n.lastIndexOf('\\'))
        if (cut >= 0) n = n.substring(cut + 1)
        n = stripLoneSurrogates(n.filterNot { forbidden(it) })
        n = n.trimEnd('.', ' ')
        if (n.isEmpty()) return "file"
        val base = n.substringBefore('.').trimEnd(' ').uppercase(java.util.Locale.ROOT)
        if (base in RESERVED) n = "_$n"
        n = truncate(n).trimEnd('.', ' ')
        return n.ifEmpty { "file" }
    }

    private fun forbidden(c: Char): Boolean =
        TextSanitizer.isControl(c) || TextSanitizer.isBidiControl(c) || FORBIDDEN.indexOf(c) >= 0

    private fun stripLoneSurrogates(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                    sb.append(c).append(s[i + 1])
                    i += 2
                    continue
                }
            } else if (!Character.isLowSurrogate(c)) {
                sb.append(c)
            }
            i++
        }
        return sb.toString()
    }

    private fun utf8Len(s: String) = s.toByteArray(Charsets.UTF_8).size

    private fun truncate(n: String): String {
        if (n.length <= MAX_CHARS && utf8Len(n) <= MAX_UTF8_BYTES) return n
        val dot = n.lastIndexOf('.')
        val ext = if (dot > 0 && n.length - dot <= 16) n.substring(dot) else ""
        var stem = if (ext.isEmpty()) n else n.substring(0, dot)
        while (stem.isNotEmpty() &&
            (stem.length + ext.length > MAX_CHARS || utf8Len(stem) + utf8Len(ext) > MAX_UTF8_BYTES)
        ) {
            val drop = if (stem.length >= 2 && Character.isLowSurrogate(stem.last()) &&
                Character.isHighSurrogate(stem[stem.length - 2])
            ) 2 else 1
            stem = stem.substring(0, stem.length - drop)
        }
        return stem + ext
    }
}

object Links {
    /** Returns the URL if the whole trimmed text is a single http(s) URL (§11), else null. */
    fun singleHttpUrl(text: String): String? {
        val t = text.trim()
        if (t.isEmpty() || t.length > 8192) return null
        if (t.any { it.isWhitespace() || TextSanitizer.isControl(it) }) return null
        val lower = t.lowercase(java.util.Locale.ROOT)
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) return null
        val uri = try {
            java.net.URI(t)
        } catch (_: Exception) {
            return null
        }
        val scheme = uri.scheme?.lowercase(java.util.Locale.ROOT)
        if (scheme != "http" && scheme != "https") return null
        if (uri.host.isNullOrEmpty()) return null
        return t
    }
}
