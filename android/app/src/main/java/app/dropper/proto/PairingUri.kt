package app.dropper.proto

import java.io.ByteArrayOutputStream

/** The contents of a validated pairing QR code (§5). */
class PairingInvite(
    val addresses: List<HostPort>,
    val pcFp: ByteArray,
    val secret: ByteArray,
    val pcName: String,
)

object PairingUri {
    private const val PREFIX = "dropper://pair?"
    private val KNOWN = setOf("v", "a", "k", "s", "n")

    sealed class Parsed {
        class Ok(val invite: PairingInvite) : Parsed()
        class Invalid(val reason: String) : Parsed()
    }

    fun parse(raw: String): Parsed {
        val s = raw.trim()
        if (s.length > 2048) return Parsed.Invalid("This QR code is too long to be a Dropper code.")
        if (!s.startsWith(PREFIX)) return Parsed.Invalid("This isn't a Dropper pairing code.")

        val params = HashMap<String, String>()
        for (part in s.substring(PREFIX.length).split('&')) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            val key = if (eq < 0) part else part.substring(0, eq)
            if (key !in KNOWN) continue // unknown parameters are ignored (§5)
            if (params.containsKey(key)) return Parsed.Invalid("The pairing code is malformed (duplicate '$key').")
            val rawValue = if (eq < 0) "" else part.substring(eq + 1)
            val value = percentDecode(rawValue, plusIsSpace = key == "n")
                ?: return Parsed.Invalid("The pairing code is malformed.")
            params[key] = value
        }

        if (params["v"] != "1") return Parsed.Invalid("This pairing code is from an unsupported Dropper version.")
        val pcFp = params["k"]?.let { Crypto.b64uDecode(it, 32) }
            ?: return Parsed.Invalid("The pairing code has an invalid PC key.")
        val secret = params["s"]?.let { Crypto.b64uDecode(it, 32) }
            ?: return Parsed.Invalid("The pairing code has an invalid secret.")
        val a = params["a"] ?: return Parsed.Invalid("The pairing code has no PC address.")
        val entries = a.split(',')
        if (entries.isEmpty() || entries.size > 4) return Parsed.Invalid("The pairing code has too many addresses.")
        val addresses = ArrayList<HostPort>(entries.size)
        for (e in entries) {
            addresses += HostPort.parsePrivate(e)
                ?: return Parsed.Invalid("The PC address isn't on a private local network.")
        }
        val nameRaw = params["n"]
        if (nameRaw != null && nameRaw.length > 64) return Parsed.Invalid("The PC name in the code is too long.")
        val name = nameRaw?.let { TextSanitizer.displayName(it) }.orEmpty().ifEmpty { "PC" }
        return Parsed.Ok(PairingInvite(addresses, pcFp, secret, name))
    }

    /** RFC 3986 percent-decoding to strict UTF-8. Returns null on malformed input. */
    private fun percentDecode(s: String, plusIsSpace: Boolean): String? {
        val out = ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '%' -> {
                    if (i + 2 >= s.length) return null
                    val hi = Character.digit(s[i + 1], 16)
                    val lo = Character.digit(s[i + 2], 16)
                    if (hi < 0 || lo < 0) return null
                    out.write((hi shl 4) or lo)
                    i += 3
                    continue
                }
                c == '+' && plusIsSpace -> out.write(' '.code)
                c.code > 0x7e || c.code < 0x21 -> return null
                else -> out.write(c.code)
            }
            i++
        }
        return Json.decodeUtf8Strict(out.toByteArray())
    }
}
