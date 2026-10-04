package app.dropper.proto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Primitives from PROTOCOL.md §2. Pure JVM — unit-tested against docs/test-vectors.json. */
object Crypto {
    private val rng = SecureRandom()
    private val b64uEncoder = Base64.getUrlEncoder().withoutPadding()
    private val b64uDecoder = Base64.getUrlDecoder()
    private val B64U_CHARS = Regex("^[A-Za-z0-9_-]*$")

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal()
    }

    /** HKDF-SHA256 with salt = 32 zero bytes and L = 32: HMAC(HMAC(0^32, ikm), info || 0x01). */
    fun hkdf32(ikm: ByteArray, info: String): ByteArray {
        val prk = hmac(ByteArray(32), ikm)
        return hmac(prk, info.toByteArray(Charsets.US_ASCII), byteArrayOf(1))
    }

    /** Constant-time comparison (MessageDigest.isEqual is constant-time on OpenJDK/Android). */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun b64u(bytes: ByteArray): String = b64uEncoder.encodeToString(bytes)

    /** Strict base64url (no padding) decode; returns null on any malformed input or wrong length. */
    fun b64uDecode(s: String, expectedLen: Int): ByteArray? {
        if (!B64U_CHARS.matches(s)) return null
        val out = try {
            b64uDecoder.decode(s)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (out.size != expectedLen) return null
        // Reject non-canonical encodings (stray low bits in the final char).
        if (b64u(out) != s) return null
        return out
    }

    private val HEX = "0123456789abcdef".toCharArray()

    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
        }
        return sb.toString()
    }

    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { i ->
            val hi = Character.digit(s[2 * i], 16)
            val lo = Character.digit(s[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex" }
            ((hi shl 4) or lo).toByte()
        }
    }

    /** 16 random bytes as 32 lowercase hex chars — transfer item ids (§9). */
    fun newItemId(): String = hex(randomBytes(16))

    private val ITEM_ID = Regex("^[0-9a-f]{32}$")
    fun isValidItemId(id: String): Boolean = ITEM_ID.matches(id)
}

/** Keys derived from the one-time pairing secret carried in the QR code (§4). */
class PairingKeys(pairingSecret: ByteArray) {
    init {
        require(pairingSecret.size == 32)
    }

    val gateKey: ByteArray = Crypto.hkdf32(pairingSecret, "dropper/v1/pair-gate")
    val proofKey: ByteArray = Crypto.hkdf32(pairingSecret, "dropper/v1/pair-proof")
    val sasKey: ByteArray = Crypto.hkdf32(pairingSecret, "dropper/v1/sas")

    fun proof(pcFp: ByteArray, phoneFp: ByteArray): ByteArray = Crypto.hmac(proofKey, pcFp, phoneFp)

    /** 6-digit short authentication string, zero-padded, no separator (e.g. "747546"). */
    fun sas(pcFp: ByteArray, phoneFp: ByteArray): String {
        val h = Crypto.hmac(sasKey, pcFp, phoneFp)
        val n = ((h[0].toLong() and 0xff) shl 24) or
            ((h[1].toLong() and 0xff) shl 16) or
            ((h[2].toLong() and 0xff) shl 8) or
            (h[3].toLong() and 0xff)
        return (n % 1_000_000L).toString().padStart(6, '0')
    }

    companion object {
        /** "747546" → "747 546" */
        fun formatSas(sas: String): String =
            if (sas.length == 6) sas.substring(0, 3) + " " + sas.substring(3) else sas
    }
}

/** Keys derived from the long-term device secret delivered in PAIR_OK (§4). */
class DeviceKeys(deviceSecret: ByteArray) {
    init {
        require(deviceSecret.size == 32)
    }

    val gateKey: ByteArray = Crypto.hkdf32(deviceSecret, "dropper/v1/gate")
    val discKey: ByteArray = Crypto.hkdf32(deviceSecret, "dropper/v1/discovery")
}

object Fingerprint {
    /** fp = SHA256(DER SubjectPublicKeyInfo) — pass `cert.publicKey.encoded`. */
    fun of(spkiDer: ByteArray): ByteArray = Crypto.sha256(spkiDer)

    /** First 16 bytes, uppercase hex, 8 groups of 4: "A0A1 A2A3 …" (§3). */
    fun display(fp: ByteArray): String {
        val h = Crypto.hex(fp.copyOfRange(0, minOf(16, fp.size))).uppercase()
        return h.chunked(4).joinToString(" ")
    }
}
