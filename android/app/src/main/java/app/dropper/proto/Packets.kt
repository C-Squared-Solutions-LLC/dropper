package app.dropper.proto

import java.nio.ByteBuffer

/** The 61-byte authenticated preamble sent before TLS (§6.1). */
object Preamble {
    const val SIZE = 61
    const val MODE_SESSION = 0x01
    const val MODE_PAIRING = 0x02
    private val MAGIC = "DRP1".toByteArray(Charsets.US_ASCII)

    fun build(mode: Int, tsMs: Long, nonce: ByteArray, key: ByteArray): ByteArray {
        require(mode == MODE_SESSION || mode == MODE_PAIRING)
        require(nonce.size == 16)
        val head = ByteBuffer.allocate(29)
            .put(MAGIC)
            .put(mode.toByte())
            .putLong(tsMs)
            .put(nonce)
            .array()
        return head + Crypto.hmac(key, head)
    }

    fun create(mode: Int, key: ByteArray): ByteArray =
        build(mode, System.currentTimeMillis(), Crypto.randomBytes(16), key)
}

/** Authenticated UDP discovery packets (§10). */
object DiscoveryPackets {
    const val PORT = 47823
    const val REQUEST_SIZE = 60
    const val RESPONSE_SIZE = 58
    private val REQ_MAGIC = "DRD1".toByteArray(Charsets.US_ASCII)
    private val RESP_MAGIC = "DRD2".toByteArray(Charsets.US_ASCII)

    fun request(tsMs: Long, nonce: ByteArray, discKey: ByteArray): ByteArray {
        require(nonce.size == 16)
        val head = ByteBuffer.allocate(28).put(REQ_MAGIC).putLong(tsMs).put(nonce).array()
        return head + Crypto.hmac(discKey, head)
    }

    /** Only used by tests (the PC builds responses). */
    fun response(ip: String, port: Int, nonce: ByteArray, discKey: ByteArray): ByteArray {
        val ipBytes = Ipv4.parse(ip) ?: throw IllegalArgumentException("bad ip")
        val head = ByteBuffer.allocate(26)
            .put(RESP_MAGIC)
            .put(ipBytes)
            .putShort(port.toShort())
            .put(nonce)
            .array()
        return head + Crypto.hmac(discKey, head)
    }

    data class Found(val ip: String, val port: Int, val nonce: ByteArray)

    /**
     * Parses and authenticates a response. Returns null unless magic, size and
     * MAC are all valid. The caller must still check the nonce is outstanding.
     */
    fun parseResponse(packet: ByteArray, length: Int, discKey: ByteArray): Found? {
        if (length != RESPONSE_SIZE) return null
        val p = packet.copyOf(length)
        if (!p.copyOfRange(0, 4).contentEquals(RESP_MAGIC)) return null
        val expected = Crypto.hmac(discKey, p.copyOfRange(0, 26))
        if (!Crypto.constantTimeEquals(expected, p.copyOfRange(26, 58))) return null
        val ip = Ipv4.format(p.copyOfRange(4, 8))
        val port = ((p[8].toInt() and 0xff) shl 8) or (p[9].toInt() and 0xff)
        if (port == 0) return null
        return Found(ip, port, p.copyOfRange(10, 26))
    }
}

/** Strict dotted-quad IPv4 handling and the RFC 1918 scope rule (§1, §5). */
object Ipv4 {
    /** Parses "a.b.c.d" strictly: 4 decimal octets 0–255, no leading zeros, no extras. */
    fun parse(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, part) in parts.withIndex()) {
            if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return null
            if (part.length > 1 && part[0] == '0') return null
            val v = part.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    fun format(b: ByteArray): String = b.joinToString(".") { (it.toInt() and 0xff).toString() }

    fun isRfc1918(b: ByteArray): Boolean {
        if (b.size != 4) return false
        val a0 = b[0].toInt() and 0xff
        val a1 = b[1].toInt() and 0xff
        return a0 == 10 || (a0 == 172 && a1 in 16..31) || (a0 == 192 && a1 == 168)
    }

    fun isRfc1918(s: String): Boolean = parse(s)?.let { isRfc1918(it) } ?: false
}

data class HostPort(val ip: String, val port: Int) {
    override fun toString() = "$ip:$port"

    companion object {
        /** Parses "ip:port"; only RFC 1918 IPv4 and ports 1–65535 are accepted. */
        fun parsePrivate(s: String): HostPort? {
            val idx = s.lastIndexOf(':')
            if (idx <= 0 || idx == s.length - 1) return null
            val ip = s.substring(0, idx)
            val portStr = s.substring(idx + 1)
            if (portStr.length > 5 || !portStr.all { it in '0'..'9' }) return null
            val port = portStr.toInt()
            if (port !in 1..65535) return null
            val bytes = Ipv4.parse(ip) ?: return null
            if (!Ipv4.isRfc1918(bytes)) return null
            return HostPort(ip, port)
        }
    }
}
