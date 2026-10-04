package app.dropper.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingUriAndNamesTest {
    private val v = TestVectors
    private val k = Crypto.b64u(ByteArray(32) { 0xA0.toByte() })
    private val s = Crypto.b64u(ByteArray(32) { 0x01 })

    private fun ok(uri: String): PairingInvite {
        val p = PairingUri.parse(uri)
        assertTrue("expected Ok for $uri, got ${(p as? PairingUri.Parsed.Invalid)?.reason}", p is PairingUri.Parsed.Ok)
        return (p as PairingUri.Parsed.Ok).invite
    }

    private fun bad(uri: String) {
        assertTrue("expected Invalid for $uri", PairingUri.parse(uri) is PairingUri.Parsed.Invalid)
    }

    @Test
    fun parsesVectorUri() {
        val invite = ok(v.json.getString("qr_uri"))
        assertEquals(listOf(HostPort("192.168.2.131", 47823)), invite.addresses)
        assertArrayEquals(v.input("pc_fp"), invite.pcFp)
        assertArrayEquals(v.input("pairing_secret"), invite.secret)
        assertEquals("MY-PC", invite.pcName)
    }

    @Test
    fun acceptsMultipleAddressesUnknownParamsAndEncodedName() {
        val invite = ok("dropper://pair?v=1&a=10.0.0.5:1,172.16.0.1:65535,192.168.0.2:47823&k=$k&s=$s&n=Alex%27s%20PC&x=ignored")
        assertEquals(3, invite.addresses.size)
        assertEquals("Alex's PC", invite.pcName)
        assertEquals("PC", ok("dropper://pair?v=1&a=10.0.0.5:47823&k=$k&s=$s").pcName)
    }

    @Test
    fun rejectsInvalidCodes() {
        val base = "dropper://pair?v=1&a=192.168.2.131:47823&k=$k&s=$s&n=PC"
        bad(base.replace("v=1", "v=2"))
        bad(base.replace("dropper://", "https://"))
        bad("$base&v=1")                                                   // duplicate param
        bad(base.replace("k=$k", "k=${k.dropLast(2)}"))                    // short key
        bad(base.replace("s=$s", "s=${Crypto.b64u(ByteArray(33))}"))       // long secret
        bad(base.replace("192.168.2.131", "8.8.8.8"))                      // public IP
        bad(base.replace("192.168.2.131", "172.32.0.1"))                   // just outside 172.16/12
        bad(base.replace("192.168.2.131", "192.168.02.131"))               // leading zero
        bad(base.replace("192.168.2.131", "100.123.196.78"))               // CGNAT (e.g. Tailscale) is not LAN
        bad(base.replace(":47823", ":0"))
        bad(base.replace(":47823", ":65536"))
        bad(base.replace("a=192.168.2.131:47823", "a=" + List(5) { "10.0.0.${it + 1}:1" }.joinToString(",")))
        bad(base.replace("&a=192.168.2.131:47823", ""))                    // no address
        bad(base.replace("n=PC", "n=" + "x".repeat(65)))
        bad(base.replace("n=PC", "n=%zz"))
        bad(base.replace("n=PC", "n=%ff"))                                 // invalid UTF-8
    }

    @Test
    fun ipv4Rules() {
        assertTrue(Ipv4.isRfc1918("10.255.255.255"))
        assertTrue(Ipv4.isRfc1918("172.31.0.1"))
        assertTrue(Ipv4.isRfc1918("192.168.0.0"))
        assertTrue(!Ipv4.isRfc1918("172.15.0.1"))
        assertTrue(!Ipv4.isRfc1918("169.254.1.1"))
        assertTrue(!Ipv4.isRfc1918("127.0.0.1"))
        assertNull(Ipv4.parse("1.2.3"))
        assertNull(Ipv4.parse("1.2.3.4.5"))
        assertNull(Ipv4.parse("256.1.1.1"))
        assertNull(Ipv4.parse("1.2.3.-4"))
        assertNull(HostPort.parsePrivate("192.168.1.1"))
        assertNull(HostPort.parsePrivate("192.168.1.1:"))
        assertNull(HostPort.parsePrivate("192.168.1.1:123456"))
        assertEquals(HostPort("192.168.1.1", 80), HostPort.parsePrivate("192.168.1.1:80"))
    }

    @Test
    fun fileNameSanitization() {
        assertEquals("passwd", FileNames.sanitize("../../etc/passwd"))
        assertEquals("c.txt", FileNames.sanitize("a\\b\\c.txt"))
        assertEquals("_CON", FileNames.sanitize("CON"))
        assertEquals("_con.txt", FileNames.sanitize("con.txt"))
        assertEquals("_COM1.tar.gz", FileNames.sanitize("COM1.tar.gz"))
        assertEquals("_lpt9", FileNames.sanitize("lpt9"))
        assertEquals("COM10.txt", FileNames.sanitize("COM10.txt"))
        assertEquals("file.txt", FileNames.sanitize("fi<l>e:\"|?*.txt"))
        assertEquals("name", FileNames.sanitize("name. . ."))
        assertEquals("file", FileNames.sanitize(""))
        assertEquals("file", FileNames.sanitize(".."))
        assertEquals("file", FileNames.sanitize("dir/"))
        assertEquals("tab.txt", FileNames.sanitize("t\u0000a\tb\u007f.txt"))
        assertEquals("invoicefdp.exe", FileNames.sanitize("invoice\u202Efdp.exe")) // RTL override stripped
        assertEquals("ok.txt", FileNames.sanitize("o\uD800k.txt"))                    // lone surrogate
        assertEquals("photo \uD83D\uDCF8.jpg", FileNames.sanitize("photo \uD83D\uDCF8.jpg"))

        val long = "a".repeat(400) + ".pdf"
        val cut = FileNames.sanitize(long)
        assertEquals(150, cut.length)
        assertTrue(cut.endsWith(".pdf"))

        val wide = "\u4E2D".repeat(149) + ".txt" // 3 bytes per char → byte cap applies
        val wideCut = FileNames.sanitize(wide)
        assertTrue(wideCut.toByteArray(Charsets.UTF_8).size <= 240)
        assertTrue(wideCut.endsWith(".txt"))
    }

    @Test
    fun displayNamesAreSanitized() {
        assertEquals("evil", TextSanitizer.displayName("\u202Eevil\n"))
        assertEquals(64, TextSanitizer.displayName("x".repeat(100)).length)
    }
}
