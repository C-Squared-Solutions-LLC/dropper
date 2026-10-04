package app.dropper.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException

class FramesAndMessagesTest {
    private val v = TestVectors

    @Test
    fun helloFrameMatchesVector() {
        val fh = v.json.getJSONObject("frame_hello")
        val body = fh.getString("body_utf8").toByteArray(Charsets.UTF_8)
        val expected = Crypto.unhex(fh.getString("bytes"))
        assertArrayEquals(expected, FrameWriter.encode(fh.getInt("type"), body))

        val out = ByteArrayOutputStream()
        FrameWriter(out).write(FrameType.HELLO, body)
        assertArrayEquals(expected, out.toByteArray())

        val frame = FrameReader(ByteArrayInputStream(expected)).read()
        assertEquals(FrameType.HELLO, frame.type)
        assertArrayEquals(body, frame.body)
    }

    @Test
    fun pingFrameMatchesVector() {
        val expected = v.hex("frame_ping")
        assertArrayEquals(expected, FrameWriter.encode(FrameType.PING, ByteArray(0)))
        val frame = FrameReader(ByteArrayInputStream(expected)).read()
        assertEquals(FrameType.PING, frame.type)
        assertEquals(0, frame.body.size)
    }

    @Test
    fun largeDataFrameRoundTrips() {
        val body = ByteArray(Limits.SEND_CHUNK) { (it * 31).toByte() }
        val out = ByteArrayOutputStream()
        FrameWriter(out).write(FrameType.DATA, body)
        val f = FrameReader(ByteArrayInputStream(out.toByteArray())).read()
        assertEquals(FrameType.DATA, f.type)
        assertArrayEquals(body, f.body)
    }

    private fun expectProtocolError(bytes: ByteArray) {
        try {
            FrameReader(ByteArrayInputStream(bytes)).read()
            fail("expected ProtocolException")
        } catch (_: ProtocolException) {
        }
    }

    @Test
    fun readerRejectsBadFrames() {
        expectProtocolError(Crypto.unhex("0000000001"))         // length 0
        expectProtocolError(Crypto.unhex("0010000201"))         // length 1 MiB + 2
        expectProtocolError(Crypto.unhex("0000000199"))         // unknown type
        expectProtocolError(Crypto.unhex("ffffffff01"))         // negative length
        try {
            FrameReader(ByteArrayInputStream(Crypto.unhex("0000000a01"))).read() // truncated body
            fail("expected EOF")
        } catch (_: EOFException) {
        }
    }

    @Test
    fun parsePcHelloValidates() {
        val ok = Messages.parsePcHello(
            """{"v":1,"role":"pc","name":"DESKTOP-ABC","app":"1.0.0","addrs":["192.168.2.131:47823","8.8.8.8:1","junk"]}"""
                .toByteArray(),
        )
        assertEquals("DESKTOP-ABC", ok.name)
        assertEquals(listOf(HostPort("192.168.2.131", 47823)), ok.addrs)

        for (bad in listOf(
            """{"v":2,"role":"pc","name":"x"}""",
            """{"v":1,"role":"phone","name":"x"}""",
            """{"v":1,"role":"pc"}""",
            """{"v":"1","role":"pc","name":"x"}""",
            """{"v":1,"role":"pc","name":"${"x".repeat(65)}"}""",
            """{"v":1,"role":"pc","name":"x"} trailing""",
            """[1,2]""",
            """not json""",
        )) {
            try {
                Messages.parsePcHello(bad.toByteArray())
                fail("accepted: $bad")
            } catch (_: ProtocolException) {
            }
        }
    }

    @Test
    fun offerParsingAndSemantics() {
        val id = "0123456789abcdef0123456789abcdef"
        val o = Messages.parseOffer("""{"id":"$id","kind":"file","name":"a.jpg","mime":"image/jpeg","size":68719476736}""".toByteArray())
        assertEquals(68_719_476_736L, o.size)
        assertNull(o.semanticError())
        assertEquals("too_large", o.copy(size = Limits.MAX_FILE + 1).semanticError())
        assertEquals("too_large", o.copy(kind = "text", size = Limits.MAX_TEXT + 1).semanticError())
        assertNull(o.copy(kind = "text", size = Limits.MAX_TEXT).semanticError())
        assertEquals("invalid", o.copy(kind = "folder").semanticError())
        assertEquals("invalid", o.copy(size = -1).semanticError())
        assertEquals("invalid", o.copy(name = "n".repeat(256)).semanticError())

        for (bad in listOf(
            """{"kind":"file","name":"a","mime":"x","size":1}""",                       // no id
            """{"id":"XYZ","kind":"file","name":"a","mime":"x","size":1}""",             // bad id
            """{"id":"${id.uppercase()}","kind":"file","name":"a","mime":"x","size":1}""",
            """{"id":"$id","kind":"file","name":"a","mime":"x","size":1.5}""",            // non-integer size
            """{"id":"$id","kind":"file","name":"a","mime":"x","size":"1"}""",
            """{"id":"$id","kind":"file","name":"a","size":1}""",                         // no mime
        )) {
            try {
                Messages.parseOffer(bad.toByteArray())
                fail("accepted: $bad")
            } catch (_: ProtocolException) {
            }
        }
    }

    @Test
    fun offerEncodeRoundTrips() {
        val o = Messages.Offer(Crypto.newItemId(), Messages.KIND_TEXT, "", "text/plain", 5)
        assertEquals(o, Messages.parseOffer(Messages.encodeOffer(o)))
    }

    @Test
    fun resultRejectAndPairMessages() {
        val id = Crypto.newItemId()
        val r = Messages.parseResult(Messages.encodeResult(id, false, "integrity"))
        assertEquals(Messages.Result(id, false, "integrity"), r)
        assertEquals(Messages.Result(id, true, null), Messages.parseResult(Messages.encodeResult(id, true)))
        assertEquals(Messages.Reject(id, "duplicate"), Messages.parseReject(Messages.encodeReject(id, "duplicate")))
        assertEquals(id, Messages.parseId(Messages.encodeId(id)))

        val secret = ByteArray(32) { it.toByte() }
        val ok = Messages.parsePairOk("""{"v":1,"name":"DESKTOP","secret":"${Crypto.b64u(secret)}"}""".toByteArray())
        assertEquals("DESKTOP", ok.name)
        assertArrayEquals(secret, ok.secret)
        try {
            Messages.parsePairOk("""{"v":1,"name":"D","secret":"${Crypto.b64u(ByteArray(31))}"}""".toByteArray())
            fail("short secret accepted")
        } catch (_: ProtocolException) {
        }
        assertEquals("rejected", Messages.parsePairFail("""{"v":1,"error":"rejected"}""".toByteArray()))
        assertEquals("unpaired", Messages.parseBye("""{"reason":"unpaired"}""".toByteArray()))
        assertEquals("shutdown", Messages.parseBye(ByteArray(0)))
    }

    @Test
    fun links() {
        assertEquals("https://example.com/a?b=c", Links.singleHttpUrl("  https://example.com/a?b=c \n"))
        assertEquals("HTTP://EXAMPLE.COM", Links.singleHttpUrl("HTTP://EXAMPLE.COM"))
        assertNull(Links.singleHttpUrl("see https://example.com"))
        assertNull(Links.singleHttpUrl("https://a.com https://b.com"))
        assertNull(Links.singleHttpUrl("javascript:alert(1)"))
        assertNull(Links.singleHttpUrl("file:///etc/passwd"))
        assertNull(Links.singleHttpUrl("intent://scan/#Intent;scheme=x;end"))
        assertNull(Links.singleHttpUrl("https://"))
        assertFalse(Links.singleHttpUrl("hello") != null)
        assertTrue(Links.singleHttpUrl("http://192.168.1.1:8080/") != null)
    }
}
