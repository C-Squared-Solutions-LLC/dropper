package app.dropper.proto

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Any violation of the wire protocol. The connection must be closed (§7). */
class ProtocolException(message: String) : IOException(message)

object FrameType {
    const val HELLO = 0x01
    const val PING = 0x02
    const val PONG = 0x03
    const val BYE = 0x04
    const val OFFER = 0x10
    const val ACCEPT = 0x11
    const val REJECT = 0x12
    const val DATA = 0x13
    const val END = 0x14
    const val RESULT = 0x15
    const val CANCEL = 0x16
    const val PAIR_REQUEST = 0x20
    const val PAIR_OK = 0x21
    const val PAIR_FAIL = 0x22

    private val KNOWN = setOf(
        HELLO, PING, PONG, BYE, OFFER, ACCEPT, REJECT, DATA, END, RESULT, CANCEL,
        PAIR_REQUEST, PAIR_OK, PAIR_FAIL,
    )

    fun isKnown(t: Int) = t in KNOWN
}

object Limits {
    const val MAX_BODY = 1_048_576
    const val MAX_FRAME_LENGTH = 1 + MAX_BODY
    const val SEND_CHUNK = 262_144
    const val MAX_JSON = 65_536
    const val MAX_TEXT = 4_194_304L
    const val MAX_FILE = 68_719_476_736L
    const val MAX_NAME = 255
    const val MAX_DISPLAY_NAME = 64
    const val DEDUPE_IDS = 500
}

class Frame(val type: Int, val body: ByteArray)

/** Reads length-prefixed frames, enforcing §7 before allocating anything large. */
class FrameReader(input: InputStream) {
    private val din = DataInputStream(input)

    /** @throws java.io.EOFException on clean end of stream, [ProtocolException] on violations. */
    fun read(): Frame {
        val length = din.readInt()
        if (length < 1 || length > Limits.MAX_FRAME_LENGTH) throw ProtocolException("bad frame length")
        val type = din.readUnsignedByte()
        if (!FrameType.isKnown(type)) throw ProtocolException("unknown frame type")
        val body = ByteArray(length - 1)
        din.readFully(body)
        return Frame(type, body)
    }
}

/**
 * Serializes frame writes: one lock per connection so control frames interleave
 * *between* DATA frames, never inside them (§7). Tracks write timing for the
 * stall watchdog.
 */
class FrameWriter(private val out: OutputStream) {
    // Fair, so a queued control frame gets the lock before the next DATA frame.
    private val lock = ReentrantLock(true)
    private val buffer = ByteArray(5 + Limits.SEND_CHUNK)

    /** System.nanoTime() when the in-progress write began, or 0 when idle. */
    @Volatile
    var writeStartedAt: Long = 0L
        private set

    @Volatile
    var lastWriteAt: Long = System.nanoTime()
        private set

    fun write(type: Int, body: ByteArray = EMPTY, off: Int = 0, len: Int = body.size) {
        lock.withLock { writeLocked(type, body, off, len) }
    }

    /** Writes only if no other write is in progress (used for PING so the watchdog never blocks). */
    fun tryWrite(type: Int, body: ByteArray = EMPTY): Boolean {
        if (!lock.tryLock(0, TimeUnit.MILLISECONDS)) return false
        try {
            writeLocked(type, body, 0, body.size)
        } finally {
            lock.unlock()
        }
        return true
    }

    private fun writeLocked(type: Int, body: ByteArray, off: Int, len: Int) {
        require(len in 0..Limits.MAX_BODY)
        writeStartedAt = System.nanoTime()
        try {
            val frameLen = 1 + len
            if (5 + len <= buffer.size) {
                putHeader(buffer, frameLen, type)
                System.arraycopy(body, off, buffer, 5, len)
                out.write(buffer, 0, 5 + len)
            } else {
                val header = ByteArray(5)
                putHeader(header, frameLen, type)
                out.write(header)
                out.write(body, off, len)
            }
            out.flush()
            lastWriteAt = System.nanoTime()
        } finally {
            writeStartedAt = 0L
        }
    }

    companion object {
        val EMPTY = ByteArray(0)

        private fun putHeader(b: ByteArray, frameLen: Int, type: Int) {
            b[0] = (frameLen ushr 24).toByte()
            b[1] = (frameLen ushr 16).toByte()
            b[2] = (frameLen ushr 8).toByte()
            b[3] = frameLen.toByte()
            b[4] = type.toByte()
        }

        fun encode(type: Int, body: ByteArray): ByteArray {
            val b = ByteArray(5 + body.size)
            putHeader(b, 1 + body.size, type)
            System.arraycopy(body, 0, b, 5, body.size)
            return b
        }
    }
}
