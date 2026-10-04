package app.dropper.net

import android.os.StatFs
import android.util.Log
import app.dropper.AppGraph
import app.dropper.data.Direction
import app.dropper.data.HistoryItem
import app.dropper.data.ItemKind
import app.dropper.data.ItemStatus
import app.dropper.data.OutboxItem
import app.dropper.proto.Crypto
import app.dropper.proto.FileNames
import app.dropper.proto.Frame
import app.dropper.proto.FrameReader
import app.dropper.proto.FrameType
import app.dropper.proto.FrameWriter
import app.dropper.proto.HostPort
import app.dropper.proto.Limits
import app.dropper.proto.Messages
import app.dropper.proto.ProtocolException
import app.dropper.service.Clip
import app.dropper.service.Notifications
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket

class ByeException(val reason: String) : IOException("peer said goodbye ($reason)")

/**
 * One authenticated session with the PC (§8.3, §9). Three loops share the socket:
 *  - reader: the only thread that reads; never blocks on writes (control frames
 *    go through [control]), so two sides streaming at once can't deadlock;
 *  - sender: drains the outbox, one item in flight;
 *  - keepalive/watchdog: PING after 45 s idle, PONG timeout, stall detection.
 */
class Session(
    private val graph: AppGraph,
    private val socket: SSLSocket,
    private val reader: FrameReader,
    private val writer: FrameWriter,
    val pcName: String,
    val address: HostPort,
) {
    private sealed class Response {
        class Accept(val id: String) : Response()
        class Reject(val id: String, val error: String) : Response()
        class Result(val id: String, val ok: Boolean, val error: String?) : Response()
    }

    private class Incoming(val offer: Messages.Offer, val sink: IncomingSink, val name: String) {
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        var received = 0L
        var writeFailed = false
        var lastProgress = -1
    }

    private class ControlFrame(val type: Int, val body: ByteArray)

    private val control = Channel<ControlFrame>(Channel.UNLIMITED)
    private val responses = Channel<Response>(4)

    @Volatile private var outgoingId: String? = null
    @Volatile private var lastReceivedAt = System.nanoTime()
    @Volatile private var pingSentAt = 0L
    @Volatile private var incoming: Incoming? = null
    private val pendingControl = AtomicInteger(0)

    @Volatile var closeReason: String? = null
        private set
    @Volatile var unpaired = false
        private set

    /** Runs until the connection ends. Never throws except for cancellation. */
    suspend fun run() {
        val done = CompletableDeferred<Throwable>()
        coroutineScope {
            val jobs = listOf(
                launch(Dispatchers.IO) { done.complete(runCatching { readLoop() }.exceptionOrNull() ?: EOFException()) },
                launch(Dispatchers.IO) { done.complete(runCatching { controlLoop() }.exceptionOrNull() ?: EOFException()) },
                launch(Dispatchers.IO) { done.complete(runCatching { sendLoop() }.exceptionOrNull() ?: EOFException()) },
                launch(Dispatchers.IO) { done.complete(runCatching { keepaliveLoop() }.exceptionOrNull() ?: EOFException()) },
            )
            try {
                val cause = done.await()
                closeReason = describe(cause)
                Log.i(TAG, "session ended: ${cause.javaClass.simpleName}")
            } finally {
                closeQuietly() // unblocks any thread stuck in socket I/O
                jobs.forEach { it.cancel() }
                jobs.joinAll()
                cleanupIncoming()
            }
        }
    }

    /** Polite close (e.g. unpair from the phone): best-effort BYE, then drop the socket. */
    fun sendByeAndClose(reason: String) {
        try {
            writer.write(FrameType.BYE, Messages.encodeBye(reason))
        } catch (_: Exception) {
        }
        closeQuietly()
    }

    fun closeQuietly() {
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }

    // ---------------------------------------------------------------- reader

    private suspend fun readLoop() {
        while (true) {
            val f = reader.read()
            lastReceivedAt = System.nanoTime()
            when (f.type) {
                FrameType.PING -> sendControl(FrameType.PONG, FrameWriter.EMPTY)
                FrameType.PONG -> pingSentAt = 0L
                FrameType.BYE -> {
                    val reason = Messages.parseBye(f.body)
                    if (reason == "unpaired") unpaired = true
                    throw ByeException(reason)
                }
                FrameType.OFFER -> onOffer(f.body)
                FrameType.DATA -> onData(f)
                FrameType.END -> onEnd(f.body)
                FrameType.CANCEL -> onCancel(f.body)
                FrameType.ACCEPT, FrameType.REJECT, FrameType.RESULT -> onResponse(f)
                else -> throw ProtocolException("unexpected frame type ${f.type}")
            }
        }
    }

    private fun sendControl(type: Int, body: ByteArray) {
        if (pendingControl.incrementAndGet() > 1_000) throw ProtocolException("control queue overflow")
        control.trySend(ControlFrame(type, body))
    }

    private suspend fun controlLoop() {
        for (f in control) {
            pendingControl.decrementAndGet()
            writer.write(f.type, f.body)
        }
    }

    private fun onOffer(body: ByteArray) {
        if (incoming != null) throw ProtocolException("OFFER while another item is pending")
        val offer = Messages.parseOffer(body)
        offer.semanticError()?.let { return reject(offer.id, it) }
        if (graph.receivedIds.contains(offer.id) || graph.history.find(offer.id)?.status == ItemStatus.RECEIVED) {
            return reject(offer.id, "duplicate")
        }
        val sink: IncomingSink
        val name: String
        if (offer.kind == Messages.KIND_TEXT) {
            sink = TextSink()
            name = ""
        } else {
            if (!hasSpaceFor(offer.size)) return reject(offer.id, "no_space")
            name = FileNames.sanitize(offer.name)
            sink = try {
                MediaStoreSink(graph.context.contentResolver, name)
            } catch (e: Exception) {
                Log.w(TAG, "cannot create download: ${e.javaClass.simpleName}")
                return reject(offer.id, "io")
            }
            graph.history.add(
                HistoryItem(
                    id = offer.id, direction = Direction.IN, kind = ItemKind.FILE, name = name, size = offer.size,
                    mime = sink.mime, uri = sink.uri.toString(), status = ItemStatus.RECEIVING,
                    time = System.currentTimeMillis(),
                ),
            )
            graph.progress.set(offer.id, 0f)
        }
        incoming = Incoming(offer, sink, name)
        sendControl(FrameType.ACCEPT, Messages.encodeId(offer.id))
    }

    private fun reject(id: String, error: String) = sendControl(FrameType.REJECT, Messages.encodeReject(id, error))

    private fun onData(f: Frame) {
        val inc = incoming ?: throw ProtocolException("DATA without an accepted OFFER")
        if (f.body.isEmpty()) throw ProtocolException("empty DATA frame")
        inc.received += f.body.size
        if (inc.received > inc.offer.size) throw ProtocolException("DATA beyond declared size")
        inc.digest.update(f.body)
        if (!inc.writeFailed) {
            try {
                inc.sink.write(f.body, 0, f.body.size)
            } catch (_: IOException) {
                inc.writeFailed = true // keep consuming until END, then RESULT io
            }
        }
        if (inc.offer.kind == Messages.KIND_FILE && inc.offer.size > 0) {
            val pct = (inc.received * 100 / inc.offer.size).toInt()
            if (pct != inc.lastProgress) {
                inc.lastProgress = pct
                graph.progress.set(inc.offer.id, pct / 100f)
            }
        }
    }

    private fun onEnd(body: ByteArray) {
        val inc = incoming ?: throw ProtocolException("END without an accepted OFFER")
        if (body.size != 32) throw ProtocolException("END must carry a 32-byte SHA-256")
        incoming = null
        val id = inc.offer.id
        graph.progress.clear(id)
        val intact = inc.received == inc.offer.size && Crypto.constantTimeEquals(inc.digest.digest(), body)
        if (!intact || inc.writeFailed) {
            inc.sink.abort()
            val error = if (!intact) "integrity" else "io"
            sendControl(FrameType.RESULT, Messages.encodeResult(id, false, error))
            graph.history.update(id) { it.copy(status = ItemStatus.FAILED, error = if (!intact) "Corrupted in transit" else "Couldn't save") }
            return
        }
        when (val sink = inc.sink) {
            is TextSink -> {
                val text = String(sink.bytes(), Charsets.UTF_8)
                graph.receivedIds.add(id)
                sendControl(FrameType.RESULT, Messages.encodeResult(id, true))
                deliverText(id, text, inc.offer.size)
            }
            is MediaStoreSink -> {
                val finalName = try {
                    sink.commit()
                } catch (e: Exception) {
                    sink.abort()
                    sendControl(FrameType.RESULT, Messages.encodeResult(id, false, "io"))
                    graph.history.update(id) { it.copy(status = ItemStatus.FAILED, error = "Couldn't save") }
                    return
                }
                graph.receivedIds.add(id)
                sendControl(FrameType.RESULT, Messages.encodeResult(id, true))
                graph.history.update(id) { it.copy(status = ItemStatus.RECEIVED, name = finalName ?: it.name) }
                graph.history.find(id)?.let { Notifications.receivedFile(graph.context, it, pcName) }
            }
        }
    }

    private fun deliverText(id: String, text: String, size: Long) {
        val copied = graph.settings.autoCopy.value && Clip.copy(graph.context, text, sensitive = true)
        val item = HistoryItem(
            id = id, direction = Direction.IN, kind = ItemKind.TEXT, name = "", size = size, mime = "text/plain",
            text = text, status = ItemStatus.RECEIVED, time = System.currentTimeMillis(),
        )
        graph.history.add(item)
        Notifications.receivedText(graph.context, item, pcName, copied)
    }

    private fun onCancel(body: ByteArray) {
        val id = Messages.parseId(body)
        val inc = incoming ?: throw ProtocolException("CANCEL without a transfer")
        if (inc.offer.id != id) throw ProtocolException("CANCEL for a different item")
        incoming = null
        inc.sink.abort()
        graph.progress.clear(id)
        graph.history.update(id) { it.copy(status = ItemStatus.FAILED, error = "Cancelled by PC") }
    }

    private fun onResponse(f: Frame) {
        val expected = outgoingId ?: throw ProtocolException("unsolicited response")
        val r = when (f.type) {
            FrameType.ACCEPT -> Response.Accept(Messages.parseId(f.body))
            FrameType.REJECT -> Messages.parseReject(f.body).let { Response.Reject(it.id, it.error) }
            else -> Messages.parseResult(f.body).let { Response.Result(it.id, it.ok, it.error) }
        }
        val id = when (r) {
            is Response.Accept -> r.id
            is Response.Reject -> r.id
            is Response.Result -> r.id
        }
        if (id != expected) throw ProtocolException("response for the wrong item")
        if (!responses.trySend(r).isSuccess) throw ProtocolException("too many responses")
    }

    private fun cleanupIncoming() {
        val inc = incoming ?: return
        incoming = null
        inc.sink.abort()
        graph.progress.clear(inc.offer.id)
        graph.history.update(inc.offer.id) { it.copy(status = ItemStatus.FAILED, error = "Interrupted") }
    }

    private fun hasSpaceFor(size: Long): Boolean = try {
        val dir = graph.context.getExternalFilesDir(null) ?: graph.context.filesDir
        StatFs(dir.path).availableBytes > size + 50L * 1024 * 1024
    } catch (_: Exception) {
        true
    }

    // ---------------------------------------------------------------- sender

    private suspend fun sendLoop() {
        while (true) {
            val item = graph.outbox.awaitNextPending()
            sendItem(item)
        }
    }

    private suspend fun awaitResponse(timeoutMs: Long): Response = withTimeout(timeoutMs) { responses.receive() }

    private suspend fun sendItem(item: OutboxItem) {
        val id = item.id
        var settled = false
        outgoingId = id
        try {
            graph.outbox.markSending(id)
            graph.progress.set(id, 0f)
            val kind = if (item.kind == ItemKind.TEXT) Messages.KIND_TEXT else Messages.KIND_FILE
            writer.write(FrameType.OFFER, Messages.encodeOffer(Messages.Offer(id, kind, item.name, item.mime, item.size)))
            when (val r = awaitResponse(30_000)) {
                is Response.Reject -> {
                    settled = true
                    if (r.error == "duplicate") graph.outbox.markDelivered(id)
                    else graph.outbox.markFailed(id, describeReject(r.error))
                    return
                }
                is Response.Result -> throw ProtocolException("RESULT before data")
                is Response.Accept -> Unit
            }

            val digest = MessageDigest.getInstance("SHA-256")
            val source: InputStream = if (item.kind == ItemKind.TEXT) {
                ByteArrayInputStream((item.text ?: "").toByteArray(Charsets.UTF_8))
            } else {
                try {
                    FileInputStream(graph.outbox.file(id))
                } catch (_: IOException) {
                    writer.write(FrameType.CANCEL, Messages.encodeId(id))
                    settled = true
                    graph.outbox.markFailed(id, "File is no longer available")
                    return
                }
            }
            var sent = 0L
            var lastPct = -1
            source.use { input ->
                val buf = ByteArray(Limits.SEND_CHUNK)
                while (sent < item.size) {
                    val want = minOf(buf.size.toLong(), item.size - sent).toInt()
                    val n = try {
                        input.read(buf, 0, want)
                    } catch (_: IOException) {
                        -1
                    }
                    if (n <= 0) {
                        writer.write(FrameType.CANCEL, Messages.encodeId(id))
                        settled = true
                        graph.outbox.markFailed(id, "File changed while sending")
                        return
                    }
                    digest.update(buf, 0, n)
                    writer.write(FrameType.DATA, buf, 0, n)
                    sent += n
                    val pct = if (item.size == 0L) 100 else (sent * 100 / item.size).toInt()
                    if (pct != lastPct) {
                        lastPct = pct
                        graph.progress.set(id, pct / 100f)
                    }
                }
            }
            writer.write(FrameType.END, digest.digest())
            when (val r = awaitResponse(60_000)) {
                is Response.Result -> {
                    settled = true
                    if (r.ok) graph.outbox.markDelivered(id)
                    else graph.outbox.markAttemptFailed(id, describeResult(r.error))
                }
                else -> throw ProtocolException("expected RESULT")
            }
        } finally {
            outgoingId = null
            graph.progress.clear(id)
            if (!settled) graph.outbox.markAttemptFailed(id, "Connection lost")
        }
    }

    // ------------------------------------------------------------- keepalive

    private suspend fun keepaliveLoop() {
        while (true) {
            delay(1_000)
            val now = System.nanoTime()
            val ping = pingSentAt
            if (ping != 0L && now - ping > 15_000_000_000L) throw TimeoutException("no PONG within 15 s")
            val ws = writer.writeStartedAt
            if (ws != 0L && now - ws > 30_000_000_000L) throw TimeoutException("write stalled for 30 s")
            if (incoming != null && now - lastReceivedAt > 30_000_000_000L) throw TimeoutException("transfer stalled for 30 s")
            if (ping == 0L && now - writer.lastWriteAt >= 45_000_000_000L) {
                pingSentAt = now
                sendControl(FrameType.PING, FrameWriter.EMPTY)
            }
        }
    }

    private fun describe(t: Throwable): String = when (t) {
        is ByeException -> if (t.reason == "unpaired") "This phone was removed on the PC" else "The PC closed the connection"
        is ProtocolException -> "Protocol error"
        is TimeoutException -> "Connection timed out"
        is EOFException -> "The PC closed the connection"
        else -> "Connection lost"
    }

    private fun describeReject(error: String): String = when (error) {
        "no_space" -> "Not enough space on the PC"
        "too_large" -> "Too large for the PC to accept"
        "invalid" -> "The PC rejected the item"
        "io" -> "The PC couldn't save it"
        else -> "Rejected by PC ($error)"
    }

    private fun describeResult(error: String?): String = when (error) {
        "integrity" -> "Corrupted in transit"
        "io" -> "The PC couldn't save it"
        else -> "Delivery failed"
    }

    private companion object {
        const val TAG = "DropperSession"
    }
}
