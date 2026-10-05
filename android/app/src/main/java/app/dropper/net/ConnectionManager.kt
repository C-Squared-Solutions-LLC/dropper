package app.dropper.net

import android.os.SystemClock
import android.util.Log
import app.dropper.AppGraph
import app.dropper.BuildConfig
import app.dropper.data.PairingRecord
import app.dropper.proto.DeviceKeys
import app.dropper.proto.FrameReader
import app.dropper.proto.FrameType
import app.dropper.proto.FrameWriter
import app.dropper.proto.HostPort
import app.dropper.proto.Messages
import app.dropper.proto.Preamble
import app.dropper.proto.ProtocolException
import app.dropper.security.Identity
import app.dropper.security.IdentityMaterial
import app.dropper.security.PinMismatchException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedInputStream
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket

sealed interface ConnState {
    data object Idle : ConnState
    data object NotPaired : ConnState
    data class NoNetwork(val pcName: String) : ConnState
    data class Connecting(val pcName: String) : ConnState
    data class Connected(val pcName: String, val address: HostPort) : ConnState
    data class Offline(val pcName: String, val reason: String, val retryAt: Long) : ConnState
}

/**
 * Keeps one session to the paired PC alive while running: last known address
 * first, then authenticated discovery, with exponential backoff that resets on
 * network changes (PROTOCOL.md §6, §10).
 */
class ConnectionManager(private val graph: AppGraph) {
    private val _state = MutableStateFlow<ConnState>(ConnState.Idle)
    val state: StateFlow<ConnState> = _state.asStateFlow()

    private val kicks = Channel<Unit>(Channel.CONFLATED)
    private var loopJob: Job? = null

    @Volatile
    private var session: Session? = null

    @Synchronized
    fun start() {
        if (loopJob?.isActive == true) return
        loopJob = graph.scope.launch(Dispatchers.IO) { loop() }
    }

    @Synchronized
    fun stop() {
        loopJob?.cancel()
        loopJob = null
        session?.closeQuietly()
        _state.value = ConnState.Idle
    }

    /** Retry now instead of waiting out the backoff. */
    fun kick() {
        kicks.trySend(Unit)
    }

    /** Tells the PC we're unpairing (best effort) and drops the connection. */
    fun sayGoodbye() {
        session?.sendByeAndClose("unpaired")
    }

    /** The user quit Dropper: tell the PC we're going away (not unpairing), then drop the socket. */
    fun sayShutdown() {
        session?.sendByeAndClose("shutdown")
    }

    private suspend fun loop() {
        var failures = 0
        val netWatch = graph.scope.launch {
            graph.network.current.map { it?.network }.distinctUntilChanged().drop(1).collect {
                failures = 0
                kick()
            }
        }
        try {
            while (true) {
                val pairing = graph.pairingRepo.current
                if (pairing == null) {
                    _state.value = ConnState.NotPaired
                    graph.pairingRepo.state.first { it != null }
                    continue
                }
                val lan = graph.network.current.value
                if (lan == null) {
                    _state.value = ConnState.NoNetwork(pairing.pcName)
                    graph.network.current.first { it != null }
                    continue
                }
                _state.value = ConnState.Connecting(pairing.pcName)
                var reason: String
                try {
                    val s = connect(pairing, lan)
                    failures = 0
                    session = s
                    _state.value = ConnState.Connected(s.pcName, s.address)
                    s.run()
                    reason = s.closeReason ?: "Connection closed"
                    if (s.unpaired) {
                        graph.onRemotelyUnpaired()
                        continue
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.i(TAG, "connect failed: ${e.javaClass.simpleName}")
                    reason = describe(e)
                    failures++
                } finally {
                    session = null
                }
                val wait = BACKOFF_MS[minOf(failures, BACKOFF_MS.size - 1)]
                _state.value = ConnState.Offline(pairing.pcName, reason, SystemClock.elapsedRealtime() + wait)
                withTimeoutOrNull(wait) { kicks.receive() }
            }
        } finally {
            netWatch.cancel()
        }
    }

    private suspend fun connect(p: PairingRecord, lan: LanNetwork): Session = withContext(Dispatchers.IO) {
        val identity = Identity.get()
        var lastError: Exception? = null
        for (hp in p.addresses) {
            try {
                return@withContext establish(p, lan, hp, identity)
            } catch (e: Exception) {
                lastError = e
            }
        }
        val found = DiscoveryClient.discover(lan, DeviceKeys(p.deviceSecret).discKey, p.addresses.firstOrNull()?.ip)
        if (found != null) {
            try {
                val s = establish(p, lan, found, identity)
                graph.pairingRepo.updateAddresses(listOf(found) + p.addresses)
                return@withContext s
            } catch (e: Exception) {
                lastError = e
            }
        } else if (lastError == null || lastError is SocketTimeoutException || lastError is NoRouteToHostException) {
            lastError = PcNotFoundException()
        }
        throw lastError ?: PcNotFoundException()
    }

    private fun establish(p: PairingRecord, lan: LanNetwork, hp: HostPort, identity: IdentityMaterial): Session {
        val plain = Net.openSocket(lan, hp, 3_000)
        var ssl: SSLSocket? = null
        try {
            plain.soTimeout = 10_000
            plain.getOutputStream().apply {
                write(Preamble.create(Preamble.MODE_SESSION, DeviceKeys(p.deviceSecret).gateKey))
                flush()
            }
            val tls = Tls.clientHandshakeCompat(plain, hp, p.pcFp, identity)
            ssl = tls
            val writer = FrameWriter(tls.outputStream)
            val reader = FrameReader(BufferedInputStream(tls.inputStream, 64 * 1024))
            writer.write(
                FrameType.HELLO,
                Messages.phoneHello(DeviceInfo.name(graph.context), DeviceInfo.model, BuildConfig.VERSION_NAME),
            )
            val f = reader.read()
            if (f.type != FrameType.HELLO) throw ProtocolException("expected HELLO")
            val hello = Messages.parsePcHello(f.body)
            tls.soTimeout = 180_000 // backstop; the keepalive watchdog is the real liveness check
            // Keep the address that just worked first, then whatever the PC advertises.
            graph.pairingRepo.updateAddresses(listOf(hp) + hello.addrs + p.addresses)
            return Session(graph, tls, reader, writer, hello.name, hp)
        } catch (e: Exception) {
            try {
                (ssl ?: plain).close()
            } catch (_: Exception) {
            }
            throw e
        }
    }

    private fun describe(e: Exception): String = when (e) {
        is PcNotFoundException -> "PC not found on this network"
        is PinMismatchException -> "A different device answered at the PC's address"
        is ConnectException -> "Dropper isn't running on the PC"
        is SocketTimeoutException, is NoRouteToHostException -> "PC not reachable"
        is SSLException, is EOFException -> "The PC refused this phone — was it removed on the PC?"
        is ProtocolException -> "Protocol error"
        is IOException -> "PC not reachable"
        else -> "Connection failed"
    }

    class PcNotFoundException : IOException("PC not found")

    private companion object {
        const val TAG = "DropperConn"
        val BACKOFF_MS = longArrayOf(2_000, 5_000, 15_000, 30_000, 60_000, 120_000, 300_000)
    }
}

/** Small adapter so both pairing and sessions use the same TLS entry point. */
internal object Tls {
    fun clientHandshakeCompat(plain: java.net.Socket, hp: HostPort, pin: ByteArray, identity: IdentityMaterial): SSLSocket =
        app.dropper.security.Tls.clientHandshake(plain, hp.ip, hp.port, pin, identity)
}
