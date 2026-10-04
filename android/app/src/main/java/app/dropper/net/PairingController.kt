package app.dropper.net

import android.util.Log
import app.dropper.AppGraph
import app.dropper.data.PairingRecord
import app.dropper.proto.FrameReader
import app.dropper.proto.FrameType
import app.dropper.proto.FrameWriter
import app.dropper.proto.Messages
import app.dropper.proto.PairingInvite
import app.dropper.proto.PairingKeys
import app.dropper.proto.Preamble
import app.dropper.proto.ProtocolException
import app.dropper.security.Identity
import app.dropper.security.PinMismatchException
import app.dropper.service.ConnectionService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.EOFException
import java.net.ConnectException
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException

sealed interface PairingUi {
    data object Idle : PairingUi
    data class Connecting(val pcName: String) : PairingUi
    data class AwaitingApproval(val pcName: String, val sas: String) : PairingUi
    data class Failed(val message: String) : PairingUi
}

/**
 * Runs the pairing exchange (PROTOCOL.md §6.1 mode 2, §8.2): pinned TLS to the
 * key from the QR code, PAIR_REQUEST with a proof binding the QR secret to this
 * phone's key, then wait for the user to approve on the PC.
 */
class PairingController(private val graph: AppGraph) {
    private val _state = MutableStateFlow<PairingUi>(PairingUi.Idle)
    val state: StateFlow<PairingUi> = _state.asStateFlow()

    /** One-shot message for the pairing screen (e.g. "your PC removed this phone"). */
    val notice = MutableStateFlow<String?>(null)

    private var job: Job? = null

    @Volatile
    private var activeSocket: Socket? = null

    @Synchronized
    fun start(invite: PairingInvite) {
        cancel()
        notice.value = null
        job = graph.scope.launch(Dispatchers.IO) { run(invite) }
    }

    @Synchronized
    fun cancel() {
        job?.cancel()
        job = null
        try {
            activeSocket?.close()
        } catch (_: Exception) {
        }
        activeSocket = null
        _state.value = PairingUi.Idle
    }

    fun dismissError() {
        if (_state.value is PairingUi.Failed) _state.value = PairingUi.Idle
    }

    private suspend fun run(invite: PairingInvite) {
        _state.value = PairingUi.Connecting(invite.pcName)
        try {
            val lan = graph.network.current.value
                ?: return fail("Connect this phone to the same Wi-Fi network as your PC, then scan again.")
            val identity = Identity.get()
            val keys = PairingKeys(invite.secret)
            val sas = PairingKeys.formatSas(keys.sas(invite.pcFp, identity.fingerprint))

            var lastError: Exception? = null
            for (hp in invite.addresses) {
                val plain = try {
                    Net.openSocket(lan, hp, 4_000)
                } catch (e: Exception) {
                    lastError = e
                    continue
                }
                activeSocket = plain
                try {
                    plain.soTimeout = 10_000
                    plain.getOutputStream().apply {
                        write(Preamble.create(Preamble.MODE_PAIRING, keys.gateKey))
                        flush()
                    }
                    val ssl = Tls.clientHandshakeCompat(plain, hp, invite.pcFp, identity)
                    activeSocket = ssl
                    ssl.use {
                        val writer = FrameWriter(ssl.outputStream)
                        val reader = FrameReader(BufferedInputStream(ssl.inputStream))
                        writer.write(
                            FrameType.PAIR_REQUEST,
                            Messages.pairRequest(
                                DeviceInfo.name(graph.context),
                                DeviceInfo.model,
                                keys.proof(invite.pcFp, identity.fingerprint),
                            ),
                        )
                        _state.value = PairingUi.AwaitingApproval(invite.pcName, sas)
                        ssl.soTimeout = 150_000
                        val f = reader.read()
                        when (f.type) {
                            FrameType.PAIR_OK -> {
                                val ok = Messages.parsePairOk(f.body)
                                graph.pairingRepo.save(
                                    PairingRecord(
                                        pcFp = invite.pcFp,
                                        pcName = ok.name,
                                        addresses = (listOf(hp) + invite.addresses).distinct(),
                                        deviceSecret = ok.secret,
                                        pairedAt = System.currentTimeMillis(),
                                    ),
                                )
                                _state.value = PairingUi.Idle
                                ConnectionService.start(graph.context)
                            }
                            FrameType.PAIR_FAIL -> fail(describeFail(Messages.parsePairFail(f.body)))
                            else -> throw ProtocolException("unexpected frame")
                        }
                    }
                    return
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    try {
                        plain.close()
                    } catch (_: Exception) {
                    }
                    if (_state.value is PairingUi.AwaitingApproval || e is PinMismatchException) {
                        // Got past TLS to the right/wrong PC: no point trying other addresses.
                        return fail(describeError(e, invite.pcName))
                    }
                    lastError = e
                } finally {
                    activeSocket = null
                }
            }
            fail(describeError(lastError, invite.pcName))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "pairing failed: ${e.javaClass.simpleName}")
            fail(describeError(e, invite.pcName))
        }
    }

    private fun fail(message: String) {
        _state.value = PairingUi.Failed(message)
    }

    private fun describeFail(error: String): String = when (error) {
        "rejected" -> "Pairing was declined on your PC."
        "timeout" -> "Nobody approved the pairing on the PC in time. Try again."
        "expired" -> "That QR code has expired. Click “Pair a phone” on your PC to get a new one."
        "bad_proof" -> "Your PC couldn't verify this phone. Scan a fresh QR code."
        "busy" -> "Your PC is already pairing with another device."
        else -> "Pairing failed ($error)."
    }

    private fun describeError(e: Exception?, pcName: String): String = when (e) {
        is PinMismatchException -> "The device that answered isn't the PC from the QR code. Pairing was stopped to keep you safe."
        is SocketTimeoutException ->
            if (_state.value is PairingUi.AwaitingApproval) "Nobody approved the pairing on the PC in time."
            else "Couldn't reach $pcName. Make sure this phone is on the same Wi-Fi network."
        is ConnectException -> "Couldn't reach Dropper on $pcName. Is the app running and allowed through the firewall?"
        is SSLException, is EOFException ->
            "$pcName refused the connection. The QR code may have expired or already been used — generate a new one."
        is ProtocolException -> "Unexpected response from $pcName."
        null -> "Couldn't reach $pcName."
        else -> "Couldn't reach $pcName. Make sure this phone is on the same Wi-Fi network."
    }

    private companion object {
        const val TAG = "DropperPairing"
    }
}
