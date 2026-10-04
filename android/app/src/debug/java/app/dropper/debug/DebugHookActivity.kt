package app.dropper.debug

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import app.dropper.DropperApp
import app.dropper.proto.Crypto
import app.dropper.proto.PairingUri
import app.dropper.service.ConnectionService
import app.dropper.ui.MainActivity
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * DEBUG-ONLY test hook (src/debug). Extras:
 *   pair_uri    (string)  run the normal pairing flow with this QR payload
 *   send_random (int)     queue a file of N random bytes ("debug-random-N.bin")
 *   send_text   (string)  queue a text item
 *   dump        (boolean) log connection state + recent activity to tag DropperDebug
 */
class DebugHookActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(extras: Intent) {
        val graph = DropperApp.graph(this)

        extras.getStringExtra("pair_uri")?.let { raw ->
            when (val p = PairingUri.parse(raw)) {
                is PairingUri.Parsed.Ok -> {
                    Log.i(TAG, "pair_uri accepted; pairing with ${p.invite.addresses}")
                    graph.pairing.start(p.invite)
                    startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }
                is PairingUri.Parsed.Invalid -> Log.w(TAG, "pair_uri rejected: ${p.reason}")
            }
        }

        // Start the service while this activity is still visible (FGS start rules).
        ConnectionService.start(this)

        if (extras.hasExtra("send_random")) {
            val n = extras.getIntExtra("send_random", -1)
            if (n >= 0) {
                graph.scope.launch {
                    val rng = SecureRandom()
                    val md = MessageDigest.getInstance("SHA-256")
                    val item = graph.outbox.importGenerated("debug-random-$n.bin", n.toLong()) { buf, len ->
                        val chunk = ByteArray(len).also(rng::nextBytes)
                        System.arraycopy(chunk, 0, buf, 0, len)
                        md.update(chunk)
                    }
                    Log.i(TAG, "queued file id=${item.id} name=${item.name} size=$n sha256=${Crypto.hex(md.digest())}")
                }
            }
        }

        extras.getStringExtra("send_text")?.let { text ->
            val item = graph.outbox.enqueueText(text)
            Log.i(TAG, "queued text id=${item.id} bytes=${item.size} sha256=${Crypto.hex(Crypto.sha256(text.toByteArray()))}")
        }

        if (extras.getBooleanExtra("dump", false)) {
            Log.i(TAG, "state=${graph.connection.state.value} paired=${graph.pairingRepo.current != null}")
            Log.i(TAG, "outbox=${graph.outbox.items.value.map { "${it.id.take(8)}:${it.state}:${it.attempts}" }}")
            graph.history.items.value.take(20).forEach { h ->
                val textInfo = h.text?.let { " textBytes=${it.toByteArray().size} textSha256=${Crypto.hex(Crypto.sha256(it.toByteArray()))}" } ?: ""
                Log.i(TAG, "history id=${h.id} dir=${h.direction} kind=${h.kind} name=${h.name} size=${h.size} status=${h.status} error=${h.error}$textInfo")
            }
        }
        finish()
    }

    private companion object {
        const val TAG = "DropperDebug"
    }
}
