package app.dropper

import android.app.Application
import android.content.Context
import app.dropper.data.HistoryRepository
import app.dropper.data.Outbox
import app.dropper.data.PairingRepository
import app.dropper.data.SettingsRepository
import app.dropper.data.TransferProgress
import app.dropper.data.Visibility
import app.dropper.net.ConnectionManager
import app.dropper.net.NetworkMonitor
import app.dropper.net.PairingController
import app.dropper.security.Identity
import app.dropper.security.SecureStore
import app.dropper.service.Notifications
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

class DropperApp : Application() {
    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = AppGraph(this)
        Notifications.createChannels(this)
    }

    companion object {
        fun graph(context: Context): AppGraph = (context.applicationContext as DropperApp).graph
    }
}

/** Process-wide singletons. */
class AppGraph(val context: Context) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val store = SecureStore(context)
    val settings = SettingsRepository(context)
    val pairingRepo = PairingRepository(store)
    val history = HistoryRepository(store, scope)
    val outbox = Outbox(context, store, history)
    val progress = TransferProgress()
    val visibility = Visibility()
    val network = NetworkMonitor(context)
    val receivedIds = RecentIds(500)
    val connection = ConnectionManager(this)
    val pairing = PairingController(this)

    /**
     * Unpair from the phone side: tell the PC (best effort), then wipe the
     * pairing, the device secret, the queued items and the identity key. A new
     * identity is generated at the next pairing, so the old PC can't link it.
     */
    fun unpair() {
        connection.sayGoodbye()
        connection.stop()
        wipePairing()
    }

    /** The PC sent BYE "unpaired". */
    fun onRemotelyUnpaired() {
        wipePairing()
        pairing.notice.value = "Your PC removed this phone. Scan a new QR code to pair again."
    }

    private fun wipePairing() {
        pairingRepo.clear()
        outbox.clearAll()
        try {
            Identity.reset()
        } catch (_: Exception) {
        }
    }
}

/** Bounded memory of recently completed incoming item ids (dedupe, §9). */
class RecentIds(private val capacity: Int) {
    private val set = LinkedHashSet<String>()

    @Synchronized
    fun add(id: String) {
        set.remove(id)
        set.add(id)
        while (set.size > capacity) set.remove(set.first())
    }

    @Synchronized
    fun contains(id: String) = id in set
}
