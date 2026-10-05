package app.dropper.service

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.util.Log
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import app.dropper.AppGraph
import app.dropper.DropperApp
import app.dropper.net.ConnState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/**
 * Foreground service (type connectedDevice) hosting the connection to the PC.
 * Runs while the app is visible, while anything is queued or in flight, and
 * always when "Stay connected" is on. Stops itself 15 s after none apply.
 */
class ConnectionService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var graph: AppGraph

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        graph = DropperApp.graph(this)
        if (graph.quit || !goForeground(graph.connection.state.value)) {
            stopSelf()
            return
        }
        graph.connection.start()
        scope.launch {
            graph.connection.state.collect { st ->
                Notifications.updateService(this@ConnectionService, st)
            }
        }
        scope.launch {
            combine(
                graph.visibility.visibleCount,
                graph.settings.stayConnected,
                graph.outbox.items,
                graph.progress.map,
                graph.pairingRepo.state,
            ) { visible, stay, outbox, progress, pairing ->
                pairing != null && (visible > 0 || stay || outbox.any { it.state == app.dropper.data.OutboxState.PENDING } || progress.isNotEmpty())
            }.distinctUntilChanged().collectLatest { shouldRun ->
                if (!shouldRun) {
                    delay(15_000)
                    Log.i(TAG, "nothing to do; stopping")
                    stopSelf()
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (::graph.isInitialized) {
            goForeground(graph.connection.state.value)
            graph.connection.kick()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        if (::graph.isInitialized) graph.connection.stop()
        scope.cancel()
        super.onDestroy()
    }

    private fun goForeground(state: ConnState): Boolean = try {
        ServiceCompat.startForeground(
            this,
            Notifications.ID_SERVICE,
            Notifications.service(this, state),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        true
    } catch (e: Exception) {
        // e.g. ForegroundServiceStartNotAllowedException when restarted from the background.
        Log.w(TAG, "cannot enter foreground: ${e.javaClass.simpleName}")
        false
    }

    companion object {
        private const val TAG = "DropperService"

        /** Starts (or pokes) the service. Silently ignored if Android doesn't allow it right now. */
        fun start(context: Context) {
            val graph = DropperApp.graph(context)
            if (graph.pairingRepo.current == null || graph.quit) return
            try {
                ContextCompat.startForegroundService(context, Intent(context, ConnectionService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "cannot start service: ${e.javaClass.simpleName}")
            }
        }
    }
}

/** Restarts the connection after boot / app update when "Stay connected" is on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> {
                val graph = DropperApp.graph(context)
                if (graph.settings.stayConnected.value && graph.pairingRepo.current != null) {
                    ConnectionService.start(context)
                }
            }
        }
    }
}

/** Notification actions (not exported; reached only through our immutable PendingIntents). */
class ActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_QUIT) {
            DropperApp.graph(context).quit()
            return
        }
        if (intent.action != ACTION_COPY) return
        val id = intent.getStringExtra(EXTRA_ID) ?: return
        val graph = DropperApp.graph(context)
        val text = graph.history.find(id)?.text ?: return
        if (Clip.copy(context, text, sensitive = true)) {
            Notifications.cancel(context, id)
        }
    }

    companion object {
        const val ACTION_COPY = "app.dropper.action.COPY"
        const val ACTION_QUIT = "app.dropper.action.QUIT"
        const val EXTRA_ID = "id"
    }
}
