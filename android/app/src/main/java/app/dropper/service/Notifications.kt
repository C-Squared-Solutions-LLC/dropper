package app.dropper.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.PersistableBundle
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.dropper.R
import app.dropper.data.HistoryItem
import app.dropper.net.ConnState
import app.dropper.proto.Links
import app.dropper.ui.Format
import app.dropper.ui.MainActivity

object Notifications {
    const val CH_CONNECTION = "connection"
    const val CH_RECEIVED = "received"
    const val ID_SERVICE = 1

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CH_CONNECTION, "Connection status", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while Dropper keeps a secure connection to your PC."
                setShowBadge(false)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_RECEIVED, "Received from PC", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "Files, links and text sent from your PC."
            },
        )
    }

    private fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(
        context, 0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    fun service(context: Context, state: ConnState): Notification {
        val (title, text) = when (state) {
            is ConnState.Connected -> "Connected to ${state.pcName}" to "Ready to send and receive"
            is ConnState.Connecting -> "Connecting to ${state.pcName}…" to "Looking for your PC on this network"
            is ConnState.Offline -> "${state.pcName} not reachable" to state.reason
            is ConnState.NoNetwork -> "Waiting for Wi-Fi" to "Dropper only works on your local network"
            ConnState.NotPaired -> "Not paired" to "Open Dropper to pair with your PC"
            ConnState.Idle -> "Dropper" to "Starting…"
        }
        return NotificationCompat.Builder(context, CH_CONNECTION)
            .setSmallIcon(R.drawable.ic_stat_dropper)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openApp(context))
            .build()
    }

    fun updateService(context: Context, state: ConnState) = post(context, ID_SERVICE, service(context, state))

    fun receivedText(context: Context, item: HistoryItem, pcName: String, copied: Boolean) {
        val text = item.text ?: return
        val url = Links.singleHttpUrl(text)
        val nid = notificationId(item.id)
        val b = NotificationCompat.Builder(context, CH_RECEIVED)
            .setSmallIcon(R.drawable.ic_stat_dropper)
            .setContentTitle(if (url != null) "Link from $pcName" else "Text from $pcName")
            .setContentText(text.take(300))
            .setStyle(NotificationCompat.BigTextStyle().bigText(text.take(1_000)))
            .setSubText(if (copied) "Copied to clipboard" else null)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(
                NotificationCompat.Builder(context, CH_RECEIVED)
                    .setSmallIcon(R.drawable.ic_stat_dropper)
                    .setContentTitle("Received from $pcName")
                    .build(),
            )
        val copyIntent = Intent(context, ActionReceiver::class.java)
            .setAction(ActionReceiver.ACTION_COPY)
            .putExtra(ActionReceiver.EXTRA_ID, item.id)
        b.addAction(
            0, "Copy",
            PendingIntent.getBroadcast(context, nid, copyIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT),
        )
        if (url != null) {
            val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
            b.addAction(
                0, "Open",
                PendingIntent.getActivity(context, nid, view, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT),
            )
        }
        post(context, nid, b.build())
    }

    fun receivedFile(context: Context, item: HistoryItem, pcName: String) {
        val uri = item.uri?.let(Uri::parse) ?: return
        val nid = notificationId(item.id)
        val view = app.dropper.ui.ItemActions.viewIntent(uri, item.name, item.mime)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val b = NotificationCompat.Builder(context, CH_RECEIVED)
            .setSmallIcon(R.drawable.ic_stat_dropper)
            .setContentTitle("Received ${item.name}")
            .setContentText("${Format.size(item.size)} from $pcName · saved to Downloads/Dropper")
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(
                PendingIntent.getActivity(context, nid, view, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT),
            )
        post(context, nid, b.build())
    }

    fun cancel(context: Context, itemId: String) =
        NotificationManagerCompat.from(context).cancel(notificationId(itemId))

    private fun notificationId(itemId: String) = 1000 + (itemId.hashCode() and 0x3fffffff)

    private fun post(context: Context, id: Int, n: Notification) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        try {
            NotificationManagerCompat.from(context).notify(id, n)
        } catch (_: SecurityException) {
        }
    }
}

object Clip {
    /** Copies text; marks it sensitive so Android hides it from the clipboard preview. */
    fun copy(context: Context, text: String, sensitive: Boolean): Boolean = try {
        val clip = ClipData.newPlainText("Dropper", text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        true
    } catch (_: Exception) {
        false
    }
}
