package app.dropper.ui

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.dropper.AppGraph
import app.dropper.DropperApp
import app.dropper.data.ItemStatus
import app.dropper.data.OutboxException
import app.dropper.net.ConnState
import app.dropper.proto.TextSanitizer
import app.dropper.service.ConnectionService
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** What another app shared with us, already filtered to what we'll accept. */
class SharedContent(val texts: List<String>, val uris: List<Uri>, val mimeHint: String?) {
    val isEmpty get() = texts.isEmpty() && uris.isEmpty()

    companion object {
        private const val MAX_ITEMS = 100

        fun from(intent: Intent, context: Context): SharedContent {
            val texts = ArrayList<String>()
            val uris = ArrayList<Uri>()
            when (intent.action) {
                Intent.ACTION_SEND -> {
                    IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)?.let { uris += it }
                    intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.takeIf { it.isNotBlank() }?.let { texts += it }
                }
                Intent.ACTION_SEND_MULTIPLE -> {
                    IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)?.let { uris += it }
                    intent.getCharSequenceArrayListExtra(Intent.EXTRA_TEXT)?.forEach { t ->
                        t?.toString()?.takeIf { it.isNotBlank() }?.let { texts += it }
                    }
                }
            }
            if (uris.isEmpty()) {
                intent.clipData?.let { clip -> for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let { uris += it } }
            }
            val accepted = uris.distinct().filter { isAcceptable(it, context) }.take(MAX_ITEMS)
            return SharedContent(texts.take(10), accepted, intent.type)
        }

        /**
         * Only content:// URIs from other apps. file:// is never followed, and our
         * own providers are refused so a malicious share can't make us read (and
         * send) our private files.
         */
        fun isAcceptable(uri: Uri, context: Context): Boolean {
            if (uri.scheme != ContentResolver.SCHEME_CONTENT) return false
            val authority = uri.authority ?: return false
            val pkg = context.packageName
            if (authority == pkg || authority.startsWith("$pkg.")) return false
            val provider = try {
                context.packageManager.resolveContentProvider(authority, 0)
            } catch (_: Exception) {
                null
            }
            return provider?.packageName != pkg
        }
    }
}

class ShareActivity : ComponentActivity() {
    private lateinit var graph: AppGraph

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        graph = DropperApp.graph(this)
        val content = SharedContent.from(intent, this)
        setContent {
            DropperTheme {
                ShareSheet(
                    graph = graph,
                    content = content,
                    onClose = { finish() },
                    onOpenApp = {
                        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        finish()
                    },
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        graph.visibility.onStart()
    }

    override fun onStop() {
        graph.visibility.onStop()
        super.onStop()
    }
}

private sealed interface Phase {
    /** Nothing has been read or queued yet; waiting for the user to tap Send. */
    data object Confirm : Phase
    data object Preparing : Phase
    data object Sending : Phase
    data object NotPaired : Phase
    data class Error(val message: String) : Phase
}

@Composable
private fun ShareSheet(
    graph: AppGraph,
    content: SharedContent,
    onClose: () -> Unit,
    onOpenApp: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val pairing by graph.pairingRepo.state.collectAsStateWithLifecycle()
    val history by graph.history.items.collectAsStateWithLifecycle()
    val progress by graph.progress.map.collectAsStateWithLifecycle()
    var phase by remember { mutableStateOf<Phase>(Phase.Confirm) }
    var submitted by rememberSaveable { mutableStateOf(false) }
    var ids by remember { mutableStateOf<List<String>>(emptyList()) }
    var warnings by remember { mutableStateOf<List<String>>(emptyList()) }
    var queuedHint by remember { mutableStateOf(false) }
    val firstFileName = remember(content) { content.uris.firstOrNull()?.let { displayName(context, it) } }

    LaunchedEffect(Unit) {
        when {
            graph.pairingRepo.current == null -> phase = Phase.NotPaired
            submitted -> onClose() // recreated after sending started: the items are already queued
            content.isEmpty -> phase = Phase.Error("There's nothing here Dropper can send.")
            else -> phase = Phase.Confirm
        }
    }

    // Any app can open this screen directly, so nothing is read or queued until the user taps Send.
    fun send() = scope.launch {
        submitted = true
        phase = Phase.Preparing
        graph.resume() // sharing after Quit is an explicit request to connect again
        val newIds = ArrayList<String>()
        val errors = ArrayList<String>()
        for (t in content.texts) {
            try {
                newIds += graph.outbox.enqueueText(t).id
            } catch (e: OutboxException) {
                errors += e.message ?: "Couldn't add text"
            }
        }
        for (u in content.uris) {
            try {
                newIds += graph.outbox.importUri(context.contentResolver, u, content.mimeHint).id
            } catch (e: OutboxException) {
                errors += e.message ?: "Couldn't add a file"
            }
        }
        warnings = errors
        ids = newIds
        if (newIds.isEmpty()) {
            phase = Phase.Error(errors.firstOrNull() ?: "Nothing could be sent.")
            return@launch
        }
        ConnectionService.start(context)
        phase = Phase.Sending
        delay(6_000)
        if (graph.connection.state.value !is ConnState.Connected) queuedHint = true
    }

    val items = ids.mapNotNull { id -> history.firstOrNull { it.id == id } }
    val delivered = items.count { it.status == ItemStatus.DELIVERED }
    val failed = items.filter { it.status == ItemStatus.FAILED }
    val allDone = ids.isNotEmpty() && delivered == ids.size
    val fraction = if (ids.isEmpty()) 0f else ids.sumOf { id ->
        val it = items.firstOrNull { h -> h.id == id }
        when {
            it == null -> 0.0
            it.status == ItemStatus.DELIVERED -> 1.0
            else -> (progress[id] ?: 0f).toDouble()
        }
    }.toFloat() / ids.size

    LaunchedEffect(allDone) {
        if (allDone) {
            delay(1_200)
            onClose()
        }
    }

    val pcName = pairing?.pcName ?: "your PC"
    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.4f))
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null, onClick = onClose)
            .safeDrawingPadding(),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier
                .widthIn(max = 440.dp)
                .fillMaxWidth()
                .padding(24.dp)
                .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) { },
        ) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                when (val p = phase) {
                    Phase.Confirm -> {
                        Header(
                            Icons.AutoMirrored.Rounded.Send,
                            "Send to $pcName?",
                            confirmSummary(content, firstFileName),
                        )
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = onClose) { Text("Cancel") }
                            Spacer(Modifier.width(8.dp))
                            Button(onClick = { send() }, enabled = !content.isEmpty) { Text("Send") }
                        }
                    }
                    Phase.NotPaired -> {
                        Header(Icons.Rounded.ErrorOutline, "Dropper isn't paired yet", "Pair with your PC first, then share again.", error = true)
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = onClose) { Text("Close") }
                            Spacer(Modifier.width(8.dp))
                            Button(onClick = onOpenApp) { Text("Open Dropper") }
                        }
                    }
                    is Phase.Error -> {
                        Header(Icons.Rounded.ErrorOutline, "Couldn't send", p.message, error = true)
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = onClose) { Text("Close") }
                        }
                    }
                    Phase.Preparing -> {
                        Header(Icons.AutoMirrored.Rounded.Send, "Sending to $pcName", "Preparing…")
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                    }
                    Phase.Sending -> {
                        val summary = summarize(items.size, items.sumOf { it.size }, items.firstOrNull()?.let {
                            if (it.text != null) Format.preview(it.text, 60) else it.name
                        })
                        when {
                            allDone -> Header(Icons.Rounded.CheckCircle, "Sent to $pcName", summary, success = true)
                            failed.isNotEmpty() -> Header(
                                Icons.Rounded.ErrorOutline, "Some items failed",
                                failed.first().error ?: "Delivery failed", error = true,
                            )
                            queuedHint && delivered == 0 && fraction == 0f -> Header(
                                Icons.Rounded.Schedule, "Queued", "$pcName isn't reachable right now. Dropper will send it as soon as it is.",
                            )
                            else -> Header(Icons.AutoMirrored.Rounded.Send, "Sending to $pcName", summary)
                        }
                        if (!allDone && failed.isEmpty()) {
                            if (fraction > 0f) LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                            else LinearProgressIndicator(Modifier.fillMaxWidth())
                        }
                        if (warnings.isNotEmpty()) {
                            Text(warnings.first(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                        }
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = onClose) { Text(if (allDone || failed.isNotEmpty()) "Done" else "Hide") }
                        }
                    }
                }
            }
        }
    }
}

/** What the user is about to send, shown before anything is read or queued. */
private fun confirmSummary(content: SharedContent, firstFileName: String?): String {
    val parts = ArrayList<String>()
    if (content.texts.isNotEmpty()) {
        parts += "“" + Format.preview(content.texts.first(), 120) + "”" +
            if (content.texts.size > 1) " and ${content.texts.size - 1} more" else ""
    }
    when (content.uris.size) {
        0 -> Unit
        1 -> parts += firstFileName ?: "1 file"
        else -> parts += "${content.uris.size} files" + (firstFileName?.let { ", starting with $it" } ?: "")
    }
    return parts.joinToString(" · ")
}

/** Display name of a shared content:// item, or null if the sharing app won't say. */
private fun displayName(context: Context, uri: Uri): String? = try {
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0)?.let { TextSanitizer.displayName(it).takeIf { n -> n.isNotEmpty() } } else null
    }
} catch (_: Exception) {
    null
}

private fun summarize(count: Int, bytes: Long, first: String?): String = when {
    count == 0 -> ""
    count == 1 && first != null -> first
    else -> "$count items · ${Format.size(bytes)}"
}

@Composable
private fun Header(icon: ImageVector, title: String, body: String, error: Boolean = false, success: Boolean = false) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        val bg = when {
            error -> MaterialTheme.colorScheme.errorContainer
            success -> StatusColors.connected.copy(alpha = 0.18f)
            else -> MaterialTheme.colorScheme.primaryContainer
        }
        val fg = when {
            error -> MaterialTheme.colorScheme.onErrorContainer
            success -> StatusColors.connected
            else -> MaterialTheme.colorScheme.onPrimaryContainer
        }
        Box(
            Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(bg),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, contentDescription = null, tint = fg) }
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(2.dp))
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
