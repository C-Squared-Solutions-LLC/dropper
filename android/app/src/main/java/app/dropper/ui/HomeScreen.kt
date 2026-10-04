package app.dropper.ui

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.AttachFile
import androidx.compose.material.icons.rounded.AudioFile
import androidx.compose.material.icons.rounded.Computer
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.FolderZip
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Inbox
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Movie
import androidx.compose.material.icons.rounded.PictureAsPdf
import androidx.compose.material.icons.rounded.TextFields
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.dropper.AppGraph
import app.dropper.data.Direction
import app.dropper.data.HistoryItem
import app.dropper.data.ItemKind
import app.dropper.data.ItemStatus
import app.dropper.data.OutboxException
import app.dropper.net.ConnState
import app.dropper.proto.Links
import app.dropper.service.ConnectionService
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(graph: AppGraph, onOpenSettings: () -> Unit) {
    val context = LocalContext.current
    val conn by graph.connection.state.collectAsStateWithLifecycle()
    val history by graph.history.items.collectAsStateWithLifecycle()
    val progress by graph.progress.map.collectAsStateWithLifecycle()
    val pairing by graph.pairingRepo.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var draft by rememberSaveable { mutableStateOf("") }

    // Ask for notification permission once, at the point we start delivering things.
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (!graph.settings.notificationsAsked &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            graph.settings.notificationsAsked = true
            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    fun enqueueUris(uris: List<Uri>) {
        scope.launch {
            for (u in uris) {
                try {
                    graph.outbox.importUri(context.contentResolver, u, null)
                } catch (e: OutboxException) {
                    snackbar.showSnackbar(e.message ?: "Couldn't add that file")
                }
            }
            ConnectionService.start(context)
        }
    }

    fun sendText(text: String) {
        if (text.isBlank()) return
        try {
            graph.outbox.enqueueText(text)
            ConnectionService.start(context)
        } catch (e: OutboxException) {
            scope.launch { snackbar.showSnackbar(e.message ?: "Couldn't send that text") }
        }
    }

    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) enqueueUris(uris)
    }
    val pickMedia = rememberLauncherForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(50)) { uris ->
        if (uris.isNotEmpty()) enqueueUris(uris)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Dropper") },
                actions = {
                    IconButton(onClick = onOpenSettings) { Icon(Icons.Outlined.Settings, contentDescription = "Settings") }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .imePadding(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 4.dp,
                bottom = padding.calculateBottomPadding() + 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "status") {
                StatusCard(conn, pairing?.pcName) {
                    graph.connection.kick()
                    ConnectionService.start(context)
                }
            }
            item(key = "actions") {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    ActionTile(Icons.Rounded.AttachFile, "Files", Modifier.weight(1f)) { pickFiles.launch(arrayOf("*/*")) }
                    ActionTile(Icons.Rounded.Image, "Photos", Modifier.weight(1f)) {
                        pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo))
                    }
                    ActionTile(Icons.Rounded.ContentPaste, "Clipboard", Modifier.weight(1f)) {
                        val text = readClipboard(context)
                        if (text.isNullOrBlank()) scope.launch { snackbar.showSnackbar("Your clipboard is empty") }
                        else sendText(text)
                    }
                }
            }
            item(key = "compose") {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Type a message or paste a link") },
                    maxLines = 5,
                    shape = RoundedCornerShape(16.dp),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Sentences,
                        imeAction = ImeAction.Send,
                    ),
                    keyboardActions = KeyboardActions(onSend = {
                        sendText(draft)
                        draft = ""
                    }),
                    trailingIcon = {
                        IconButton(
                            onClick = {
                                sendText(draft)
                                draft = ""
                            },
                            enabled = draft.isNotBlank(),
                        ) { Icon(Icons.AutoMirrored.Rounded.Send, contentDescription = "Send to PC") }
                    },
                )
            }
            item(key = "header") {
                Text(
                    "Activity",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 4.dp, top = 8.dp),
                )
            }
            if (history.isEmpty()) {
                item(key = "empty") { EmptyState() }
            }
            items(history, key = { it.id }) { item ->
                HistoryRow(item, progress[item.id], graph)
            }
        }
    }
}

private fun readClipboard(context: Context): String? = try {
    context.getSystemService(ClipboardManager::class.java).primaryClip
        ?.takeIf { it.itemCount > 0 }
        ?.getItemAt(0)
        ?.coerceToText(context)
        ?.toString()
} catch (_: Exception) {
    null
}

@Composable
private fun StatusCard(state: ConnState, pcName: String?, onRetry: () -> Unit) {
    val (dot, line) = when (state) {
        is ConnState.Connected -> StatusColors.connected to "Connected · ${state.address.ip}"
        is ConnState.Connecting -> StatusColors.connecting to "Connecting…"
        is ConnState.Offline -> StatusColors.offline to state.reason
        is ConnState.NoNetwork -> StatusColors.offline to "Connect to your home Wi-Fi"
        ConnState.NotPaired -> StatusColors.offline to "Not paired"
        ConnState.Idle -> StatusColors.connecting to "Starting…"
    }
    val name = (state as? ConnState.Connected)?.pcName ?: pcName ?: "Your PC"
    ElevatedCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.Computer, contentDescription = null, tint = MaterialTheme.colorScheme.onPrimaryContainer)
            }
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(dot),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        line,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            if (state is ConnState.Offline || state is ConnState.NoNetwork) {
                TextButton(onClick = onRetry) { Text("Retry") }
            }
        }
    }
}

@Composable
private fun ActionTile(icon: ImageVector, label: String, modifier: Modifier, onClick: () -> Unit) {
    FilledTonalButton(
        onClick = onClick,
        modifier = modifier.height(76.dp),
        shape = RoundedCornerShape(18.dp),
        contentPadding = PaddingValues(4.dp),
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null)
            Spacer(Modifier.height(6.dp))
            Text(label, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun EmptyState() {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Rounded.Inbox,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text("Nothing here yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            "Share anything to Dropper from any app, or send from your PC.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun iconFor(item: HistoryItem): ImageVector {
    if (item.kind == ItemKind.TEXT) {
        return if (item.text?.let { Links.singleHttpUrl(it) } != null) Icons.Rounded.Link else Icons.Rounded.TextFields
    }
    val m = item.mime
    return when {
        m.startsWith("image/") -> Icons.Rounded.Image
        m.startsWith("video/") -> Icons.Rounded.Movie
        m.startsWith("audio/") -> Icons.Rounded.AudioFile
        m == "application/pdf" -> Icons.Rounded.PictureAsPdf
        m.contains("zip") || m.contains("compressed") || m.contains("x-7z") || m.contains("x-rar") -> Icons.Rounded.FolderZip
        else -> Icons.Rounded.Description
    }
}

@Composable
private fun HistoryRow(item: HistoryItem, progress: Float?, graph: AppGraph) {
    val context = LocalContext.current
    var menuOpen by remember { mutableStateOf(false) }
    val url = item.text?.let { Links.singleHttpUrl(it) }
    val isReceivedFile = item.kind == ItemKind.FILE && item.direction == Direction.IN && item.status == ItemStatus.RECEIVED
    val inOutbox = item.direction == Direction.OUT && graph.outbox.find(item.id) != null

    val title = if (item.kind == ItemKind.TEXT) Format.preview(item.text ?: "") else item.name
    val who = if (item.direction == Direction.IN) "From PC" else "To PC"
    val what = if (item.kind == ItemKind.TEXT) (if (url != null) "Link" else "Text") else Format.size(item.size)
    val pct = progress?.let { " ${(it * 100).toInt()}%" } ?: ""
    val (statusText, statusColor) = when (item.status) {
        ItemStatus.QUEUED -> "Queued" to MaterialTheme.colorScheme.onSurfaceVariant
        ItemStatus.SENDING -> "Sending$pct" to MaterialTheme.colorScheme.primary
        ItemStatus.RECEIVING -> "Receiving$pct" to MaterialTheme.colorScheme.primary
        ItemStatus.DELIVERED -> "Delivered" to MaterialTheme.colorScheme.onSurfaceVariant
        ItemStatus.RECEIVED -> Format.time(context, item.time) to MaterialTheme.colorScheme.onSurfaceVariant
        ItemStatus.FAILED -> ("Failed" + (item.error?.let { " — $it" } ?: "")) to MaterialTheme.colorScheme.error
    }

    val onClick: () -> Unit = when {
        url != null -> { { ItemActions.openLink(context, url) } }
        item.kind == ItemKind.TEXT -> { { ItemActions.copy(context, item.text ?: "") } }
        isReceivedFile -> { { ItemActions.openFile(context, item) } }
        else -> { { menuOpen = true } }
    }

    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(start = 12.dp, top = 12.dp, bottom = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Box {
                Box(
                    Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.secondaryContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(iconFor(item), contentDescription = null, tint = MaterialTheme.colorScheme.onSecondaryContainer)
                }
                Box(
                    Modifier
                        .align(Alignment.BottomEnd)
                        .offset(x = 4.dp, y = 4.dp)
                        .size(18.dp)
                        .clip(CircleShape)
                        .background(if (item.direction == Direction.IN) StatusColors.connected else MaterialTheme.colorScheme.primary),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        if (item.direction == Direction.IN) Icons.Rounded.ArrowDownward else Icons.Rounded.ArrowUpward,
                        contentDescription = if (item.direction == Direction.IN) "Received" else "Sent",
                        tint = Color.White,
                        modifier = Modifier.size(12.dp),
                    )
                }
            }
            Column(
                Modifier
                    .weight(1f)
                    .padding(horizontal = 14.dp),
            ) {
                Text(title.ifEmpty { "(empty)" }, style = MaterialTheme.typography.bodyLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(2.dp))
                Text(
                    "$who · $what · $statusText",
                    style = MaterialTheme.typography.bodySmall,
                    color = statusColor,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (progress != null && (item.status == ItemStatus.SENDING || item.status == ItemStatus.RECEIVING)) {
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                }
            }
            Box {
                IconButton(onClick = { menuOpen = true }) { Icon(Icons.Rounded.MoreVert, contentDescription = "More") }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    fun entry(label: String, action: () -> Unit) = @Composable {
                        DropdownMenuItem(text = { Text(label) }, onClick = {
                            menuOpen = false
                            action()
                        })
                    }
                    if (item.kind == ItemKind.TEXT) entry("Copy") { ItemActions.copy(context, item.text ?: "") }()
                    if (url != null) entry("Open link") { ItemActions.openLink(context, url) }()
                    if (isReceivedFile) entry("Open") { ItemActions.openFile(context, item) }()
                    if (item.kind == ItemKind.TEXT || isReceivedFile) entry("Share") { ItemActions.share(context, item) }()
                    if (inOutbox && item.status == ItemStatus.FAILED) {
                        entry("Retry") {
                            graph.outbox.retry(item.id)
                            ConnectionService.start(context)
                        }()
                    }
                    if (inOutbox && item.status == ItemStatus.QUEUED) entry("Cancel") { graph.outbox.remove(item.id) }()
                    if (inOutbox && item.status == ItemStatus.FAILED) entry("Remove") { graph.outbox.remove(item.id) }()
                    if (!inOutbox && item.status != ItemStatus.RECEIVING) entry("Remove from list") { graph.history.remove(item.id) }()
                }
            }
        }
    }
}
