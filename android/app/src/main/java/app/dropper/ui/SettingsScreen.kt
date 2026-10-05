package app.dropper.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.dropper.AppGraph
import app.dropper.BuildConfig
import app.dropper.proto.Fingerprint
import app.dropper.proto.HostPort
import app.dropper.security.Identity
import app.dropper.service.ConnectionService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(graph: AppGraph, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val stay by graph.settings.stayConnected.collectAsStateWithLifecycle()
    val autoCopy by graph.settings.autoCopy.collectAsStateWithLifecycle()
    val pairing by graph.pairingRepo.state.collectAsStateWithLifecycle()

    var phoneFp by remember { mutableStateOf<String?>(null) }
    var keyLevel by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            Identity.existing()?.let {
                phoneFp = Fingerprint.display(it.fingerprint)
                keyLevel = it.securityLevel()
            }
        }
    }

    val power = context.getSystemService(PowerManager::class.java)
    var unrestricted by remember { mutableStateOf(power.isIgnoringBatteryOptimizations(context.packageName)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        unrestricted = power.isIgnoringBatteryOptimizations(context.packageName)
    }

    var showUnpair by remember { mutableStateOf(false) }
    var showAddress by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Section("Connection") {
                SwitchRow(
                    title = "Stay connected",
                    body = "Keep a secure connection to your PC in the background so items arrive instantly. Shows a silent notification.",
                    checked = stay,
                ) {
                    graph.settings.setStayConnected(it)
                    if (it) ConnectionService.start(context)
                }
                HorizontalDivider()
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Background reliability", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            if (unrestricted) "Android won't pause Dropper to save battery."
                            else "Android may pause Dropper in the background. Allow it to keep running so items arrive reliably.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    if (unrestricted) {
                        Icon(Icons.Rounded.CheckCircle, contentDescription = "Allowed", tint = StatusColors.connected)
                    } else {
                        FilledTonalButton(onClick = { requestUnrestricted(context) }) { Text("Allow") }
                    }
                }
                HorizontalDivider()
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("PC address", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            pairing?.addresses?.firstOrNull()?.toString() ?: "—",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { showAddress = true }, enabled = pairing != null) { Text("Edit") }
                }
            }

            Section("Received items") {
                SwitchRow(
                    title = "Copy received text automatically",
                    body = "Text and links from your PC go straight to the clipboard. They're never opened automatically.",
                    checked = autoCopy,
                ) { graph.settings.setAutoCopy(it) }
                HorizontalDivider()
                Text("Files are saved to Download/Dropper.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Section("Security") {
                InfoRow("This phone's key", phoneFp ?: "—", keyLevel?.let { "Stored in: $it" })
                HorizontalDivider()
                InfoRow("Paired PC's key", pairing?.let { Fingerprint.display(it.pcFp) } ?: "—", null)
                HorizontalDivider()
                InfoRow(
                    "Paired with",
                    pairing?.pcName ?: "—",
                    pairing?.let { "Since " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(it.pairedAt)) },
                    monospace = false,
                )
                Text(
                    "These fingerprints should match the ones shown in Dropper on your PC. Everything is encrypted with TLS 1.3 and both sides only accept each other's keys.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Section("Pairing") {
                Text(
                    "Unpairing deletes the pairing, any queued items and this phone's key. If your PC is reachable, it forgets this phone too.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(
                    onClick = { showUnpair = true },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Unpair this phone") }
            }

            Section("Quit") {
                Text(
                    "Stops the background connection and closes Dropper. Nothing arrives until you open it again or share something to it. Your pairing is kept.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val activity = LocalContext.current as? android.app.Activity
                OutlinedButton(onClick = {
                    graph.quit()
                    activity?.finishAffinity()
                }) { Text("Quit Dropper") }
            }

            Text(
                "Dropper ${BuildConfig.VERSION_NAME}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, bottom = 24.dp),
            )
        }
    }

    if (showUnpair) {
        AlertDialog(
            onDismissRequest = { showUnpair = false },
            title = { Text("Unpair this phone?") },
            text = { Text("You'll need to scan a new QR code on your PC to use Dropper again.") },
            confirmButton = {
                TextButton(onClick = {
                    showUnpair = false
                    scope.launch(Dispatchers.IO) { graph.unpair() }
                    onBack()
                }) { Text("Unpair", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { showUnpair = false }) { Text("Cancel") } },
        )
    }

    if (showAddress) {
        var text by remember { mutableStateOf(pairing?.addresses?.firstOrNull()?.toString() ?: "") }
        val parsed = HostPort.parsePrivate(text.trim())
        AlertDialog(
            onDismissRequest = { showAddress = false },
            title = { Text("PC address") },
            text = {
                Column {
                    Text(
                        "Only needed if your PC's address changed and Dropper can't find it automatically. Use the address shown in Dropper on the PC.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it },
                        singleLine = true,
                        isError = text.isNotBlank() && parsed == null,
                        supportingText = { if (text.isNotBlank() && parsed == null) Text("Use a local address like 192.168.1.20:47823") },
                        placeholder = { Text("192.168.1.20:47823") },
                    )
                }
            },
            confirmButton = {
                TextButton(enabled = parsed != null, onClick = {
                    val hp = parsed ?: return@TextButton
                    showAddress = false
                    scope.launch(Dispatchers.IO) {
                        graph.pairingRepo.updateAddresses(listOf(hp) + (pairing?.addresses ?: emptyList()))
                        graph.connection.kick()
                    }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { showAddress = false }) { Text("Cancel") } },
        )
    }
}

@SuppressLint("BatteryLife") // sideloaded personal app; the user explicitly taps "Allow"
private fun requestUnrestricted(context: android.content.Context) {
    try {
        context.startActivity(
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")),
        )
    } catch (_: Exception) {
        context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 4.dp, top = 8.dp),
    )
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) { content() }
    }
}

@Composable
private fun SwitchRow(title: String, body: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun InfoRow(title: String, value: String, detail: String?, monospace: Boolean = true) {
    Column {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
        if (detail != null) {
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
