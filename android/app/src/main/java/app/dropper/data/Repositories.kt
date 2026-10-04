package app.dropper.data

import android.content.Context
import app.dropper.proto.Crypto
import app.dropper.proto.HostPort
import app.dropper.security.SecureStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/** The paired PC (pin + device secret), encrypted at rest. */
class PairingRepository(private val store: SecureStore) {
    private val _state = MutableStateFlow(load())
    val state: StateFlow<PairingRecord?> = _state.asStateFlow()

    val current: PairingRecord? get() = _state.value

    @Synchronized
    fun save(record: PairingRecord) {
        val o = JSONObject()
            .put("v", 1)
            .put("pc_fp", Crypto.b64u(record.pcFp))
            .put("pc_name", record.pcName)
            .put("addrs", JSONArray(record.addresses.map { it.toString() }))
            .put("secret", Crypto.b64u(record.deviceSecret))
            .put("paired_at", record.pairedAt)
        store.write(FILE, o.toString().toByteArray(Charsets.UTF_8))
        _state.value = record
    }

    /** Replace the address list, keeping at most 4 unique entries. No-op if unchanged. */
    @Synchronized
    fun updateAddresses(addresses: List<HostPort>) {
        val cur = _state.value ?: return
        val list = addresses.distinct().take(4)
        if (list.isEmpty() || list == cur.addresses) return
        save(cur.withAddresses(list))
    }

    @Synchronized
    fun clear() {
        store.delete(FILE)
        _state.value = null
    }

    private fun load(): PairingRecord? {
        val raw = store.read(FILE) ?: return null
        return try {
            val o = JSONObject(String(raw, Charsets.UTF_8))
            val arr = o.getJSONArray("addrs")
            val addrs = (0 until arr.length()).mapNotNull { HostPort.parsePrivate(arr.getString(it)) }
            PairingRecord(
                pcFp = Crypto.b64uDecode(o.getString("pc_fp"), 32) ?: return null,
                pcName = o.getString("pc_name"),
                addresses = addrs,
                deviceSecret = Crypto.b64uDecode(o.getString("secret"), 32) ?: return null,
                pairedAt = o.optLong("paired_at", 0L),
            )
        } catch (_: Exception) {
            null
        }
    }

    private companion object {
        const val FILE = "pairing.bin"
    }
}

/** Non-secret preferences. */
class SettingsRepository(context: Context) {
    private val prefs = context.getSharedPreferences("dropper_settings", Context.MODE_PRIVATE)

    private val _stayConnected = MutableStateFlow(prefs.getBoolean(KEY_STAY, true))
    val stayConnected: StateFlow<Boolean> = _stayConnected.asStateFlow()

    private val _autoCopy = MutableStateFlow(prefs.getBoolean(KEY_COPY, true))
    val autoCopy: StateFlow<Boolean> = _autoCopy.asStateFlow()

    var notificationsAsked: Boolean
        get() = prefs.getBoolean(KEY_NOTIF_ASKED, false)
        set(v) = prefs.edit().putBoolean(KEY_NOTIF_ASKED, v).apply()

    fun setStayConnected(v: Boolean) {
        prefs.edit().putBoolean(KEY_STAY, v).apply()
        _stayConnected.value = v
    }

    fun setAutoCopy(v: Boolean) {
        prefs.edit().putBoolean(KEY_COPY, v).apply()
        _autoCopy.value = v
    }

    private companion object {
        const val KEY_STAY = "stay_connected"
        const val KEY_COPY = "auto_copy"
        const val KEY_NOTIF_ASKED = "notif_asked"
    }
}

/** Activity list (last 200 items), encrypted at rest, saved with a short debounce. */
class HistoryRepository(private val store: SecureStore, scope: CoroutineScope) {
    private val _items = MutableStateFlow<List<HistoryItem>>(emptyList())
    val items: StateFlow<List<HistoryItem>> = _items.asStateFlow()
    private val saves = Channel<Unit>(Channel.CONFLATED)

    init {
        scope.launch(Dispatchers.IO) {
            val loaded = load().map {
                // Anything mid-flight when the process died didn't finish.
                when (it.status) {
                    ItemStatus.RECEIVING -> it.copy(status = ItemStatus.FAILED, error = "interrupted")
                    ItemStatus.SENDING -> it.copy(status = ItemStatus.QUEUED)
                    else -> it
                }
            }
            _items.update { current -> (current + loaded).distinctBy { it.id }.take(MAX) }
            for (unused in saves) {
                delay(400)
                save()
            }
        }
    }

    fun find(id: String): HistoryItem? = _items.value.firstOrNull { it.id == id }

    fun add(item: HistoryItem) {
        val stored = item.copy(text = item.text?.let { if (it.length > MAX_TEXT_CHARS) it.take(MAX_TEXT_CHARS) else it })
        _items.update { list -> (listOf(stored) + list.filterNot { it.id == item.id }).take(MAX) }
        saves.trySend(Unit)
    }

    fun update(id: String, transform: (HistoryItem) -> HistoryItem) {
        _items.update { list -> list.map { if (it.id == id) transform(it) else it } }
        saves.trySend(Unit)
    }

    fun remove(id: String) {
        _items.update { list -> list.filterNot { it.id == id } }
        saves.trySend(Unit)
    }

    fun clear() {
        _items.value = emptyList()
        store.delete(FILE)
    }

    private fun save() {
        val arr = JSONArray()
        _items.value.forEach { arr.put(it.toJson()) }
        try {
            store.write(FILE, arr.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {
        }
    }

    private fun load(): List<HistoryItem> {
        val raw = store.read(FILE) ?: return emptyList()
        return try {
            val arr = JSONArray(String(raw, Charsets.UTF_8))
            (0 until arr.length()).mapNotNull { HistoryItem.fromJson(arr.getJSONObject(it)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private companion object {
        const val FILE = "history.bin"
        const val MAX = 200
        const val MAX_TEXT_CHARS = 262_144
    }
}

/** Live progress (0..1) of transfers in flight, keyed by item id. Not persisted. */
class TransferProgress {
    private val _map = MutableStateFlow<Map<String, Float>>(emptyMap())
    val map: StateFlow<Map<String, Float>> = _map.asStateFlow()

    fun set(id: String, fraction: Float) = _map.update { it + (id to fraction.coerceIn(0f, 1f)) }
    fun clear(id: String) = _map.update { it - id }
}

/** Counts visible activities so the service knows whether the app is in the foreground. */
class Visibility {
    private val _visible = MutableStateFlow(0)
    val visibleCount: StateFlow<Int> = _visible.asStateFlow()
    fun onStart() = _visible.update { it + 1 }
    fun onStop() = _visible.update { (it - 1).coerceAtLeast(0) }
}
