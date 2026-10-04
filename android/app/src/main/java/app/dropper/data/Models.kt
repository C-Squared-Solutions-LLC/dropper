package app.dropper.data

import app.dropper.proto.HostPort
import org.json.JSONObject

enum class Direction { IN, OUT }

enum class ItemKind { TEXT, FILE }

enum class ItemStatus { QUEUED, SENDING, DELIVERED, FAILED, RECEIVING, RECEIVED }

/** One row in the activity list (sent or received). */
data class HistoryItem(
    val id: String,
    val direction: Direction,
    val kind: ItemKind,
    val name: String,
    val size: Long,
    val mime: String,
    val text: String? = null,
    val uri: String? = null,
    val status: ItemStatus,
    val time: Long,
    val error: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("dir", direction.name)
        .put("kind", kind.name)
        .put("name", name)
        .put("size", size)
        .put("mime", mime)
        .put("text", text ?: JSONObject.NULL)
        .put("uri", uri ?: JSONObject.NULL)
        .put("status", status.name)
        .put("time", time)
        .put("error", error ?: JSONObject.NULL)

    companion object {
        fun fromJson(o: JSONObject): HistoryItem? = try {
            HistoryItem(
                id = o.getString("id"),
                direction = Direction.valueOf(o.getString("dir")),
                kind = ItemKind.valueOf(o.getString("kind")),
                name = o.getString("name"),
                size = o.getLong("size"),
                mime = o.getString("mime"),
                text = o.optStringOrNull("text"),
                uri = o.optStringOrNull("uri"),
                status = ItemStatus.valueOf(o.getString("status")),
                time = o.getLong("time"),
                error = o.optStringOrNull("error"),
            )
        } catch (_: Exception) {
            null
        }
    }
}

enum class OutboxState { PENDING, FAILED }

/** Something waiting to go to the PC. File content lives in filesDir/outbox/<id>.bin. */
data class OutboxItem(
    val id: String,
    val kind: ItemKind,
    val name: String,
    val mime: String,
    val size: Long,
    val text: String? = null,
    val attempts: Int = 0,
    val state: OutboxState = OutboxState.PENDING,
    val createdAt: Long = System.currentTimeMillis(),
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("kind", kind.name)
        .put("name", name)
        .put("mime", mime)
        .put("size", size)
        .put("text", text ?: JSONObject.NULL)
        .put("attempts", attempts)
        .put("state", state.name)
        .put("created", createdAt)

    companion object {
        fun fromJson(o: JSONObject): OutboxItem? = try {
            OutboxItem(
                id = o.getString("id"),
                kind = ItemKind.valueOf(o.getString("kind")),
                name = o.getString("name"),
                mime = o.getString("mime"),
                size = o.getLong("size"),
                text = o.optStringOrNull("text"),
                attempts = o.optInt("attempts", 0),
                state = OutboxState.valueOf(o.getString("state")),
                createdAt = o.optLong("created", 0L),
            )
        } catch (_: Exception) {
            null
        }
    }
}

/** Everything the phone remembers about its paired PC (stored encrypted). */
class PairingRecord(
    val pcFp: ByteArray,
    val pcName: String,
    val addresses: List<HostPort>,
    val deviceSecret: ByteArray,
    val pairedAt: Long,
) {
    fun withAddresses(list: List<HostPort>) = PairingRecord(pcFp, pcName, list, deviceSecret, pairedAt)
}

internal fun JSONObject.optStringOrNull(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name)
