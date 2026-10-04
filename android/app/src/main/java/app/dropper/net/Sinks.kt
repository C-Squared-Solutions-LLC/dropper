package app.dropper.net

import android.content.ContentResolver
import android.content.ContentValues
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.Locale

/** Where an incoming item's bytes go while it streams in. */
interface IncomingSink {
    fun write(b: ByteArray, off: Int, len: Int)
    fun abort()
}

class TextSink : IncomingSink {
    private val buf = ByteArrayOutputStream()
    override fun write(b: ByteArray, off: Int, len: Int) = buf.write(b, off, len)
    override fun abort() = buf.reset()
    fun bytes(): ByteArray = buf.toByteArray()
}

/**
 * Writes into Download/Dropper/ via MediaStore. The row stays IS_PENDING (hidden
 * from other apps) until the content is hash-verified and committed (§11).
 */
class MediaStoreSink(private val resolver: ContentResolver, name: String) : IncomingSink {
    val mime: String = mimeFor(name)
    val uri: Uri
    private val out: OutputStream

    init {
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Dropper")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        uri = resolver.insert(MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), values)
            ?: throw IOException("MediaStore insert failed")
        out = try {
            BufferedOutputStream(resolver.openOutputStream(uri, "w") ?: throw IOException("no output stream"), 256 * 1024)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)
            throw e
        }
    }

    override fun write(b: ByteArray, off: Int, len: Int) = out.write(b, off, len)

    /** Publishes the file. Returns the final display name (MediaStore may add " (1)"). */
    fun commit(): String? {
        out.close()
        val values = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
        if (resolver.update(uri, values, null, null) != 1) throw IOException("MediaStore publish failed")
        return try {
            resolver.query(uri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (_: Exception) {
            null
        }
    }

    override fun abort() {
        try {
            out.close()
        } catch (_: Exception) {
        }
        try {
            resolver.delete(uri, null, null)
        } catch (_: Exception) {
        }
    }

    companion object {
        /** MIME comes from our own extension mapping, never from the peer (§11). */
        fun mimeFor(name: String): String {
            val ext = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
            if (ext.isEmpty()) return "application/octet-stream"
            return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        }
    }
}
