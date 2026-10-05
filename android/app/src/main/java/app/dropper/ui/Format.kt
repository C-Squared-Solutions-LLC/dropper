package app.dropper.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.text.format.DateUtils
import android.widget.Toast
import app.dropper.data.HistoryItem
import app.dropper.data.ItemKind
import app.dropper.proto.Links
import app.dropper.service.Clip
import java.util.Locale

object Format {
    fun size(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = bytes / 1024.0
        var i = 0
        while (v >= 1024 && i < units.size - 1) {
            v /= 1024
            i++
        }
        return if (v >= 100) String.format(Locale.getDefault(), "%.0f %s", v, units[i])
        else String.format(Locale.getDefault(), "%.1f %s", v, units[i])
    }

    fun time(context: Context, millis: Long): String =
        if (DateUtils.isToday(millis)) DateUtils.formatDateTime(context, millis, DateUtils.FORMAT_SHOW_TIME)
        else DateUtils.formatDateTime(context, millis, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH or DateUtils.FORMAT_SHOW_TIME)

    fun preview(text: String, max: Int = 140): String {
        val oneLine = text.replace(Regex("\\s+"), " ").trim()
        return if (oneLine.length > max) oneLine.take(max) + "…" else oneLine
    }
}

/** Opening, copying and sharing history items. Never auto-opens anything (§11). */
object ItemActions {
    fun copy(context: Context, text: String) {
        if (Clip.copy(context, text, sensitive = false)) {
            Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
        }
    }

    fun openLink(context: Context, url: String) {
        // Re-validate: only a single http(s) URL is ever opened.
        val safe = Links.singleHttpUrl(url) ?: return
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(safe)).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(context, "No app can open this link", Toast.LENGTH_SHORT).show()
        }
    }

    fun openFile(context: Context, item: HistoryItem) {
        val uri = item.uri?.let(Uri::parse) ?: return
        val intent = viewIntent(uri, item.name, item.mime)
        try {
            // APKs go straight to the system installer; a chooser there only adds a useless step.
            context.startActivity(if (isApk(item.name)) intent else Intent.createChooser(intent, item.name))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(context, "No app can open this file", Toast.LENGTH_SHORT).show()
        }
    }

    fun isApk(name: String): Boolean = name.endsWith(".apk", ignoreCase = true)

    /**
     * MIME type to put on a share intent. Media and documents keep their real type so the
     * share sheet only lists apps that handle them. Anything else (APK, zip, raw binary) is
     * shared as the wildcard: apps such as Google Messages accept arbitrary files but only
     * register for specific types plus wildcard shares, so a real APK type would hide them.
     * The receiving app still reads the true type from the content URI.
     */
    fun shareType(mime: String): String {
        val m = mime.lowercase()
        val specific = m.startsWith("image/") || m.startsWith("video/") || m.startsWith("audio/") ||
            m.startsWith("text/") || m == "application/pdf" || m.startsWith("application/vnd.openxmlformats") ||
            m.startsWith("application/vnd.ms-") || m == "application/msword"
        return if (specific) m else "*/*"
    }

    /**
     * ACTION_VIEW for a received file. APKs always carry the package-archive MIME type,
     * which is what routes them to the Package Installer.
     */
    fun viewIntent(uri: Uri, name: String, mime: String): Intent =
        Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, if (isApk(name)) APK_MIME else mime)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

    private const val APK_MIME = "application/vnd.android.package-archive"

    fun share(context: Context, item: HistoryItem) {
        val intent = Intent(Intent.ACTION_SEND)
        if (item.kind == ItemKind.TEXT) {
            intent.type = "text/plain"
            intent.putExtra(Intent.EXTRA_TEXT, item.text ?: return)
        } else {
            val uri = item.uri?.let(Uri::parse) ?: return
            intent.type = shareType(item.mime)
            intent.putExtra(Intent.EXTRA_STREAM, uri)
            // The read grant only reaches the app picked in the chooser when the URI is
            // also in ClipData; without it Messages/SMS apps can't open the attachment.
            intent.clipData = ClipData.newRawUri(item.name, uri)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(intent, null)
        if (intent.clipData != null) {
            chooser.clipData = intent.clipData
            chooser.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        try {
            context.startActivity(chooser)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(context, "No app can share this", Toast.LENGTH_SHORT).show()
        }
    }
}
