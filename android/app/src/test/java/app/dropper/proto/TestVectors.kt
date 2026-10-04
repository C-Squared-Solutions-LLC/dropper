package app.dropper.proto

import org.json.JSONObject
import java.io.File

/** Loads docs/test-vectors.json from the repository (walks up from the working dir). */
object TestVectors {
    val json: JSONObject by lazy {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val f = File(dir, "docs/test-vectors.json")
            if (f.isFile) return@lazy JSONObject(f.readText(Charsets.UTF_8))
            dir = dir.parentFile
        }
        error("docs/test-vectors.json not found above ${File("").absolutePath}")
    }

    val inputs: JSONObject get() = json.getJSONObject("inputs")
    val keys: JSONObject get() = json.getJSONObject("keys")

    fun input(name: String): ByteArray = Crypto.unhex(inputs.getString(name))
    fun key(name: String): ByteArray = Crypto.unhex(keys.getString(name))
    fun hex(name: String): ByteArray = Crypto.unhex(json.getString(name))
}
