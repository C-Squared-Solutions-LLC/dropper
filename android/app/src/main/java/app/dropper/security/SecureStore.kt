package app.dropper.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Log
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small encrypted-file store: AES-256-GCM with a non-exportable Keystore key.
 * Each file is bound to its name through the GCM associated data, so files
 * can't be swapped for one another.
 *
 * Format: version(1) | ivLen(1) | iv | ciphertext+tag
 */
class SecureStore(context: Context) {
    private val dir = File(context.filesDir, "secure").apply { mkdirs() }

    @Synchronized
    fun write(name: String, plaintext: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(aad(name))
        val ct = cipher.doFinal(plaintext)
        val iv = cipher.iv
        val out = ByteArray(2 + iv.size + ct.size)
        out[0] = VERSION
        out[1] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 2, iv.size)
        System.arraycopy(ct, 0, out, 2 + iv.size, ct.size)

        val file = AtomicFile(File(dir, name))
        val fos = file.startWrite()
        try {
            fos.write(out)
            file.finishWrite(fos)
        } catch (e: Exception) {
            file.failWrite(fos)
            throw e
        }
    }

    /** Returns null if the file doesn't exist or can't be authenticated. */
    @Synchronized
    fun read(name: String): ByteArray? {
        val file = AtomicFile(File(dir, name))
        if (!file.baseFile.exists()) return null
        return try {
            val raw = file.readFully()
            require(raw.size > 2 && raw[0] == VERSION)
            val ivLen = raw[1].toInt() and 0xff
            require(ivLen in 12..16 && raw.size > 2 + ivLen + 16)
            val iv = raw.copyOfRange(2, 2 + ivLen)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            cipher.updateAAD(aad(name))
            cipher.doFinal(raw, 2 + ivLen, raw.size - 2 - ivLen)
        } catch (e: Exception) {
            Log.w(TAG, "secure file '$name' unreadable: ${e.javaClass.simpleName}")
            null
        }
    }

    @Synchronized
    fun delete(name: String) {
        AtomicFile(File(dir, name)).delete()
    }

    private fun aad(name: String) = "dropper/store/v1/$name".toByteArray(Charsets.UTF_8)

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(Identity.PROVIDER).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, Identity.PROVIDER)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    companion object {
        private const val TAG = "SecureStore"
        private const val ALIAS = "dropper_storage_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION: Byte = 1
    }
}
