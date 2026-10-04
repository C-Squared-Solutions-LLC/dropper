package app.dropper.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import app.dropper.proto.Fingerprint
import java.math.BigInteger
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal

/** The phone's long-term identity: an EC P-256 key that never leaves the Keystore (TEE). */
class IdentityMaterial(val privateKey: PrivateKey, val certificate: X509Certificate) {
    /** fp = SHA256(SubjectPublicKeyInfo) (PROTOCOL.md §3). */
    val fingerprint: ByteArray = Fingerprint.of(certificate.publicKey.encoded)

    /** Always offers our single identity as the TLS client certificate. */
    fun keyManager(): X509ExtendedKeyManager = object : X509ExtendedKeyManager() {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String =
            Identity.ALIAS

        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String =
            Identity.ALIAS

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf(Identity.ALIAS)

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            if (alias == Identity.ALIAS) arrayOf(certificate) else null

        override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == Identity.ALIAS) privateKey else null

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
    }

    fun securityLevel(): String = try {
        val info = KeyFactory.getInstance(privateKey.algorithm, Identity.PROVIDER)
            .getKeySpec(privateKey, KeyInfo::class.java)
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "Hardware (StrongBox)"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Hardware (TEE)"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software"
            else -> "Hardware"
        }
    } catch (_: Exception) {
        "Unknown"
    }
}

object Identity {
    const val ALIAS = "dropper_identity_v1"
    const val PROVIDER = "AndroidKeyStore"

    @Volatile
    private var cached: IdentityMaterial? = null

    /** Loads the identity, generating it on first use. Call off the main thread. */
    @Synchronized
    fun get(): IdentityMaterial {
        cached?.let { return it }
        load()?.let { cached = it; return it }
        generate()
        return load()?.also { cached = it } ?: error("Keystore identity unavailable")
    }

    /** Peek without generating (for Settings). */
    @Synchronized
    fun existing(): IdentityMaterial? = cached ?: load()?.also { cached = it }

    /** Deletes the identity; a fresh one is generated at the next pairing. */
    @Synchronized
    fun reset() {
        val ks = keyStore()
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        cached = null
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun load(): IdentityMaterial? {
        val ks = keyStore()
        val key = ks.getKey(ALIAS, null) as? PrivateKey ?: return null
        val cert = ks.getCertificate(ALIAS) as? X509Certificate ?: return null
        return IdentityMaterial(key, cert)
    }

    private fun generate() {
        val now = System.currentTimeMillis()
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // DIGEST_NONE is required: Conscrypt signs the pre-hashed TLS transcript (NONEwithECDSA).
            .setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512,
            )
            .setCertificateSubject(X500Principal("CN=Dropper Phone"))
            .setCertificateSerialNumber(BigInteger(63, SecureRandom()).add(BigInteger.ONE))
            .setCertificateNotBefore(Date(now - 86_400_000L))
            .setCertificateNotAfter(Date(now + 30L * 365 * 86_400_000L))
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }
}
