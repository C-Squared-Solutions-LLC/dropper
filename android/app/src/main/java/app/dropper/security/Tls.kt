package app.dropper.security

import app.dropper.proto.Crypto
import app.dropper.proto.Fingerprint
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedTrustManager

/** Raised when the server presents a key other than the pinned PC key. */
class PinMismatchException : SSLPeerUnverifiedException("The PC's key does not match the paired key")

private class PinMismatchCertException : CertificateException("pin mismatch")

/**
 * Trusts exactly one public key (SHA-256 of its SubjectPublicKeyInfo). CA chain,
 * hostname and validity dates are deliberately ignored (PROTOCOL.md §6.2).
 */
class PinningTrustManager(private val pin: ByteArray) : X509ExtendedTrustManager() {
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        throw CertificateException("client role not supported")

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) =
        throw CertificateException("client role not supported")

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) =
        throw CertificateException("client role not supported")

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    private fun check(chain: Array<out X509Certificate>?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("empty certificate chain")
        if (!Crypto.constantTimeEquals(Fingerprint.of(leaf.publicKey.encoded), pin)) {
            throw PinMismatchCertException()
        }
    }
}

object Tls {
    /**
     * Upgrades an already-connected socket (preamble already sent) to TLS 1.3 with
     * mutual auth. A fresh SSLContext per call means no session resumption.
     */
    fun clientHandshake(
        plain: Socket,
        host: String,
        port: Int,
        pin: ByteArray,
        identity: IdentityMaterial,
        timeoutMs: Int = 10_000,
    ): SSLSocket {
        val ctx = SSLContext.getInstance("TLSv1.3")
        ctx.init(arrayOf(identity.keyManager()), arrayOf(PinningTrustManager(pin)), SecureRandom())
        val ssl = ctx.socketFactory.createSocket(plain, host, port, true) as SSLSocket
        try {
            ssl.enabledProtocols = arrayOf("TLSv1.3")
            ssl.useClientMode = true
            ssl.soTimeout = timeoutMs
            try {
                ssl.startHandshake()
            } catch (e: SSLHandshakeException) {
                if (e.causeChain().any { it is PinMismatchCertException }) {
                    throw PinMismatchException()
                }
                throw e
            }
            val session = ssl.session
            if (session.protocol != "TLSv1.3") throw SSLHandshakeException("negotiated ${session.protocol}, need TLSv1.3")
            // Belt and braces: re-check the pin on the negotiated session.
            val peer = session.peerCertificates.firstOrNull() as? X509Certificate
                ?: throw SSLPeerUnverifiedException("no peer certificate")
            if (!Crypto.constantTimeEquals(Fingerprint.of(peer.publicKey.encoded), pin)) throw PinMismatchException()
            return ssl
        } catch (e: Exception) {
            try {
                ssl.close()
            } catch (_: Exception) {
            }
            throw e
        }
    }

    private fun Throwable.causeChain(): Sequence<Throwable> = generateSequence(this) { it.cause }
}
