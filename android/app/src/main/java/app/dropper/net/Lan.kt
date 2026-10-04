package app.dropper.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import app.dropper.proto.Crypto
import app.dropper.proto.DiscoveryPackets
import app.dropper.proto.HostPort
import app.dropper.proto.Ipv4
import app.dropper.proto.TextSanitizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer

/** A usable local network: Wi-Fi or Ethernet (never cellular, never a VPN). */
data class LanNetwork(val network: Network, val address: Inet4Address?, val prefixLength: Int) {
    fun directedBroadcast(): InetAddress? {
        val a = address ?: return null
        if (prefixLength !in 8..30) return null
        val ip = ByteBuffer.wrap(a.address).int
        val mask = -1 shl (32 - prefixLength)
        return InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(ip or mask.inv()).array())
    }
}

class NetworkMonitor(context: Context) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val known = LinkedHashMap<Network, LanNetwork>()
    private val _current = MutableStateFlow<LanNetwork?>(null)
    val current: StateFlow<LanNetwork?> = _current.asStateFlow()

    init {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) // a LAN without internet is fine
            .build()
        cm.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                cm.getLinkProperties(network)?.let { update(network, it) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                update(network, linkProperties)
            }

            override fun onLost(network: Network) {
                synchronized(known) {
                    known.remove(network)
                    publish()
                }
            }
        })
    }

    private fun update(network: Network, lp: LinkProperties) {
        val v4 = lp.linkAddresses.firstOrNull { it.address is Inet4Address }
        synchronized(known) {
            known[network] = LanNetwork(network, v4?.address as? Inet4Address, v4?.prefixLength ?: 0)
            publish()
        }
    }

    private fun publish() {
        _current.value = known.values.lastOrNull()
    }
}

object Net {
    /**
     * Opens a TCP connection to an RFC 1918 address over the LAN network only.
     * Falls back to an unbound socket only if binding itself is refused.
     */
    fun openSocket(lan: LanNetwork, hp: HostPort, timeoutMs: Int): Socket {
        val bytes = Ipv4.parse(hp.ip) ?: throw IOException("invalid address")
        if (!Ipv4.isRfc1918(bytes)) throw IOException("address is not on a private network")
        val socket = try {
            lan.network.socketFactory.createSocket()
        } catch (_: Exception) {
            Socket()
        }
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(InetAddress.getByAddress(bytes), hp.port), timeoutMs)
            return socket
        } catch (e: Exception) {
            try {
                socket.close()
            } catch (_: Exception) {
            }
            throw e
        }
    }
}

object DeviceInfo {
    fun name(context: Context): String {
        val user = try {
            Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
        } catch (_: Exception) {
            null
        }
        return TextSanitizer.displayName(user ?: "").ifEmpty { TextSanitizer.displayName(Build.MODEL ?: "") }
            .ifEmpty { "Android phone" }
    }

    val model: String get() = TextSanitizer.displayName(Build.MODEL ?: "").ifEmpty { "Android" }
}

/** Authenticated UDP discovery (PROTOCOL.md §10). */
object DiscoveryClient {
    suspend fun discover(lan: LanNetwork, discKey: ByteArray, lastIp: String?): HostPort? = withContext(Dispatchers.IO) {
        val socket = DatagramSocket()
        try {
            try {
                lan.network.bindSocket(socket)
            } catch (_: Exception) {
            }
            socket.broadcast = true
            socket.soTimeout = 250
            val targets = buildList {
                add(InetAddress.getByAddress(byteArrayOf(-1, -1, -1, -1)))
                lan.directedBroadcast()?.let { add(it) }
                lastIp?.let { Ipv4.parse(it) }?.takeIf { Ipv4.isRfc1918(it) }?.let { add(InetAddress.getByAddress(it)) }
            }
            val outstanding = ArrayList<ByteArray>()
            val buf = ByteArray(256)
            repeat(3) {
                val nonce = Crypto.randomBytes(16)
                outstanding += nonce
                val req = DiscoveryPackets.request(System.currentTimeMillis(), nonce, discKey)
                for (t in targets) {
                    try {
                        socket.send(DatagramPacket(req, req.size, t, DiscoveryPackets.PORT))
                    } catch (_: IOException) {
                    }
                }
                val deadline = SystemClock.elapsedRealtime() + 1_000
                while (SystemClock.elapsedRealtime() < deadline) {
                    ensureActive()
                    val pkt = DatagramPacket(buf, buf.size)
                    try {
                        socket.receive(pkt)
                    } catch (_: SocketTimeoutException) {
                        continue
                    }
                    val found = DiscoveryPackets.parseResponse(pkt.data, pkt.length, discKey) ?: continue
                    if (outstanding.none { Crypto.constantTimeEquals(it, found.nonce) }) continue
                    if (!Ipv4.isRfc1918(found.ip)) continue
                    return@withContext HostPort(found.ip, found.port)
                }
            }
            null
        } finally {
            socket.close()
        }
    }
}
