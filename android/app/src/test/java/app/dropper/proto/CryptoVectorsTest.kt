package app.dropper.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoVectorsTest {
    private val v = TestVectors

    @Test
    fun hkdfMatchesRfc5869Case3() {
        val c = v.json.getJSONObject("rfc5869_case3")
        val okm = Crypto.hkdf32(Crypto.unhex(c.getString("ikm")), "")
        assertEquals(c.getString("okm32"), Crypto.hex(okm))
    }

    @Test
    fun pairingKeysMatchVectors() {
        val keys = PairingKeys(v.input("pairing_secret"))
        assertArrayEquals(v.key("pair_gate_key"), keys.gateKey)
        assertArrayEquals(v.key("pair_proof_key"), keys.proofKey)
        assertArrayEquals(v.key("sas_key"), keys.sasKey)
    }

    @Test
    fun deviceKeysMatchVectors() {
        val keys = DeviceKeys(v.input("device_secret"))
        assertArrayEquals(v.key("gate_key"), keys.gateKey)
        assertArrayEquals(v.key("disc_key"), keys.discKey)
    }

    @Test
    fun proofAndSasMatchVectors() {
        val keys = PairingKeys(v.input("pairing_secret"))
        val proof = keys.proof(v.input("pc_fp"), v.input("phone_fp"))
        assertArrayEquals(v.hex("pair_proof"), proof)
        assertEquals(v.json.getString("pair_proof_b64u"), Crypto.b64u(proof))
        val sas = keys.sas(v.input("pc_fp"), v.input("phone_fp"))
        assertEquals(v.json.getString("sas"), sas)
        assertEquals("747 546", PairingKeys.formatSas(sas))
    }

    @Test
    fun preamblesMatchVectors() {
        val ts = v.inputs.getLong("ts_ms")
        val nonce = v.input("nonce")
        val session = Preamble.build(Preamble.MODE_SESSION, ts, nonce, DeviceKeys(v.input("device_secret")).gateKey)
        val pairing = Preamble.build(Preamble.MODE_PAIRING, ts, nonce, PairingKeys(v.input("pairing_secret")).gateKey)
        assertEquals(Preamble.SIZE, session.size)
        assertArrayEquals(v.hex("preamble_session"), session)
        assertArrayEquals(v.hex("preamble_pairing"), pairing)
    }

    @Test
    fun discoveryRequestMatchesVector() {
        val req = DiscoveryPackets.request(
            v.inputs.getLong("ts_ms"), v.input("nonce"), DeviceKeys(v.input("device_secret")).discKey,
        )
        assertEquals(DiscoveryPackets.REQUEST_SIZE, req.size)
        assertArrayEquals(v.hex("disc_request"), req)
    }

    @Test
    fun discoveryResponseEncodesAndParses() {
        val discKey = DeviceKeys(v.input("device_secret")).discKey
        val ip = v.inputs.getString("pc_ip")
        val port = v.inputs.getInt("port")
        val resp = DiscoveryPackets.response(ip, port, v.input("nonce"), discKey)
        assertArrayEquals(v.hex("disc_response"), resp)

        val found = DiscoveryPackets.parseResponse(resp, resp.size, discKey)
        assertNotNull(found)
        assertEquals(ip, found!!.ip)
        assertEquals(port, found.port)
        assertArrayEquals(v.input("nonce"), found.nonce)
    }

    @Test
    fun discoveryResponseRejectsTamperingWrongKeyAndSize() {
        val discKey = DeviceKeys(v.input("device_secret")).discKey
        val resp = v.hex("disc_response")
        val tampered = resp.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() } // flip an IP bit
        assertNull(DiscoveryPackets.parseResponse(tampered, tampered.size, discKey))
        assertNull(DiscoveryPackets.parseResponse(resp, resp.size, ByteArray(32)))
        assertNull(DiscoveryPackets.parseResponse(resp, resp.size - 1, discKey))
        val request = v.hex("disc_request")
        assertNull(DiscoveryPackets.parseResponse(request, request.size, discKey))
    }

    @Test
    fun fingerprintDisplayMatchesVector() {
        assertEquals(v.json.getString("fp_display_pc"), Fingerprint.display(v.input("pc_fp")))
    }

    @Test
    fun strictBase64Url() {
        val fp = ByteArray(32) { 0xFB.toByte() } // encodes to "-_v7…", exercising both URL-safe chars
        val enc = Crypto.b64u(fp)
        assertTrue(enc.contains('-') && enc.contains('_'))
        assertArrayEquals(fp, Crypto.b64uDecode(enc, 32))
        assertNull(Crypto.b64uDecode("$enc=", 32))          // padding not allowed
        assertNull(Crypto.b64uDecode(enc.replace('-', '+'), 32)) // standard alphabet rejected
        assertNull(Crypto.b64uDecode(enc.replace('_', '/'), 32))
        assertNull(Crypto.b64uDecode(enc.dropLast(1), 32))   // wrong length
        assertNull(Crypto.b64uDecode(enc, 31))
    }

    @Test
    fun itemIds() {
        val id = Crypto.newItemId()
        assertEquals(32, id.length)
        assert(Crypto.isValidItemId(id))
        assert(!Crypto.isValidItemId(id.uppercase()))
        assert(!Crypto.isValidItemId(id.dropLast(1)))
    }
}
