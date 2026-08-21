package com.chimera.vpn

// Pure-JVM by design: no android.* imports, so Invites is unit-testable
// with plain JUnit (see app/src/test). Base64 uses java.util.Base64
// (available since API 26) and connect-URL queries are parsed manually.

import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale

/**
 * Chimera share URLs. Keep in lockstep with Go `internal/invite`.
 *
 * Canonical: chimera://v1/<base64url({"v":1,"a":"host:port","s":"<64 hex>","p":"<64 hex>","g":0})>
 */
data class Invite(
    val addr: String,
    val seedHex: String,
    val pskHex: String,
    val generation: Long,
    val name: String = ""
)

object Invites {
    private const val V1 = "chimera://v1/"
    private const val CONNECT = "chimera://connect"
    private val B64ENC: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val B64DEC: Base64.Decoder = Base64.getUrlDecoder()

    fun format(p: Invite): String {
        val n = normalize(p)
        val obj = JSONObject()
            .put("v", 1)
            .put("a", n.addr)
            .put("s", n.seedHex)
            .put("p", n.pskHex)
            .put("g", n.generation)
        if (n.name.isNotEmpty()) obj.put("n", n.name)
        val raw = obj.toString().toByteArray(StandardCharsets.UTF_8)
        return V1 + B64ENC.encodeToString(raw)
    }

    fun parse(text: String): Invite {
        var s = text.trim()
        if (s.isEmpty()) throw IllegalArgumentException("empty invite")
        extractUrl(s)?.let { s = it }
        return when {
            s.startsWith("{") -> parseJson(s)
            s.startsWith(V1) -> parseV1(s.removePrefix(V1).trim().trimEnd('/'))
            s.startsWith(CONNECT) -> parseConnect(s)
            else -> throw IllegalArgumentException("not a chimera invite")
        }
    }

    private fun parseV1(payload: String): Invite {
        // java.util.Base64 tolerates missing padding, which covers both the
        // NO_PADDING canonical form and padded variants.
        val decoded = B64DEC.decode(payload)
        val obj = JSONObject(String(decoded, StandardCharsets.UTF_8))
        val v = obj.optInt("v", 1)
        if (v != 0 && v != 1) throw IllegalArgumentException("unsupported invite version $v")
        return normalize(
            Invite(
                addr = obj.optString("a"),
                seedHex = obj.optString("s"),
                pskHex = obj.optString("p"),
                generation = obj.optLong("g", 0L),
                name = obj.optString("n")
            )
        )
    }

    private fun parseConnect(raw: String): Invite {
        val params = queryParams(raw)
        val gen = firstQuery(params, "generation", "g")
        return normalize(
            Invite(
                addr = firstQuery(params, "addr", "server", "serverAddr"),
                seedHex = firstQuery(params, "seed", "seedHex"),
                pskHex = firstQuery(params, "psk", "pskHex"),
                generation = gen.toLongOrNull() ?: 0L,
                name = firstQuery(params, "name", "n")
            )
        )
    }

    private fun queryParams(raw: String): Map<String, String> {
        val query = raw.substringAfter('?', "")
        val out = LinkedHashMap<String, String>()
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val i = pair.indexOf('=')
            val k = if (i >= 0) pair.substring(0, i) else pair
            val v = if (i >= 0) pair.substring(i + 1) else ""
            if (k.isEmpty() || out.containsKey(k)) continue
            out[k] = java.net.URLDecoder.decode(v, StandardCharsets.UTF_8)
        }
        return out
    }

    private fun parseJson(s: String): Invite {
        val obj = JSONObject(s)
        return normalize(
            Invite(
                addr = firstJson(obj, "serverAddr", "a", "addr"),
                seedHex = firstJson(obj, "seedHex", "s", "seed_hex"),
                pskHex = firstJson(obj, "pskHex", "p", "psk_hex"),
                generation = when {
                    obj.has("generation") && !obj.isNull("generation") ->
                        obj.optLong("generation", 0L)
                    else -> 0L
                },
                name = firstJson(obj, "name", "n")
            )
        )
    }

    private fun normalize(p: Invite): Invite {
        val seed = normHex("seed", p.seedHex)
        val psk = normHex("psk", p.pskHex)
        val addr = p.addr.trim()
        if (addr.isEmpty()) throw IllegalArgumentException("server address is empty")
        return Invite(addr, seed, psk, p.generation, p.name.trim())
    }

    private fun normHex(label: String, raw: String): String {
        var s = raw.trim().lowercase(Locale.US)
        if (s.startsWith("0x")) s = s.substring(2)
        if (s.length != 64 || !s.all { it in '0'..'9' || it in 'a'..'f' }) {
            throw IllegalArgumentException("$label must be 64 hex characters")
        }
        return s
    }

    private fun extractUrl(s: String): String? {
        for (prefix in listOf(V1, CONNECT)) {
            val i = s.indexOf(prefix)
            if (i < 0) continue
            var rest = s.substring(i)
            val cut = rest.indexOfFirst { it in " \t\r\n<>\"'" }
            if (cut >= 0) rest = rest.substring(0, cut)
            return rest
        }
        return null
    }

    private fun firstQuery(params: Map<String, String>, vararg keys: String): String {
        for (k in keys) {
            val v = params[k]?.trim().orEmpty()
            if (v.isNotEmpty()) return v
        }
        return ""
    }

    private fun firstJson(obj: JSONObject, vararg keys: String): String {
        for (k in keys) {
            val v = obj.optString(k).trim()
            if (v.isNotEmpty()) return v
        }
        return ""
    }
}
