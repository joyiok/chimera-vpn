package com.chimera.vpn

import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets
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
    private const val B64 = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING

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
        return V1 + Base64.encodeToString(raw, B64)
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
        val decoded = try {
            Base64.decode(payload, B64)
        } catch (_: IllegalArgumentException) {
            Base64.decode(payload, Base64.URL_SAFE or Base64.NO_WRAP)
        }
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
        val q = android.net.Uri.parse(raw)
        val gen = q.getQueryParameter("generation") ?: q.getQueryParameter("g")
        return normalize(
            Invite(
                addr = firstQuery(q, "addr", "server", "serverAddr"),
                seedHex = firstQuery(q, "seed", "seedHex"),
                pskHex = firstQuery(q, "psk", "pskHex"),
                generation = gen?.toLongOrNull() ?: 0L,
                name = firstQuery(q, "name", "n")
            )
        )
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

    private fun firstQuery(uri: android.net.Uri, vararg keys: String): String {
        for (k in keys) {
            val v = uri.getQueryParameter(k)?.trim().orEmpty()
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
