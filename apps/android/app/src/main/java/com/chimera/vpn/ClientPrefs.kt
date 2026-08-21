package com.chimera.vpn

import android.content.Context
import android.content.Context.MODE_PRIVATE

object ClientPrefs {
    const val PREF = "chimera_client"
    const val SERVER = "server"
    const val SEED = "seed"
    const val GENERATION = "generation"
    const val PSK = "psk"
    const val TUN_IP = "tun_ip"
    const val TRANSPORT = "transport"
    const val SPLIT_TUNNEL = "split_tunnel"
    const val PORT_HOP_COUNT = "port_hop_count"
    const val PORT_HOP_SPREAD = "port_hop_spread"
    private const val SERVERS = "servers"

    fun load(context: Context): ChimeraVpnService.VpnConfig? {
        val p = context.getSharedPreferences(PREF, MODE_PRIVATE)
        val server = p.getString(SERVER, "").orEmpty()
        val seed = p.getString(SEED, "").orEmpty()
        val psk = p.getString(PSK, "").orEmpty()
        if (server.isBlank() || seed.isBlank() || psk.isBlank()) return null
        return ChimeraVpnService.VpnConfig(
            serverAddr = server,
            seedHex = seed,
            generation = p.getString(GENERATION, "0")?.toLongOrNull() ?: 0L,
            pskHex = psk,
            tunIp = p.getString(TUN_IP, "10.99.0.2").orEmpty().ifBlank { "10.99.0.2" },
            transport = p.getString(TRANSPORT, "udp").orEmpty().ifBlank { "udp" },
            splitTunnel = p.getBoolean(SPLIT_TUNNEL, true),
            portHopCount = p.getInt(PORT_HOP_COUNT, 1),
            portHopSpread = p.getInt(PORT_HOP_SPREAD, 0)
        )
    }

    fun save(context: Context, config: ChimeraVpnService.VpnConfig) {
        context.getSharedPreferences(PREF, MODE_PRIVATE).edit()
            .putString(SERVER, config.serverAddr)
            .putString(SEED, config.seedHex)
            .putString(GENERATION, config.generation.toString())
            .putString(PSK, config.pskHex)
            .putString(TUN_IP, config.tunIp)
            .putString(TRANSPORT, config.transport)
            .putBoolean(SPLIT_TUNNEL, config.splitTunnel)
            .putInt(PORT_HOP_COUNT, config.portHopCount)
            .putInt(PORT_HOP_SPREAD, config.portHopSpread)
            .apply()
        if (servers(context).none { it.second.equals(config.serverAddr, ignoreCase = true) }) {
            saveServer(context, config.serverAddr, config.serverAddr)
        }
    }

    fun servers(context: Context): List<Pair<String, String>> {
        val raw = context.getSharedPreferences(PREF, MODE_PRIVATE).getString(SERVERS, "").orEmpty()
        if (raw.isBlank()) return emptyList()
        return raw.lineSequence().mapNotNull { line ->
            val parts = line.split('|', limit = 2)
            if (parts.size == 2 && parts[1].isNotBlank()) parts[0] to parts[1] else null
        }.toList()
    }

    fun saveServer(context: Context, name: String, addr: String) {
        val a = addr.trim()
        if (a.isEmpty()) return
        val n = name.trim().ifBlank { a }
        val rest = servers(context).filterNot { it.second.equals(a, ignoreCase = true) }
        val next = (listOf(n to a) + rest).joinToString("\n") { "${it.first}|${it.second}" }
        context.getSharedPreferences(PREF, MODE_PRIVATE).edit().putString(SERVERS, next).apply()
    }

    fun removeServer(context: Context, addr: String) {
        val next = servers(context)
            .filterNot { it.second.equals(addr, ignoreCase = true) }
            .joinToString("\n") { "${it.first}|${it.second}" }
        context.getSharedPreferences(PREF, MODE_PRIVATE).edit().putString(SERVERS, next).apply()
    }
}
