package com.chimera.vpn

// Centralized connection-state classification so the service, the
// activity, and the unit tests agree on what a raw status string means.
// Keyword rules stay in lockstep with the strings in strings.xml.

enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

object VpnState {
    fun classify(raw: String): ConnState {
        val s = raw.trim()
        if (s.isEmpty()) return ConnState.DISCONNECTED
        if (s.contains("不完整")) return ConnState.FAILED
        if (s.startsWith("连接失败") || s.startsWith("重连失败")) return ConnState.FAILED
        if (s == "已连接") return ConnState.CONNECTED
        if (s.contains("连接中") || s.contains("重连中")) return ConnState.CONNECTING
        if (s.startsWith("已断开")) return ConnState.DISCONNECTED
        // Unknown payloads keep the spinner rather than flipping the
        // connect button into a wrong mode.
        return ConnState.CONNECTING
    }
}
