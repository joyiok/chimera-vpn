package com.chimera.vpn

// Keyword-classification rules centralized in VpnState must stay in
// lockstep with the strings the service posts (strings.xml).

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnStateTest {

    @Test
    fun `exact resource strings classify`() {
        assertEquals(ConnState.CONNECTING, VpnState.classify("正在连接…"))
        assertEquals(ConnState.CONNECTED, VpnState.classify("已连接"))
        assertEquals(ConnState.DISCONNECTED, VpnState.classify("已断开"))
    }

    @Test
    fun `dynamic service payloads classify`() {
        assertEquals(ConnState.CONNECTING, VpnState.classify("重连中…"))
        assertEquals(ConnState.FAILED, VpnState.classify("连接失败：dial refused"))
        assertEquals(ConnState.FAILED, VpnState.classify("重连失败：timeout"))
        assertEquals(ConnState.FAILED, VpnState.classify("连接参数不完整"))
    }

    @Test
    fun `unknown payloads keep the spinner`() {
        // A wrong flip to DISCONNECTED would turn the connect button back
        // into "connect" while the tunnel is still negotiating; unknown
        // strings must read as in-progress instead.
        assertEquals(ConnState.CONNECTING, VpnState.classify("握手进行中"))
        assertEquals(ConnState.CONNECTING, VpnState.classify(""))
    }

    @Test
    fun `failure wins over connecting keywords`() {
        // "重连失败" contains neither 连接中 nor 重连中, but a payload like
        // "重连失败：连接中" must classify as FAILED.
        assertEquals(ConnState.FAILED, VpnState.classify("重连失败：连接中已超时"))
    }
}
