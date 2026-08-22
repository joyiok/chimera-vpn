package com.chimera.vpn

// Plain-JVM unit tests for the invite codec. Invite.kt deliberately has
// no android.* imports so these run without Robolectric (gradle
// testDebugUnitTest, wired into CI).

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class InviteTest {

    private val seed = "a".repeat(64)
    private val psk = "B".repeat(64)

    @Test
    fun `format then parse round trips`() {
        val inv = Invite(addr = "vpn.example.com:4789", seedHex = seed, pskHex = psk, generation = 7, name = "home")
        val text = Invites.format(inv)
        org.junit.Assert.assertTrue(text.startsWith("chimera://v1/"))
        // format() normalizes hex to lowercase; the parsed result must
        // match the canonical form.
        val back = Invites.parse(text)
        assertEquals(inv.copy(pskHex = psk.lowercase()), back)
    }

    @Test
    fun `parse normalizes uppercase and 0x hex`() {
        val text = Invites.format(
            Invite("h:1", seed, psk, 2)
        ).replace(seed, seed.uppercase())
        val back = Invites.parse(text)
        assertEquals(seed, back.seedHex) // lowercase canonical
    }

    @Test
    fun `parse json form with snake_case aliases`() {
        val json = """{"serverAddr":"h:1","seed_hex":"$seed","psk_hex":"$psk","generation":5}"""
        val inv = Invites.parse(json)
        assertEquals("h:1", inv.addr)
        assertEquals(seed, inv.seedHex)
        assertEquals(psk.lowercase(), inv.pskHex)
        assertEquals(5, inv.generation)
    }

    @Test
    fun `parse chimera connect url`() {
        val url = "chimera://connect?server=h%3A1&seedHex=$seed&pskHex=$psk&generation=3&n=office"
        val inv = Invites.parse(url)
        assertEquals("h:1", inv.addr)
        assertEquals(seed, inv.seedHex)
        assertEquals(3, inv.generation)
        assertEquals("office", inv.name)
    }

    @Test
    fun `parse extracts invite from pasted text`() {
        val text = "请导入: ${Invites.format(Invite("h:1", seed, psk, 0))} 谢谢"
        val inv = Invites.parse(text)
        assertEquals("h:1", inv.addr)
    }

    @Test
    fun `rejects garbage at parse level`() {
        // These go through parse() directly so the rejection happens where
        // a real invite would fail, not inside format().
        assertThrows(IllegalArgumentException::class.java) { Invites.parse("") }
        assertThrows(IllegalArgumentException::class.java) { Invites.parse("https://example.com/x") }
        assertThrows(IllegalArgumentException::class.java) {
            Invites.parse("""{"v":1,"a":"h:1","s":"zz","p":"$psk"}""")
        }
        assertThrows(IllegalArgumentException::class.java) {
            Invites.parse("""{"v":1,"s":"$seed","p":"$psk"}""")
        }
    }
}
