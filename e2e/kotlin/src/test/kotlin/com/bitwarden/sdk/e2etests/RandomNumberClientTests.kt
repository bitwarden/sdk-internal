package com.bitwarden.sdk.e2etests

import com.bitwarden.random.SdkRandomNumberClient
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kotlin port of the Swift suite's `RandomNumberClientTests`. */
class RandomNumberClientTests {
    @Test
    fun genBytesReturnsRequestedLength() {
        val client = SdkRandomNumberClient()
        assertEquals(0, client.genBytes(0u).size)
        assertEquals(32, client.genBytes(32u).size)
        // 1 KiB is the documented maximum and must succeed.
        assertEquals(1024, client.genBytes(1024u).size)
    }

    @Test
    fun genBytesAboveLimitThrows() {
        val client = SdkRandomNumberClient()
        // Over the 1 KiB limit throws a catchable error instead of crashing.
        assertThrows(Exception::class.java) { client.genBytes(1025u) }
    }

    @Test
    fun genBytesIsRandom() {
        val client = SdkRandomNumberClient()
        assertFalse(client.genBytes(32u).contentEquals(client.genBytes(32u)))
    }

    @Test
    fun genUuidIsAValidUuid() {
        val client = SdkRandomNumberClient()
        val uuid = client.genUuid()
        assertEquals(uuid, UUID.fromString(uuid).toString())
    }

    @Test
    fun genUuidIsDistinct() {
        val client = SdkRandomNumberClient()
        assertTrue(client.genUuid() != client.genUuid())
    }

    @Test
    fun genRangeStaysWithinInclusiveBounds() {
        val client = SdkRandomNumberClient()
        repeat(1000) {
            assertTrue(client.genRange(10u, 20u) in 10u..20u)
        }
        assertEquals(7u, client.genRange(7u, 7u))
        // An inverted range throws a catchable error instead of crashing.
        assertThrows(Exception::class.java) { client.genRange(20u, 10u) }
    }
}
