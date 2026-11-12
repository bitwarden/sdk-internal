package com.bitwarden.sdk.e2etests

import com.bitwarden.core.ReinitUserCryptoException
import com.bitwarden.core.ReinitUserCryptoRequest
import com.bitwarden.sdk.BitwardenException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kotlin port of the Swift suite's `ReinitUserCryptoTests`. */
class ReinitUserCryptoTests {
    private val stateBridge = InMemoryStateBridge()

    @Test
    fun returnsNotUnlockedWhenLocked() = runBlocking {
        // No `initializeUserCrypto` call, so the user-key slot is empty.
        val client = makeClient(stateBridge)
        val req = ReinitUserCryptoRequest(makeV2AccountCryptographicState(), makeMockUpgradeToken())

        val error = assertThrows(BitwardenException.ReinitUserCrypto::class.java) {
            runBlocking { client.crypto().reinitUserCrypto(req) }
        }
        assertTrue(
            "expected NotUnlocked, got ${error.v1}",
            error.v1 is ReinitUserCryptoException.NotUnlocked,
        )
    }

    @Test
    fun secondReinitWithSamePayloadIsNoop() = runBlocking {
        val client = makeV1InitializedClient(stateBridge)
        val upgradeToken = makeValidUpgradeToken()
        stateBridge.setV2UpgradeToken(upgradeToken)
        val req = ReinitUserCryptoRequest(makeV2AccountCryptographicState(), upgradeToken)

        // The first call performs the V1 to V2 upgrade.
        client.crypto().reinitUserCrypto(req)
        assertEquals(TEST_VECTOR_USER_KEY_V2_B64, client.crypto().getUserEncryptionKey())

        // The second call with the same payload is a no-op: the active user key is already V2, so
        // reinit returns early and the key is unchanged.
        client.crypto().reinitUserCrypto(req)
        assertEquals(TEST_VECTOR_USER_KEY_V2_B64, client.crypto().getUserEncryptionKey())
    }

    @Test
    fun upgradesV1ToV2WithValidToken() = runBlocking {
        val client = makeV1InitializedClient(stateBridge)
        val upgradeToken = makeValidUpgradeToken()
        stateBridge.setV2UpgradeToken(upgradeToken)
        val req = ReinitUserCryptoRequest(makeV2AccountCryptographicState(), upgradeToken)

        client.crypto().reinitUserCrypto(req)

        // After a V1 to V2 reinit the active user key is the V2 test vector key, which
        // `getUserEncryptionKey` returns as base64 COSE.
        assertEquals(TEST_VECTOR_USER_KEY_V2_B64, client.crypto().getUserEncryptionKey())
    }

    @Test
    fun invalidUpgradeTokenReturnsError() = runBlocking {
        val client = makeV1InitializedClient(stateBridge)
        val req = ReinitUserCryptoRequest(makeV2AccountCryptographicState(), makeMockUpgradeToken())

        val error = assertThrows(BitwardenException.ReinitUserCrypto::class.java) {
            runBlocking { client.crypto().reinitUserCrypto(req) }
        }
        assertTrue(
            "expected InvalidUpgradeToken, got ${error.v1}",
            error.v1 is ReinitUserCryptoException.InvalidUpgradeToken,
        )
    }
}
