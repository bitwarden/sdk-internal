package com.bitwarden.sdk.e2etests

import com.bitwarden.core.PinLockType
import com.bitwarden.core.PinUnlockStatus
import com.bitwarden.sdk.Client
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Kotlin port of the Swift suite's `PinLockTests`. */
class PinLockTests {
    private lateinit var client: Client
    private lateinit var stateBridge: InMemoryStateBridge

    @Before
    fun setUp() = runBlocking {
        stateBridge = InMemoryStateBridge()
        client = makeInitializedClient(stateBridge)
    }

    @Test
    fun enrollsPinBeforeFirstUnlock() = runBlocking {
        val pinSettings = client.userCryptoManagement().pinSettings()

        pinSettings.setPin(TEST_PIN, PinLockType.BEFORE_FIRST_UNLOCK)

        assertEquals(PinUnlockStatus.AVAILABLE, pinSettings.getStatus())
        assertEquals(PinLockType.BEFORE_FIRST_UNLOCK, pinSettings.getLockType())
        assertNotNull(stateBridge.getEncryptedPin())
        // BeforeFirstUnlock populates both envelopes
        assertNotNull(stateBridge.getPersistentPinEnvelope())
        assertNotNull(stateBridge.getEphemeralPinEnvelope())
    }

    @Test
    fun enrollsPinAfterFirstUnlock() = runBlocking {
        val pinSettings = client.userCryptoManagement().pinSettings()

        pinSettings.setPin(TEST_PIN, PinLockType.AFTER_FIRST_UNLOCK)

        assertEquals(PinUnlockStatus.AVAILABLE, pinSettings.getStatus())
        assertEquals(PinLockType.AFTER_FIRST_UNLOCK, pinSettings.getLockType())
        assertNotNull(stateBridge.getEncryptedPin())
        // AfterFirstUnlock populates only the ephemeral envelope
        assertNotNull(stateBridge.getEphemeralPinEnvelope())
        assertNull(stateBridge.getPersistentPinEnvelope())
    }

    @Test
    fun validatesPin() = runBlocking {
        val pinSettings = client.userCryptoManagement().pinSettings()

        pinSettings.setPin(TEST_PIN, PinLockType.BEFORE_FIRST_UNLOCK)

        assertTrue(pinSettings.validatePin(TEST_PIN))
    }

    @Test
    fun unsetsPin() = runBlocking {
        val pinSettings = client.userCryptoManagement().pinSettings()

        pinSettings.setPin(TEST_PIN, PinLockType.BEFORE_FIRST_UNLOCK)
        pinSettings.unsetPin()

        assertEquals(PinUnlockStatus.NOT_SET, pinSettings.getStatus())
        assertNull(stateBridge.getEncryptedPin())
        assertNull(stateBridge.getPersistentPinEnvelope())
        assertNull(stateBridge.getEphemeralPinEnvelope())
    }
}
