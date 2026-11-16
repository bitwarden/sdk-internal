package com.bitwarden.sdk.e2etests

import com.bitwarden.core.ClientManagedTokens
import com.bitwarden.core.InitUserCryptoMethod
import com.bitwarden.core.InitUserCryptoRequest
import com.bitwarden.core.MasterPasswordUnlockData
import com.bitwarden.core.StateBridgeForeignImpl
import com.bitwarden.core.V2EncryptedMigrationsGracePeriodStart
import com.bitwarden.core.V2UpgradeToken
import com.bitwarden.core.WebAuthnPrfUnlockData
import com.bitwarden.core.WrappedAccountCryptographicState
import com.bitwarden.crypto.EncString
import com.bitwarden.crypto.Kdf
import com.bitwarden.crypto.KeyId
import com.bitwarden.crypto.PasswordProtectedKeyEnvelope
import com.bitwarden.crypto.SymmetricCryptoKey
import com.bitwarden.sdk.Client
import com.bitwarden.sdk.ManagedSettingsBindingClient

/** In-memory `StateBridgeForeignImpl` for tests, like the Swift suite's `InMemoryStateBridge`. */
class InMemoryStateBridge : StateBridgeForeignImpl {
    @Volatile private var userKey: SymmetricCryptoKey? = null
    @Volatile private var userKeyId: KeyId? = null
    @Volatile private var persistentPinEnvelope: PasswordProtectedKeyEnvelope? = null
    @Volatile private var ephemeralPinEnvelope: PasswordProtectedKeyEnvelope? = null
    @Volatile private var encryptedPin: EncString? = null
    @Volatile private var pinLength: UInt? = null
    @Volatile private var v2UpgradeToken: V2UpgradeToken? = null
    @Volatile private var accountCryptographicState: WrappedAccountCryptographicState? = null
    @Volatile private var masterpasswordUnlockData: MasterPasswordUnlockData? = null
    @Volatile private var webauthnPrfUnlockData: WebAuthnPrfUnlockData? = null
    @Volatile private var kdfConfig: Kdf? = null
    @Volatile
    private var v2EncryptedMigrationsGracePeriodStart: V2EncryptedMigrationsGracePeriodStart? = null

    override suspend fun setUserKey(value: SymmetricCryptoKey) { userKey = value }
    override suspend fun getUserKey(): SymmetricCryptoKey? = userKey
    override suspend fun clearUserKey() { userKey = null }

    override suspend fun setUserKeyId(value: KeyId) { userKeyId = value }
    override suspend fun getUserKeyId(): KeyId? = userKeyId
    override suspend fun clearUserKeyId() { userKeyId = null }

    override suspend fun setPersistentPinEnvelope(value: PasswordProtectedKeyEnvelope) {
        persistentPinEnvelope = value
    }
    override suspend fun getPersistentPinEnvelope(): PasswordProtectedKeyEnvelope? =
        persistentPinEnvelope
    override suspend fun clearPersistentPinEnvelope() { persistentPinEnvelope = null }

    override suspend fun setEphemeralPinEnvelope(value: PasswordProtectedKeyEnvelope) {
        ephemeralPinEnvelope = value
    }
    override suspend fun getEphemeralPinEnvelope(): PasswordProtectedKeyEnvelope? =
        ephemeralPinEnvelope
    override suspend fun clearEphemeralPinEnvelope() { ephemeralPinEnvelope = null }

    override suspend fun setEncryptedPin(value: EncString) { encryptedPin = value }
    override suspend fun getEncryptedPin(): EncString? = encryptedPin
    override suspend fun clearEncryptedPin() { encryptedPin = null }

    override suspend fun setPinLength(value: UInt) { pinLength = value }
    override suspend fun getPinLength(): UInt? = pinLength
    override suspend fun clearPinLength() { pinLength = null }

    override suspend fun setV2UpgradeToken(value: V2UpgradeToken) { v2UpgradeToken = value }
    override suspend fun getV2UpgradeToken(): V2UpgradeToken? = v2UpgradeToken
    override suspend fun clearV2UpgradeToken() { v2UpgradeToken = null }

    override suspend fun setAccountCryptographicState(value: WrappedAccountCryptographicState) {
        accountCryptographicState = value
    }
    override suspend fun getAccountCryptographicState(): WrappedAccountCryptographicState? =
        accountCryptographicState
    override suspend fun clearAccountCryptographicState() { accountCryptographicState = null }

    override suspend fun setMasterpasswordUnlockData(value: MasterPasswordUnlockData) {
        masterpasswordUnlockData = value
    }
    override suspend fun getMasterpasswordUnlockData(): MasterPasswordUnlockData? =
        masterpasswordUnlockData
    override suspend fun clearMasterpasswordUnlockData() { masterpasswordUnlockData = null }

    override suspend fun setWebauthnPrfUnlockData(value: WebAuthnPrfUnlockData) {
        webauthnPrfUnlockData = value
    }
    override suspend fun getWebauthnPrfUnlockData(): WebAuthnPrfUnlockData? = webauthnPrfUnlockData
    override suspend fun clearWebauthnPrfUnlockData() { webauthnPrfUnlockData = null }

    override suspend fun setKdfConfig(value: Kdf) { kdfConfig = value }
    override suspend fun getKdfConfig(): Kdf? = kdfConfig
    override suspend fun clearKdfConfig() { kdfConfig = null }

    override suspend fun setV2EncryptedMigrationsGracePeriodStart(
        value: V2EncryptedMigrationsGracePeriodStart,
    ) {
        v2EncryptedMigrationsGracePeriodStart = value
    }
    override suspend fun getV2EncryptedMigrationsGracePeriodStart(): V2EncryptedMigrationsGracePeriodStart? =
        v2EncryptedMigrationsGracePeriodStart
    override suspend fun clearV2EncryptedMigrationsGracePeriodStart() {
        v2EncryptedMigrationsGracePeriodStart = null
    }
}

class MockTokenProvider : ClientManagedTokens {
    override suspend fun getAccessToken(): String? = null
}

/** A `Client` with `stateBridge` registered and no user crypto initialized. */
fun makeClient(stateBridge: InMemoryStateBridge): Client {
    // A fresh handle has no active profile, so no setting reads as administrator-forced.
    val client = Client(MockTokenProvider(), null, ManagedSettingsBindingClient())
    client.kmStateBridge().registerBridgeImpl(stateBridge)
    return client
}

/** A `Client` with an initialized V1 account (PBKDF2 100k), like the Swift suite's. */
suspend fun makeInitializedClient(stateBridge: InMemoryStateBridge): Client {
    val client = makeClient(stateBridge)
    client.crypto().initializeUserCrypto(
        InitUserCryptoRequest(
            userId = "00000000-0000-0000-0000-000000000000",
            kdfParams = Kdf.Pbkdf2(100_000u),
            email = TEST_EMAIL,
            accountCryptographicState = WrappedAccountCryptographicState.V1(PRIVATE_KEY),
            method = InitUserCryptoMethod.MasterPasswordUnlock(
                password = TEST_PASSWORD,
                masterPasswordUnlock = MasterPasswordUnlockData(
                    kdf = Kdf.Pbkdf2(100_000u),
                    masterKeyWrappedUserKey = MASTER_KEY_WRAPPED_USER_KEY,
                    salt = TEST_EMAIL,
                ),
            ),
            upgradeToken = null,
        ),
    )
    return client
}

/**
 * A V1 `Client` matching the `test_bitwarden_com_account` Rust fixture (PBKDF2 600k, V1 wrapped
 * account state). Its V1 user key is the one used to mint `VALID_UPGRADE_TOKEN_WRAPPED_UK*`.
 */
suspend fun makeV1InitializedClient(stateBridge: InMemoryStateBridge): Client {
    val client = makeClient(stateBridge)
    client.crypto().initializeUserCrypto(
        InitUserCryptoRequest(
            userId = TEST_VECTOR_USER_ID_V1,
            kdfParams = Kdf.Pbkdf2(TEST_VECTOR_KDF_ITERATIONS_V1),
            email = TEST_EMAIL,
            accountCryptographicState =
                WrappedAccountCryptographicState.V1(TEST_VECTOR_PRIVATE_KEY_V1),
            method = InitUserCryptoMethod.MasterPasswordUnlock(
                password = TEST_PASSWORD,
                masterPasswordUnlock = MasterPasswordUnlockData(
                    kdf = Kdf.Pbkdf2(TEST_VECTOR_KDF_ITERATIONS_V1),
                    masterKeyWrappedUserKey = TEST_VECTOR_MASTER_KEY_WRAPPED_USER_KEY_V1,
                    salt = TEST_EMAIL,
                ),
            ),
            upgradeToken = null,
        ),
    )
    return client
}

/**
 * A V2 `Client` matching the `test_bitwarden_com_account_v2` Rust fixture (V2 wrapped account
 * state, user key given directly).
 */
suspend fun makeV2InitializedClient(stateBridge: InMemoryStateBridge): Client {
    val client = makeClient(stateBridge)
    client.crypto().initializeUserCrypto(
        InitUserCryptoRequest(
            userId = TEST_VECTOR_USER_ID_V1,
            kdfParams = Kdf.Argon2id(6u, 32u, 4u),
            email = TEST_EMAIL,
            accountCryptographicState = makeV2AccountCryptographicState(),
            method = InitUserCryptoMethod.DecryptedKey(TEST_VECTOR_USER_KEY_V2_B64),
            upgradeToken = null,
        ),
    )
    return client
}

/** V2 wrapped account state that decrypts only with `TEST_VECTOR_USER_KEY_V2_B64`. */
fun makeV2AccountCryptographicState(): WrappedAccountCryptographicState =
    WrappedAccountCryptographicState.V2(
        privateKey = TEST_VECTOR_PRIVATE_KEY_V2,
        signedPublicKey = TEST_VECTOR_SIGNED_PUBLIC_KEY_V2,
        signingKey = TEST_VECTOR_SIGNING_KEY_V2,
        securityState = TEST_VECTOR_SECURITY_STATE_V2,
    )

/** An upgrade token that unwraps with the user key of `makeV1InitializedClient`. */
fun makeValidUpgradeToken(): V2UpgradeToken =
    V2UpgradeToken(VALID_UPGRADE_TOKEN_WRAPPED_UK1, VALID_UPGRADE_TOKEN_WRAPPED_UK2)

/**
 * A structurally valid upgrade token whose wrapped keys are bound to unrelated keys, so unwrapping
 * it with the V1 client's user key fails.
 */
fun makeMockUpgradeToken(): V2UpgradeToken =
    V2UpgradeToken(MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK1, MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK2)
