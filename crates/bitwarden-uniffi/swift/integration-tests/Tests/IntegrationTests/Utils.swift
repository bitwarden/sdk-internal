import BitwardenSdk
import Foundation

let TEST_EMAIL = "test@bitwarden.com"
let TEST_PASSWORD = "asdfasdfasdf"
let TEST_PIN = "1234"

let PRIVATE_KEY =
    "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw="

let MASTER_KEY_WRAPPED_USER_KEY =
    "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc="

/// In-memory `StateBridgeForeignImpl` for tests. Mirrors `makeStateBridge()`
/// from the WASM integration tests.
actor InMemoryStateBridge: StateBridgeForeignImpl {
    private var userKey: SymmetricCryptoKey?
    private var persistentPinEnvelope: PasswordProtectedKeyEnvelope?
    private var ephemeralPinEnvelope: PasswordProtectedKeyEnvelope?
    private var encryptedPin: EncString?
    private var v2UpgradeToken: V2UpgradeToken?
    private var accountCryptographicState: WrappedAccountCryptographicState?
    private var masterpasswordUnlockData: MasterPasswordUnlockData?

    func setUserKey(value: SymmetricCryptoKey) { userKey = value }
    func getUserKey() -> SymmetricCryptoKey? { userKey }
    func clearUserKey() { userKey = nil }

    func setPersistentPinEnvelope(value: PasswordProtectedKeyEnvelope) { persistentPinEnvelope = value }
    func getPersistentPinEnvelope() -> PasswordProtectedKeyEnvelope? { persistentPinEnvelope }
    func clearPersistentPinEnvelope() { persistentPinEnvelope = nil }

    func setEphemeralPinEnvelope(value: PasswordProtectedKeyEnvelope) { ephemeralPinEnvelope = value }
    func getEphemeralPinEnvelope() -> PasswordProtectedKeyEnvelope? { ephemeralPinEnvelope }
    func clearEphemeralPinEnvelope() { ephemeralPinEnvelope = nil }

    func setEncryptedPin(value: EncString) { encryptedPin = value }
    func getEncryptedPin() -> EncString? { encryptedPin }
    func clearEncryptedPin() { encryptedPin = nil }

    func setV2UpgradeToken(value: V2UpgradeToken) { v2UpgradeToken = value }
    func getV2UpgradeToken() -> V2UpgradeToken? { v2UpgradeToken }
    func clearV2UpgradeToken() { v2UpgradeToken = nil }

    func setAccountCryptographicState(value: WrappedAccountCryptographicState) { accountCryptographicState = value }
    func getAccountCryptographicState() -> WrappedAccountCryptographicState? { accountCryptographicState }
    func clearAccountCryptographicState() { accountCryptographicState = nil }

    func setMasterpasswordUnlockData(value: MasterPasswordUnlockData) { masterpasswordUnlockData = value }
    func getMasterpasswordUnlockData() -> MasterPasswordUnlockData? { masterpasswordUnlockData }
    func clearMasterpasswordUnlockData() { masterpasswordUnlockData = nil }
}

final class MockTokenProvider: ClientManagedTokens {
    func getAccessToken() async -> String? { nil }
}

/// Builds a `Client` with a registered `InMemoryStateBridge` and an initialized
/// crypto state, mirroring `makeInitializedPasswordmanagerClient` from the WASM
/// integration tests.
func makeInitializedClient(stateBridge: InMemoryStateBridge) async throws -> Client {
    let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
    client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

    let req = InitUserCryptoRequest(
        userId: "00000000-0000-0000-0000-000000000000",
        kdfParams: .pbkdf2(iterations: 100_000),
        email: TEST_EMAIL,
        accountCryptographicState: .v1(privateKey: PRIVATE_KEY),
        method: .masterPasswordUnlock(
            password: TEST_PASSWORD,
            masterPasswordUnlock: MasterPasswordUnlockData(
                kdf: .pbkdf2(iterations: 100_000),
                masterKeyWrappedUserKey: MASTER_KEY_WRAPPED_USER_KEY,
                salt: TEST_EMAIL
            )
        ),
        upgradeToken: nil
    )

    try await client.crypto().initializeUserCrypto(req: req)
    return client
}
