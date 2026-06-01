import BitwardenSdk
import XCTest

/// Swift integration tests for `CryptoClient.reinitUserCrypto`.
final class ReinitUserCryptoTests: XCTestCase {
    var stateBridge: InMemoryStateBridge!

    override func setUp() async throws {
        try await super.setUp()
        stateBridge = InMemoryStateBridge()
    }

    func testReturnsNotUnlockedWhenLocked() async throws {
        // No `initializeUserCrypto` call — the user-key slot is empty.
        let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
        client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

        let req = ReinitUserCryptoRequest(
            accountCryptographicState: makeV2AccountCryptographicState(),
            upgradeToken: makeMockUpgradeToken()
        )

        do {
            try await client.crypto().reinitUserCrypto(req: req)
            XCTFail("expected ReinitUserCryptoError.NotUnlocked")
        } catch BitwardenError.ReinitUserCrypto(let inner) {
            guard case .NotUnlocked = inner else {
                XCTFail("expected .NotUnlocked, got \(inner)")
                return
            }
        }
    }

    func testReturnsAlreadyV2WhenActiveUserIsV2() async throws {
        let client = try await makeV2InitializedClient(stateBridge: stateBridge)

        let req = ReinitUserCryptoRequest(
            accountCryptographicState: makeV2AccountCryptographicState(),
            upgradeToken: makeMockUpgradeToken()
        )

        do {
            try await client.crypto().reinitUserCrypto(req: req)
            XCTFail("expected ReinitUserCryptoError.AlreadyV2Encryption")
        } catch BitwardenError.ReinitUserCrypto(let inner) {
            guard case .AlreadyV2Encryption = inner else {
                XCTFail("expected .AlreadyV2Encryption, got \(inner)")
                return
            }
        }
    }

    func testUpgradesV1ToV2WithValidToken() async throws {
        let client = try await makeV1InitializedClient(stateBridge: stateBridge)

        let upgradeToken = makeValidUpgradeToken()
        await stateBridge.setV2UpgradeToken(value: upgradeToken)

        let req = ReinitUserCryptoRequest(
            accountCryptographicState: makeV2AccountCryptographicState(),
            upgradeToken: upgradeToken
        )

        try await client.crypto().reinitUserCrypto(req: req)

        // After a successful V1→V2 reinit, the active user key in the slot
        // must be the V2 test-vector key (returned base64-encoded by
        // `getUserEncryptionKey` for V2 keys via COSE serialization).
        let userKey = try await client.crypto().getUserEncryptionKey()
        XCTAssertEqual(userKey, TEST_VECTOR_USER_KEY_V2_B64)
    }

    func testInvalidUpgradeTokenReturnsError() async throws {
        let client = try await makeV1InitializedClient(stateBridge: stateBridge)

        let req = ReinitUserCryptoRequest(
            accountCryptographicState: makeV2AccountCryptographicState(),
            upgradeToken: makeMockUpgradeToken()
        )

        do {
            try await client.crypto().reinitUserCrypto(req: req)
            XCTFail("expected ReinitUserCryptoError.InvalidUpgradeToken")
        } catch BitwardenError.ReinitUserCrypto(let inner) {
            guard case .InvalidUpgradeToken = inner else {
                XCTFail("expected .InvalidUpgradeToken, got \(inner)")
                return
            }
        }
    }
}
