import BitwardenSdk
import XCTest

/// Swift port of `crates/bitwarden-wasm-internal/integration-tests/tests/pin-lock.test.ts`.
final class PinLockTests: XCTestCase {
    var client: Client!
    var stateBridge: InMemoryStateBridge!

    override func setUp() async throws {
        try await super.setUp()
        stateBridge = InMemoryStateBridge()
        client = try await makeInitializedClient(stateBridge: stateBridge)
    }

    func testEnrollsPinBeforeFirstUnlock() async throws {
        let pinSettings = client.userCryptoManagement().pinSettings()

        try await pinSettings.setPin(pin: TEST_PIN, lockType: .beforeFirstUnlock)

        let status = await pinSettings.getStatus()
        XCTAssertEqual(status, .available)
        let lockType = await pinSettings.getLockType()
        XCTAssertEqual(lockType, .beforeFirstUnlock)

        let encryptedPin = await stateBridge.getEncryptedPin()
        XCTAssertNotNil(encryptedPin)
        // BeforeFirstUnlock populates both envelopes
        let persistent = await stateBridge.getPersistentPinEnvelope()
        XCTAssertNotNil(persistent)
        let ephemeral = await stateBridge.getEphemeralPinEnvelope()
        XCTAssertNotNil(ephemeral)
    }

    func testEnrollsPinAfterFirstUnlock() async throws {
        let pinSettings = client.userCryptoManagement().pinSettings()

        try await pinSettings.setPin(pin: TEST_PIN, lockType: .afterFirstUnlock)

        let status = await pinSettings.getStatus()
        XCTAssertEqual(status, .available)
        let lockType = await pinSettings.getLockType()
        XCTAssertEqual(lockType, .afterFirstUnlock)

        let encryptedPin = await stateBridge.getEncryptedPin()
        XCTAssertNotNil(encryptedPin)
        // AfterFirstUnlock populates only the ephemeral envelope
        let ephemeral = await stateBridge.getEphemeralPinEnvelope()
        XCTAssertNotNil(ephemeral)
        let persistent = await stateBridge.getPersistentPinEnvelope()
        XCTAssertNil(persistent)
    }

    func testValidatesPin() async throws {
        let pinSettings = client.userCryptoManagement().pinSettings()

        try await pinSettings.setPin(pin: TEST_PIN, lockType: .beforeFirstUnlock)
        let validated = await pinSettings.validatePin(pin: TEST_PIN)

        XCTAssertTrue(validated)
    }

    func testUnsetsPin() async throws {
        let pinSettings = client.userCryptoManagement().pinSettings()

        try await pinSettings.setPin(pin: TEST_PIN, lockType: .beforeFirstUnlock)
        await pinSettings.unsetPin()

        let status = await pinSettings.getStatus()
        XCTAssertEqual(status, .notSet)
        let encryptedPin = await stateBridge.getEncryptedPin()
        XCTAssertNil(encryptedPin)
        let persistent = await stateBridge.getPersistentPinEnvelope()
        XCTAssertNil(persistent)
        let ephemeral = await stateBridge.getEphemeralPinEnvelope()
        XCTAssertNil(ephemeral)
    }
}
