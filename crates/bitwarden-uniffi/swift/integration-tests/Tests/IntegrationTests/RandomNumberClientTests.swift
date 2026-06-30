import BitwardenSdk
import XCTest

/// Swift integration tests for `SdkRandomNumberClient`, the UniFFI binding for
/// `bitwarden-random`'s cross-platform FFI.
final class RandomNumberClientTests: XCTestCase {
    func testGenBytesReturnsRequestedLength() throws {
        let client = SdkRandomNumberClient()
        XCTAssertEqual(client.genBytes(len: 0).count, 0)
        XCTAssertEqual(client.genBytes(len: 32).count, 32)
        // 1 KiB is the documented maximum and must not trap.
        XCTAssertEqual(client.genBytes(len: 1024).count, 1024)
    }

    func testGenBytesIsRandom() throws {
        let client = SdkRandomNumberClient()
        XCTAssertNotEqual(client.genBytes(len: 32), client.genBytes(len: 32))
    }

    func testGenUuidIsAValidUuid() throws {
        let client = SdkRandomNumberClient()
        let uuid = client.genUuid()
        XCTAssertNotNil(UUID(uuidString: uuid), "gen_uuid should return a parseable UUID string")
    }

    func testGenUuidIsDistinct() throws {
        let client = SdkRandomNumberClient()
        XCTAssertNotEqual(client.genUuid(), client.genUuid())
    }

    func testGenRangeStaysWithinInclusiveBounds() throws {
        let client = SdkRandomNumberClient()
        for _ in 0..<1000 {
            let n = client.genRange(min: 10, max: 20)
            XCTAssertTrue((10...20).contains(n))
        }
        XCTAssertEqual(client.genRange(min: 7, max: 7), 7)
    }
}
