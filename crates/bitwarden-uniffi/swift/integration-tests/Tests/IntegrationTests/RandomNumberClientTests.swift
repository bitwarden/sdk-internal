import BitwardenSdk
import XCTest

/// Swift integration tests for `SdkRandomNumberClient`, the UniFFI binding for
/// `bitwarden-random`'s cross-platform FFI.
final class RandomNumberClientTests: XCTestCase {
    func testGenBytesReturnsRequestedLength() throws {
        let client = SdkRandomNumberClient()
        XCTAssertEqual(try client.genBytes(len: 0).count, 0)
        XCTAssertEqual(try client.genBytes(len: 32).count, 32)
        // 1 KiB is the documented maximum and must succeed.
        XCTAssertEqual(try client.genBytes(len: 1024).count, 1024)
    }

    func testGenBytesAboveLimitThrows() throws {
        let client = SdkRandomNumberClient()
        // Over the 1 KiB limit throws a catchable error instead of trapping.
        XCTAssertThrowsError(try client.genBytes(len: 1025))
    }

    func testGenBytesIsRandom() throws {
        let client = SdkRandomNumberClient()
        XCTAssertNotEqual(try client.genBytes(len: 32), try client.genBytes(len: 32))
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
            let n = try client.genRange(min: 10, max: 20)
            XCTAssertTrue((10...20).contains(n))
        }
        XCTAssertEqual(try client.genRange(min: 7, max: 7), 7)
        // An inverted range throws a catchable error instead of trapping.
        XCTAssertThrowsError(try client.genRange(min: 20, max: 10))
    }
}
