import BitwardenSdk
import XCTest

/// `exportVault` and `exportCxf` take a list of ciphers across the FFI boundary and decrypt it.
final class ExporterTests: XCTestCase {
    var client: Client!
    var exporters: ExporterClient!

    override func setUp() async throws {
        try await super.setUp()
        client = try await makeInitializedClient(stateBridge: InMemoryStateBridge())
        exporters = client.exporters()
    }

    /// The values of `field` of the items in the JSON `export`.
    private func itemValues(_ export: String, _ field: String) throws -> [String] {
        let json = try JSONSerialization.jsonObject(with: Data(export.utf8)) as? [String: Any]
        let items = try XCTUnwrap(json?["items"] as? [[String: Any]])
        return try items.map { try XCTUnwrap($0[field] as? String) }
    }

    func testExportsEveryCipherAsJsonInOrder() async throws {
        let views = loginViews(0..<300)
        let encrypted = try await client.encrypt(views)

        let export = try await exporters.exportVault(folders: [], ciphers: encrypted, format: .json)

        XCTAssertEqual(try itemValues(export, "name"), views.map(\.name))
    }

    func testLeavesOutCiphersThatFailToDecrypt() async throws {
        let views = loginViews(0..<3)
        let good = try await client.encrypt(views)
        let foreign = try await foreignCiphers(1)
        let input = [good[0], foreign[0], good[1], good[2]]

        let export = try await exporters.exportVault(folders: [], ciphers: input, format: .json)

        XCTAssertEqual(try itemValues(export, "name"), views.map(\.name))
    }

    func testExportsCiphersAsCxfInOrder() async throws {
        let views = loginViews(0..<3)
        let good = try await client.encrypt(views)
        let foreign = try await foreignCiphers(1)
        let input = [good[0], foreign[0], good[1], good[2]]
        let account = Account(id: UUID().uuidString.lowercased(), email: TEST_EMAIL, name: nil)

        let export = try exporters.exportCxf(account: account, ciphers: input)

        XCTAssertEqual(try itemValues(export, "title"), views.map(\.name))
    }
}
