import BitwardenSdk
import XCTest

/// `decryptList`, `decryptListWithFailures` and `decryptListFullWithFailures` take a list of
/// ciphers across the FFI boundary and return the decrypted ciphers in input order.
final class CipherListDecryptTests: XCTestCase {
    var client: Client!
    var ciphers: CiphersClient!

    override func setUp() async throws {
        try await super.setUp()
        client = try await makeInitializedClient(stateBridge: InMemoryStateBridge())
        ciphers = client.vault().ciphers()
    }

    func testDecryptsEveryFieldInOrder() async throws {
        // 1. Encrypt logins, some with notes
        let views = loginViews(0..<5)
        let encrypted = try await client.encrypt(views)
        XCTAssertTrue(encrypted.allSatisfy { $0.key != nil })

        // 2. Verify the list views
        let listViews = try await ciphers.decryptList(ciphers: encrypted)
        XCTAssertEqual(listViews.map(\.id), views.map(\.id))
        XCTAssertEqual(listViews.map(\.name), views.map(\.name))
        XCTAssertEqual(listViews.map(\.subtitle), views.map { $0.login?.username })
        XCTAssertEqual(
            listViews.map { view -> [String?]? in
                guard case let .login(login) = view.type else { return nil }
                return login.uris?.map(\.uri)
            },
            views.map { $0.login?.uris?.map(\.uri) }
        )
        let list = try await ciphers.decryptListWithFailures(ciphers: encrypted)
        XCTAssertEqual(list.successes, listViews)

        // 3. Verify the full views
        let full = try await ciphers.decryptListFullWithFailures(ciphers: encrypted)
        XCTAssertEqual(full.failures, [])
        XCTAssertEqual(full.successes.map(\.id), views.map(\.id))
        XCTAssertEqual(full.successes.map(\.name), views.map(\.name))
        XCTAssertEqual(full.successes.map(\.notes), views.map(\.notes))
        XCTAssertEqual(full.successes.map { $0.login?.username }, views.map { $0.login?.username })
        XCTAssertEqual(full.successes.map { $0.login?.password }, views.map { $0.login?.password })
        XCTAssertEqual(
            full.successes.map { $0.login?.uris?.map(\.uri) },
            views.map { $0.login?.uris?.map(\.uri) }
        )
    }

    func testDecryptsAnEmptyList() async throws {
        let listViews = try await ciphers.decryptList(ciphers: [])
        XCTAssertEqual(listViews, [])
        let list = try await ciphers.decryptListWithFailures(ciphers: [])
        XCTAssertEqual(list.successes, [])
        XCTAssertEqual(list.failures, [])
        let full = try await ciphers.decryptListFullWithFailures(ciphers: [])
        XCTAssertEqual(full.successes, [])
        XCTAssertEqual(full.failures, [])
    }

    func testReportsCiphersThatFailToDecrypt() async throws {
        // 1. Put ciphers of another account between ciphers of this one
        let views = loginViews(0..<3)
        let good = try await client.encrypt(views)
        let foreign = try await foreignCiphers(2)
        let input = [foreign[0], good[0], good[1], foreign[1], good[2]]

        // 2. Verify the failures come back as given, and the rest decrypts in order
        let list = try await ciphers.decryptListWithFailures(ciphers: input)
        XCTAssertEqual(list.successes.map(\.name), views.map(\.name))
        XCTAssertEqual(list.failures, foreign)
        let full = try await ciphers.decryptListFullWithFailures(ciphers: input)
        XCTAssertEqual(full.successes.map(\.name), views.map(\.name))
        XCTAssertEqual(full.failures, foreign)

        // 3. Verify `decryptList` fails as a whole, with a crypto error
        do {
            _ = try await ciphers.decryptList(ciphers: input)
            XCTFail("expected DecryptError.Crypto")
        } catch BitwardenError.Decrypt(let inner) {
            guard case .Crypto = inner else {
                XCTFail("expected .Crypto, got \(inner)")
                return
            }
        }
    }

    func testDecryptsAListSplitOverSeveralThreads() async throws {
        // 1. Encrypt a list long enough to be split over several threads
        let count = LONG_LIST_SIZE
        let views = loginViews(0..<count)
        let encrypted = try await client.encrypt(views)

        // 2. Verify every cipher decrypts, in order
        let listViews = try await ciphers.decryptList(ciphers: encrypted)
        XCTAssertEqual(listViews.map(\.name), views.map(\.name))

        // 3. Make two adjacent ciphers in the middle of the list fail
        let failingIndexes = [count / 2 - 1, count / 2]
        let foreign = try await foreignCiphers(failingIndexes.count)
        var input = encrypted
        for (i, index) in failingIndexes.enumerated() {
            input[index] = foreign[i]
        }
        let expectedNames = views.enumerated()
            .filter { !failingIndexes.contains($0.offset) }
            .map(\.element.name)

        // 4. Verify the failures, in order, and every other cipher, in order
        let list = try await ciphers.decryptListWithFailures(ciphers: input)
        XCTAssertEqual(list.successes.map(\.name), expectedNames)
        XCTAssertEqual(list.failures, foreign)
        let full = try await ciphers.decryptListFullWithFailures(ciphers: input)
        XCTAssertEqual(full.successes.map(\.name), expectedNames)
        XCTAssertEqual(full.failures, foreign)
    }
}
