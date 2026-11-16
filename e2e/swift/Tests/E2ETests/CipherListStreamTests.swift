import BitwardenSdk
import Foundation
import XCTest

/// `listStream` reads the ciphers from the client-managed cipher repository through the iterator
/// its `listIter` returns, and decrypts them a chunk per `nextChunk` call, in the repository's
/// order.
///
/// `listStream` and `listIter` are only exported to UniFFI, so `e2e/wasm` has no counterparts. It
/// tests the WASM listing, `list_iterable`, in `tests/vault/list-iterable.test.ts`.
final class CipherListStreamTests: XCTestCase {
    var client: Client!

    override func setUp() async throws {
        try await super.setUp()
        client = try await makeInitializedClient(stateBridge: InMemoryStateBridge())
    }

    func testListsEveryCipherInOrderABatchPerChunk() async throws {
        // 1. Store logins in a repository that reads a batch per `next` call
        let views = loginViews(0..<5)
        let repository = InMemoryCipherRepository(oneBatch: false)
        repository.store(try await client.encrypt(views))
        client.registerCipherRepository(repository)

        // 2. Verify every cipher decrypts, a batch per chunk, in id order
        let chunks = try await client.vault().ciphers().listStream(chunkSize: 2).chunks()
        XCTAssertEqual(chunks.map(\.count), [2, 2, 1])
        XCTAssertEqual(
            chunks.joined().map(\.decryptedName),
            views.sorted { $0.id! < $1.id! }.map(\.name)
        )
        XCTAssertEqual(repository.batchSizes, [2])
        XCTAssertEqual(repository.lists, 0)
    }

    func testListsEveryCipherFromASingleBatch() async throws {
        // 1. Store logins in a repository whose iterator returns `list()` as one batch
        let views = loginViews(0..<5)
        let repository = InMemoryCipherRepository(oneBatch: true)
        repository.store(try await client.encrypt(views))
        client.registerCipherRepository(repository)

        // 2. Verify every cipher decrypts, the one batch split into chunks of the chunk size
        let chunks = try await client.vault().ciphers().listStream(chunkSize: 2).chunks()
        XCTAssertEqual(chunks.map(\.count), [2, 2, 1])
        XCTAssertEqual(
            chunks.joined().map(\.decryptedName),
            views.sorted { $0.id! < $1.id! }.map(\.name)
        )
        XCTAssertEqual(repository.lists, 1)
    }

    func testKeepsAFailedCipherInItsPlace() async throws {
        // 1. Store ciphers of another account between ciphers of this one
        let views = loginViews(0..<3)
        let good = try await client.encrypt(views)
        let foreign = try await foreignCiphers(2)
        let repository = InMemoryCipherRepository(oneBatch: false)
        repository.store(good + foreign)
        client.registerCipherRepository(repository)

        // 2. Verify each foreign cipher comes back as stored, in its place
        let items = try await client.vault().ciphers().listStream(chunkSize: 2).chunks().joined()
        let expected = (good + foreign).sorted { $0.id! < $1.id! }.map { cipher in
            foreign.contains(cipher)
                ? "failed \(cipher.id!)"
                : "decrypted \(views.first { $0.id == cipher.id }!.name)"
        }
        XCTAssertEqual(
            items.map { item -> String in
                switch item {
                case let .decrypted(view): "decrypted \(view.name)"
                case let .failed(cipher): "failed \(cipher.id!)"
                }
            },
            expected
        )
        XCTAssertEqual(
            items.compactMap { item -> Cipher? in
                guard case let .failed(cipher) = item else { return nil }
                return cipher
            },
            foreign.sorted { $0.id! < $1.id! }
        )
    }

    func testEndsWhenTheVaultIsLocked() async throws {
        // 1. Lock the vault with ciphers in state
        let repository = InMemoryCipherRepository(oneBatch: false)
        repository.store(try await client.encrypt(loginViews(0..<3)))
        client.registerCipherRepository(repository)
        await client.unlock().lock()

        // 2. Verify the stream fails once as locked, then ends
        let stream = client.vault().ciphers().listStream(chunkSize: 2)
        do {
            _ = try await stream.nextChunk()
            XCTFail("expected DecryptStreamError.VaultLocked")
        } catch BitwardenError.DecryptStream(let inner) {
            guard case .VaultLocked = inner else {
                XCTFail("expected .VaultLocked, got \(inner)")
                return
            }
        }
        let next = try await stream.nextChunk()
        XCTAssertNil(next)
    }
}

private extension Client {
    /// Registers `repository` as the client's cipher repository.
    func registerCipherRepository(_ repository: CipherRepository) {
        platform().state().registerClientManagedRepositories(
            repositories: Repositories(
                cipher: repository,
                folder: nil,
                localUserDataKeyState: nil,
                organizationSharedKey: nil,
                send: nil,
                policy: nil,
                organization: nil
            )
        )
    }
}

private extension CipherListStream {
    /// Every chunk of the stream, read until it ends.
    func chunks() async throws -> [[CipherListItem]] {
        var chunks: [[CipherListItem]] = []
        while let chunk = try await nextChunk() {
            chunks.append(chunk)
        }
        return chunks
    }
}

private extension CipherListItem {
    /// The name of a decrypted cipher, `nil` for a failed one.
    var decryptedName: String? {
        guard case let .decrypted(view) = self else { return nil }
        return view.name
    }
}

/// An in-memory client-managed cipher repository, ordered by id. Its iterator reads up to
/// `batchSize` ciphers per `next` call, after the id of the last cipher read. With `oneBatch`, it
/// returns `list()` as one batch instead. Counts the `list` calls and records each `batchSize`.
///
/// A class with a lock, not an actor, because the SDK calls `listIter` synchronously.
final class InMemoryCipherRepository: CipherRepository, @unchecked Sendable {
    private let lock = NSLock()
    private let oneBatch: Bool
    private var ciphers: [String: Cipher] = [:]
    private var listCount = 0
    private var requestedBatchSizes: [UInt32] = []

    init(oneBatch: Bool) {
        self.oneBatch = oneBatch
    }

    /// How many times `list` was called.
    var lists: Int { lock.locked { listCount } }

    /// The `batchSize` of each `listIter` call.
    var batchSizes: [UInt32] { lock.locked { requestedBatchSizes } }

    /// Stores `ciphers` under their ids.
    func store(_ ciphers: [Cipher]) {
        lock.locked {
            for cipher in ciphers {
                self.ciphers[cipher.id!] = cipher
            }
        }
    }

    /// The stored ciphers after `after` (from the first when `nil`), at most `limit`.
    func batch(after: String?, limit: Int) -> [Cipher] {
        lock.locked {
            Array(
                ciphers.keys.sorted()
                    .filter { after == nil || $0 > after! }
                    .prefix(limit)
                    .map { ciphers[$0]! }
            )
        }
    }

    func get(id: String) async throws -> Cipher? { lock.locked { ciphers[id] } }
    func list() async throws -> [Cipher] {
        lock.locked {
            listCount += 1
            return ciphers.keys.sorted().map { ciphers[$0]! }
        }
    }
    func set(id: String, value: Cipher) async throws { lock.locked { ciphers[id] = value } }
    func setBulk(values: [String: Cipher]) async throws {
        lock.locked { ciphers.merge(values) { $1 } }
    }
    func remove(id: String) async throws { lock.locked { ciphers[id] = nil } }
    func removeBulk(keys: [String]) async throws {
        lock.locked { keys.forEach { ciphers[$0] = nil } }
    }
    func removeAll() async throws { lock.locked { ciphers.removeAll() } }
    func has(id: String) async throws -> Bool { lock.locked { ciphers[id] != nil } }

    func listIter(batchSize: UInt32) throws -> CipherIterator {
        lock.locked { requestedBatchSizes.append(batchSize) }
        return oneBatch
            ? OneBatchCipherIterator(repository: self)
            : KeysetCipherIterator(repository: self, batchSize: Int(batchSize))
    }
}

/// Returns every cipher from the repository's `list()` as one batch, then `nil`.
final class OneBatchCipherIterator: CipherIterator, @unchecked Sendable {
    private let repository: InMemoryCipherRepository
    private let lock = NSLock()
    private var done = false

    init(repository: InMemoryCipherRepository) {
        self.repository = repository
    }

    func next() async throws -> [Cipher]? {
        let first = lock.locked {
            defer { done = true }
            return !done
        }
        return first ? try await repository.list() : nil
    }
}

/// Reads up to `batchSize` ciphers per call, after the id of the last cipher read.
final class KeysetCipherIterator: CipherIterator, @unchecked Sendable {
    private let repository: InMemoryCipherRepository
    private let batchSize: Int
    private let lock = NSLock()
    private var after: String?

    init(repository: InMemoryCipherRepository, batchSize: Int) {
        self.repository = repository
        self.batchSize = batchSize
    }

    func next() async throws -> [Cipher]? {
        let batch = repository.batch(after: lock.locked { after }, limit: batchSize)
        guard let last = batch.last else { return nil }
        lock.locked { after = last.id }
        return batch
    }
}

private extension NSLock {
    /// Runs `body` while holding the lock. `NSLock.withLock` needs iOS 16, after the package's
    /// iOS 13 deployment target.
    func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
