package com.bitwarden.sdk.e2etests

import com.bitwarden.sdk.BitwardenException
import com.bitwarden.sdk.CipherIterator
import com.bitwarden.sdk.CipherListItem
import com.bitwarden.sdk.CipherListStream
import com.bitwarden.sdk.CipherRepository
import com.bitwarden.sdk.Client
import com.bitwarden.sdk.Repositories
import com.bitwarden.vault.Cipher
import com.bitwarden.vault.DecryptStreamException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Collections
import java.util.concurrent.ConcurrentSkipListMap

/**
 * `listStream` reads the ciphers from the client-managed cipher repository through the iterator
 * its `listIter` returns, and decrypts them a chunk per `nextChunk` call, in the repository's
 * order.
 *
 * `listStream` and `listIter` are only exported to UniFFI, so `e2e/wasm` has no counterparts. It
 * tests the WASM listing, `list_iterable`, in `tests/vault/list-iterable.test.ts`.
 */
class CipherListStreamTests {
    private lateinit var client: Client

    @Before
    fun setUp() = runBlocking {
        client = makeInitializedClient(InMemoryStateBridge())
    }

    @Test
    fun listsEveryCipherInOrderABatchPerChunk() = runBlocking {
        // 1. Store logins in a repository that reads a batch per `next` call
        val views = loginViews(0..4)
        val repository = InMemoryCipherRepository(oneBatch = false)
        repository.store(client.encrypt(views))
        client.registerCipherRepository(repository)

        // 2. Verify every cipher decrypts, a batch per chunk, in id order
        val chunks = client.vault().ciphers().listStream(2u).chunks()
        assertEquals(listOf(2, 2, 1), chunks.map { it.size })
        assertEquals(
            views.sortedBy { it.id }.map { it.name },
            chunks.flatten().map { (it as CipherListItem.Decrypted).view.name },
        )
        assertEquals(listOf(2u), repository.batchSizes)
        assertEquals(0, repository.lists)
    }

    @Test
    fun listsEveryCipherFromASingleBatch() = runBlocking {
        // 1. Store logins in a repository whose iterator returns `list()` as one batch
        val views = loginViews(0..4)
        val repository = InMemoryCipherRepository(oneBatch = true)
        repository.store(client.encrypt(views))
        client.registerCipherRepository(repository)

        // 2. Verify every cipher decrypts, the one batch split into chunks of the chunk size
        val chunks = client.vault().ciphers().listStream(2u).chunks()
        assertEquals(listOf(2, 2, 1), chunks.map { it.size })
        assertEquals(
            views.sortedBy { it.id }.map { it.name },
            chunks.flatten().map { (it as CipherListItem.Decrypted).view.name },
        )
        assertEquals(1, repository.lists)
    }

    @Test
    fun keepsAFailedCipherInItsPlace() = runBlocking {
        // 1. Store ciphers of another account between ciphers of this one
        val views = loginViews(0..2)
        val good = client.encrypt(views)
        val foreign = foreignCiphers(2)
        val repository = InMemoryCipherRepository(oneBatch = false)
        repository.store(good + foreign)
        client.registerCipherRepository(repository)

        // 2. Verify each foreign cipher comes back as stored, in its place
        val items = client.vault().ciphers().listStream(2u).chunks().flatten()
        val expected = (good + foreign).sortedBy { it.id }.map { cipher ->
            if (cipher in foreign) {
                "failed ${cipher.id}"
            } else {
                "decrypted ${views.first { it.id == cipher.id }.name}"
            }
        }
        assertEquals(
            expected,
            items.map {
                when (it) {
                    is CipherListItem.Decrypted -> "decrypted ${it.view.name}"
                    is CipherListItem.Failed -> "failed ${it.cipher.id}"
                }
            },
        )
        assertEquals(
            foreign.sortedBy { it.id },
            items.filterIsInstance<CipherListItem.Failed>().map { it.cipher },
        )
    }

    @Test
    fun endsWhenTheVaultIsLocked() = runBlocking {
        // 1. Lock the vault with ciphers in state
        val repository = InMemoryCipherRepository(oneBatch = false)
        repository.store(client.encrypt(loginViews(0..2)))
        client.registerCipherRepository(repository)
        client.unlock().lock()

        // 2. Verify the stream fails once as locked, then ends
        val stream = client.vault().ciphers().listStream(2u)
        val error = assertThrows(BitwardenException.DecryptStream::class.java) {
            runBlocking { stream.nextChunk() }
        }
        assertTrue(
            "expected VaultLocked, got ${error.v1}",
            error.v1 is DecryptStreamException.VaultLocked,
        )
        assertNull(stream.nextChunk())
    }
}

/** Registers `repository` as the client's cipher repository. */
private fun Client.registerCipherRepository(repository: CipherRepository) {
    platform().state().registerClientManagedRepositories(
        Repositories(
            cipher = repository,
            folder = null,
            localUserDataKeyState = null,
            organizationSharedKey = null,
            send = null,
            policy = null,
            organization = null,
        ),
    )
}

/** Every chunk of the stream, read until it ends. */
private suspend fun CipherListStream.chunks(): List<List<CipherListItem>> {
    val chunks = mutableListOf<List<CipherListItem>>()
    while (true) {
        chunks += nextChunk() ?: return chunks
    }
}

/**
 * An in-memory client-managed cipher repository, ordered by id. Its iterator reads up to
 * `batchSize` ciphers per `next` call, after the id of the last cipher read. With `oneBatch`, it
 * returns `list()` as one batch instead. Counts the `list` calls and records each `batchSize`.
 */
class InMemoryCipherRepository(private val oneBatch: Boolean) : CipherRepository {
    private val ciphers = ConcurrentSkipListMap<String, Cipher>()

    @Volatile var lists = 0
        private set
    val batchSizes: MutableList<UInt> = Collections.synchronizedList(mutableListOf())

    /** Stores `ciphers` under their ids. */
    fun store(ciphers: List<Cipher>) {
        ciphers.forEach { this.ciphers[it.id!!] = it }
    }

    override suspend fun get(id: String): Cipher? = ciphers[id]
    override suspend fun list(): List<Cipher> {
        lists++
        return ciphers.values.toList()
    }
    override suspend fun set(id: String, value: Cipher) { ciphers[id] = value }
    override suspend fun setBulk(values: Map<String, Cipher>) { ciphers.putAll(values) }
    override suspend fun remove(id: String) { ciphers.remove(id) }
    override suspend fun removeBulk(keys: List<String>) { keys.forEach { ciphers.remove(it) } }
    override suspend fun removeAll() { ciphers.clear() }
    override suspend fun has(id: String): Boolean = ciphers.containsKey(id)

    override fun listIter(batchSize: UInt): CipherIterator {
        batchSizes += batchSize
        return if (oneBatch) OneBatchIterator() else KeysetIterator(batchSize.toInt())
    }

    /** Returns every cipher from `list()` as one batch, then `null`. */
    private inner class OneBatchIterator : CipherIterator {
        @Volatile private var done = false

        override suspend fun next(): List<Cipher>? {
            if (done) return null
            done = true
            return list()
        }
    }

    /** Reads up to `batchSize` ciphers per call, after the id of the last cipher read. */
    private inner class KeysetIterator(private val batchSize: Int) : CipherIterator {
        @Volatile private var after: String? = null

        override suspend fun next(): List<Cipher>? {
            val tail = after?.let { ciphers.tailMap(it, false) } ?: ciphers
            val batch = tail.values.take(batchSize)
            if (batch.isEmpty()) return null
            after = batch.last().id
            return batch
        }
    }
}
