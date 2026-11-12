package com.bitwarden.sdk.e2etests

import com.bitwarden.sdk.BitwardenException
import com.bitwarden.sdk.CiphersClient
import com.bitwarden.sdk.Client
import com.bitwarden.vault.Cipher
import com.bitwarden.vault.CipherListViewType
import com.bitwarden.vault.DecryptException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `decryptList`, `decryptListWithFailures` and `decryptListFullWithFailures` take a list of
 * ciphers across the FFI boundary and return the decrypted ciphers in input order.
 */
class CipherListDecryptTests {
    private lateinit var client: Client
    private lateinit var ciphers: CiphersClient

    @Before
    fun setUp() = runBlocking {
        client = makeInitializedClient(InMemoryStateBridge())
        ciphers = client.vault().ciphers()
    }

    @Test
    fun decryptsEveryFieldInOrder() = runBlocking {
        // 1. Encrypt logins, some with notes
        val views = loginViews(0 until 5)
        val encrypted = client.encrypt(views)
        assertTrue(encrypted.all { it.key != null })

        // 2. Verify the list views
        val listViews = ciphers.decryptList(encrypted)
        assertEquals(views.map { it.id }, listViews.map { it.id })
        assertEquals(views.map { it.name }, listViews.map { it.name })
        assertEquals(views.map { it.login?.username }, listViews.map { it.subtitle })
        assertEquals(
            views.map { it.login?.uris?.map { uri -> uri.uri } },
            listViews.map { (it.type as CipherListViewType.Login).v1.uris?.map { uri -> uri.uri } },
        )
        assertEquals(listViews, ciphers.decryptListWithFailures(encrypted).successes)

        // 3. Verify the full views
        val full = ciphers.decryptListFullWithFailures(encrypted)
        assertEquals(emptyList<Cipher>(), full.failures)
        assertEquals(views.map { it.id }, full.successes.map { it.id })
        assertEquals(views.map { it.name }, full.successes.map { it.name })
        assertEquals(views.map { it.notes }, full.successes.map { it.notes })
        assertEquals(views.map { it.login?.username }, full.successes.map { it.login?.username })
        assertEquals(views.map { it.login?.password }, full.successes.map { it.login?.password })
        assertEquals(
            views.map { it.login?.uris?.map { uri -> uri.uri } },
            full.successes.map { it.login?.uris?.map { uri -> uri.uri } },
        )
    }

    @Test
    fun decryptsAnEmptyList() = runBlocking {
        assertEquals(emptyList<Any>(), ciphers.decryptList(emptyList()))
        val list = ciphers.decryptListWithFailures(emptyList())
        assertEquals(emptyList<Any>(), list.successes)
        assertEquals(emptyList<Any>(), list.failures)
        val full = ciphers.decryptListFullWithFailures(emptyList())
        assertEquals(emptyList<Any>(), full.successes)
        assertEquals(emptyList<Any>(), full.failures)
    }

    @Test
    fun reportsCiphersThatFailToDecrypt() = runBlocking {
        // 1. Put ciphers of another account between ciphers of this one
        val views = loginViews(0 until 3)
        val good = client.encrypt(views)
        val foreign = foreignCiphers(2)
        val input = listOf(foreign[0], good[0], good[1], foreign[1], good[2])

        // 2. Verify the failures come back as given, and the rest decrypts in order
        val list = ciphers.decryptListWithFailures(input)
        assertEquals(views.map { it.name }, list.successes.map { it.name })
        assertEquals(foreign, list.failures)
        val full = ciphers.decryptListFullWithFailures(input)
        assertEquals(views.map { it.name }, full.successes.map { it.name })
        assertEquals(foreign, full.failures)

        // 3. Verify `decryptList` fails as a whole, with a crypto error
        val error = assertThrows(BitwardenException.Decrypt::class.java) {
            runBlocking { ciphers.decryptList(input) }
        }
        assertTrue("expected Crypto, got ${error.v1}", error.v1 is DecryptException.Crypto)
    }

    @Test
    fun decryptsAListSplitOverSeveralThreads() = runBlocking {
        // 1. Encrypt a list long enough to be split over several threads
        val count = LONG_LIST_SIZE
        val views = loginViews(0 until count)
        val encrypted = client.encrypt(views)

        // 2. Verify every cipher decrypts, in order
        assertEquals(views.map { it.name }, ciphers.decryptList(encrypted).map { it.name })

        // 3. Make two adjacent ciphers in the middle of the list fail
        val failingIndexes = listOf(count / 2 - 1, count / 2)
        val foreign = foreignCiphers(failingIndexes.size)
        val input = encrypted.toMutableList()
        failingIndexes.forEachIndexed { i, index -> input[index] = foreign[i] }
        val expectedNames = views.filterIndexed { i, _ -> i !in failingIndexes }.map { it.name }

        // 4. Verify the failures, in order, and every other cipher, in order
        val list = ciphers.decryptListWithFailures(input)
        assertEquals(expectedNames, list.successes.map { it.name })
        assertEquals(foreign, list.failures)
        val full = ciphers.decryptListFullWithFailures(input)
        assertEquals(expectedNames, full.successes.map { it.name })
        assertEquals(foreign, full.failures)
    }
}
