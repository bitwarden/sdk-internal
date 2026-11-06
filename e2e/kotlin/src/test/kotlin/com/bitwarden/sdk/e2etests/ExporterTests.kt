package com.bitwarden.sdk.e2etests

import com.bitwarden.exporters.Account
import com.bitwarden.exporters.ExportFormat
import com.bitwarden.sdk.Client
import com.bitwarden.sdk.ExporterClient
import java.util.UUID
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/** `exportVault` and `exportCxf` take a list of ciphers across the FFI boundary and decrypt it. */
class ExporterTests {
    private lateinit var client: Client
    private lateinit var exporters: ExporterClient

    @Before
    fun setUp() = runBlocking {
        client = makeInitializedClient(InMemoryStateBridge())
        exporters = client.exporters()
    }

    /** The values of `field` of the items in the JSON `export`. */
    private fun itemValues(export: String, field: String): List<String> =
        Json.parseToJsonElement(export).jsonObject.getValue("items").jsonArray.map {
            it.jsonObject.getValue(field).jsonPrimitive.content
        }

    @Test
    fun exportsEveryCipherAsJsonInOrder() = runBlocking {
        val views = loginViews(0 until 300)
        val encrypted = client.encrypt(views)

        val export = exporters.exportVault(emptyList(), encrypted, ExportFormat.Json)

        assertEquals(views.map { it.name }, itemValues(export, "name"))
    }

    @Test
    fun leavesOutCiphersThatFailToDecrypt() = runBlocking {
        val views = loginViews(0 until 3)
        val good = client.encrypt(views)
        val foreign = foreignCiphers(1)
        val input = listOf(good[0], foreign[0], good[1], good[2])

        val export = exporters.exportVault(emptyList(), input, ExportFormat.Json)

        assertEquals(views.map { it.name }, itemValues(export, "name"))
    }

    @Test
    fun exportsCiphersAsCxfInOrder() = runBlocking {
        val views = loginViews(0 until 3)
        val good = client.encrypt(views)
        val foreign = foreignCiphers(1)
        val input = listOf(good[0], foreign[0], good[1], good[2])
        val account = Account(UUID.randomUUID().toString(), TEST_EMAIL, null)

        val export = exporters.exportCxf(account, input)

        assertEquals(views.map { it.name }, itemValues(export, "title"))
    }
}
