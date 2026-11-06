package com.bitwarden.sdk.e2etests

import com.bitwarden.sdk.Client
import com.bitwarden.vault.Cipher
import com.bitwarden.vault.CipherRepromptType
import com.bitwarden.vault.CipherType
import com.bitwarden.vault.CipherView
import com.bitwarden.vault.LoginUriView
import com.bitwarden.vault.LoginView
import java.time.Instant
import java.util.UUID

/**
 * A list length that `KeyStore::decrypt_large_vec` in `bitwarden-crypto` splits over several rayon
 * threads, with one rayon thread per available processor. It decrypts a list from Rust as one
 * slice, in one piece per thread of at least `batch_chunk_size` (50) ciphers. Lists this long check
 * that order and failures hold across those pieces.
 */
val LONG_LIST_SIZE = Runtime.getRuntime().availableProcessors() * 500 + 100

private val DATE: Instant = Instant.parse("2024-01-01T00:00:00Z")

/** A login with a username, password and URI. Logins with an even index also have notes. */
fun loginView(index: Int, name: String = "Login $index"): CipherView = CipherView(
    // An export leaves out a cipher without an id.
    id = UUID.randomUUID().toString(),
    organizationId = null,
    folderId = null,
    collectionIds = emptyList(),
    key = null,
    name = name,
    notes = if (index % 2 == 0) "Notes $index" else null,
    type = CipherType.LOGIN,
    login = LoginView(
        username = "user$index",
        password = "password$index",
        passwordRevisionDate = null,
        uris = listOf(LoginUriView("https://example.com/$index", null, null)),
        totp = null,
        autofillOnPageLoad = null,
        fido2Credentials = null,
    ),
    identity = null,
    card = null,
    secureNote = null,
    sshKey = null,
    bankAccount = null,
    driversLicense = null,
    passport = null,
    favorite = false,
    reprompt = CipherRepromptType.NONE,
    organizationUseTotp = false,
    edit = true,
    permissions = null,
    viewPassword = true,
    localData = null,
    attachments = null,
    attachmentDecryptionFailures = null,
    fields = null,
    passwordHistory = null,
    creationDate = DATE,
    deletedDate = null,
    revisionDate = DATE,
    archivedDate = null,
    partial = false,
)

/** `loginView` for each of `indices`. */
fun loginViews(indices: IntRange): List<CipherView> = indices.map(::loginView)

/** Encrypts `views` with the client's user key. Every cipher gets its own cipher key. */
suspend fun Client.encrypt(views: List<CipherView>): List<Cipher> =
    vault().ciphers().encryptList(views).map { it.cipher }

/**
 * Ciphers that fail to decrypt for a client of `makeInitializedClient`: they are encrypted for
 * another account, so their cipher keys are wrapped with a user key that client does not have.
 */
suspend fun foreignCiphers(count: Int): List<Cipher> =
    makeV2InitializedClient(InMemoryStateBridge())
        .encrypt((0 until count).map { loginView(it, name = "Foreign login $it") })
