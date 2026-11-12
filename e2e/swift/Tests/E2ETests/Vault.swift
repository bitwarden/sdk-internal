import BitwardenSdk
import Foundation

/// A list length that `KeyStore::decrypt_large_vec` in `bitwarden-crypto` splits over several
/// rayon threads, with one rayon thread per available processor. It decrypts a list from Rust as
/// one slice, in one piece per thread of at least `batch_chunk_size` (50) ciphers. Lists this long
/// check that order and failures hold across those pieces.
let LONG_LIST_SIZE = ProcessInfo.processInfo.activeProcessorCount * 500 + 100

private let DATE = Date(timeIntervalSince1970: 1_704_067_200)

/// A login with a username, password and URI. Logins with an even index also have notes.
func loginView(_ index: Int, name: String? = nil) -> CipherView {
    CipherView(
        // An export leaves out a cipher without an id.
        id: UUID().uuidString.lowercased(),
        organizationId: nil,
        folderId: nil,
        collectionIds: [],
        key: nil,
        name: name ?? "Login \(index)",
        notes: index % 2 == 0 ? "Notes \(index)" : nil,
        type: .login,
        login: LoginView(
            username: "user\(index)",
            password: "password\(index)",
            passwordRevisionDate: nil,
            uris: [LoginUriView(uri: "https://example.com/\(index)", match: nil, uriChecksum: nil)],
            totp: nil,
            autofillOnPageLoad: nil,
            fido2Credentials: nil
        ),
        identity: nil,
        card: nil,
        secureNote: nil,
        sshKey: nil,
        bankAccount: nil,
        driversLicense: nil,
        passport: nil,
        favorite: false,
        reprompt: .none,
        organizationUseTotp: false,
        edit: true,
        permissions: nil,
        viewPassword: true,
        localData: nil,
        attachments: nil,
        attachmentDecryptionFailures: nil,
        fields: nil,
        passwordHistory: nil,
        creationDate: DATE,
        deletedDate: nil,
        revisionDate: DATE,
        archivedDate: nil,
        partial: false
    )
}

/// `loginView` for each of `indices`.
func loginViews(_ indices: Range<Int>) -> [CipherView] {
    indices.map { loginView($0) }
}

extension Client {
    /// Encrypts `views` with the client's user key. Every cipher gets its own cipher key.
    func encrypt(_ views: [CipherView]) async throws -> [Cipher] {
        try await vault().ciphers().encryptList(cipherViews: views).map(\.cipher)
    }
}

/// Ciphers that fail to decrypt for a client of `makeInitializedClient`: they are encrypted for
/// another account, so their cipher keys are wrapped with a user key that client does not have.
func foreignCiphers(_ count: Int) async throws -> [Cipher] {
    let client = try await makeV2InitializedClient(stateBridge: InMemoryStateBridge())
    return try await client.encrypt((0..<count).map { loginView($0, name: "Foreign login \($0)") })
}
