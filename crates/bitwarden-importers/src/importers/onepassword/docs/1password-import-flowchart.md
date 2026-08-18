# 1Password Import Flow - Function Call Diagram

## Overview: Complete Call Chain

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 1. CLIENT CREATION                                                              │
└─────────────────────────────────────────────────────────────────────────────────┘

    Client::new(http_client: reqwest::Client)
         │
         └──> Creates: Client { http }
              Location: crates/bitwarden-importers/src/importers/onepassword/access/client.rs


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 2. PREPARE CREDENTIALS                                                          │
└─────────────────────────────────────────────────────────────────────────────────┘

    Credentials {
        username: String,              // Email
        password: String,              // Master password (zeroized on drop)
        account_key: String,           // Format: A3-XXXXXX-... (zeroized on drop)
        sign_in_address: SignInAddress, // my.1password.com or variant
        device_uuid: String            // Generated fresh per import
    }
         │
         └──> AccountKey::parse(&credentials.account_key)   // first line of download_all_vaults
              Location: crates/bitwarden-importers/src/importers/onepassword/access/account_key.rs
              │
              ├─→ Parse A3 format (34 chars): 2 format + 6 uuid + 26 key
              ├─→ Extract format, UUID, key portion
              └─→ hash(): HKDF-SHA256(ikm=key, salt=uuid, info=format)


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 3. CLIENT INITIALIZATION & SIGN-IN ADDRESS VALIDATION                           │
└─────────────────────────────────────────────────────────────────────────────────┘

    SignInAddress::new(subdomain, SignInDomain)   // built by the caller, before Credentials
    Location: crates/bitwarden-importers/src/importers/onepassword/access/sign_in.rs
         │
         ├─→ Validates subdomain as DNS label
         └─→ Supports domains: 1password.com, 1password.eu, 1password.ca, ent.1password.com

    Base URL https://{sign_in_address}/api is assembled in Client::login (client.rs)


    ClientInfo::for_desktop(device_uuid)
    Location: crates/bitwarden-importers/src/importers/onepassword/access/device.rs
         │
         ├─→ Platform-specific client name: "1Password for {platform}"
         ├─→ User-Agent header with version 81210036
         └─→ op-user-agent header with client metadata


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 4. LOGIN FLOW - 4-STEP AUTHENTICATION SEQUENCE                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

    Client::download_all_vaults(&credentials, ui)
    Location: crates/bitwarden-importers/src/importers/onepassword/access/client.rs
         │
         └──> Client::login()
              Location: crates/bitwarden-importers/src/importers/onepassword/access/login.rs
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 1: START SESSION (v3/auth/start)                               │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  start_new_session()                                                │
              │  POST /api/v3/auth/start                                            │
              │  │                                                                  │
              │  ├─→ Body: {                                                        │
              │  │      email,                                                      │
              │  │      skformat: accountKey.format,                                │
              │  │      skid: accountKey.uuid,                                      │
              │  │      deviceUuid                                                  │
              │  │   }                                                              │
              │  │                                                                  │
              │  └─→ Response cases:                                                │
              │      ├─ "ok"                    → Continue to Step 2 (SRP)          │
              │      ├─ "device-not-registered" → Register at v1/device             │
              │      │  └─→ POST /api/v1/device (ClientInfo::device_body())         │
              │      │  └─→ Retry Step 1                                            │
              │      └─ "device-deleted"       → Reauthorize at v1/device/{uuid}    │
              │         └─→ PUT /api/v1/device/{uuid}/reauthorize                   │
              │         └─→ Retry Step 1                                            │
              │      (Max 2 device ops before failure)                              │
              │                                                                     │
              │  Returns: SessionID + SrpInfo                                       │
              │           SrpInfo = {srp_method, key_method, iterations, salt}      │
              │           The server ephemeral B arrives in Step 2, not here.       │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 2: SRP KEY EXCHANGE (v2/auth, v2/auth/confirm-key)             │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  srp::perform_and_verify()                                          │
              │  Location: .../onepassword/access/srp.rs                            │
              │  │                                                                  │
              │  ├─→ SRP-4096 group:                                                │
              │  │   ├─ N: RFC 3526 4096-bit prime                                  │
              │  │   └─ g: 5                                                        │
              │  │                                                                  │
              │  ├─→ Private value x (compute_x):                                   │
              │  │   ├─ k1 = HKDF-SHA256(ikm=salt, salt=lower(trim(email)),         │
              │  │   │                   info="SRPg-4096")                          │
              │  │   ├─ k2 = PBKDF2-HMAC-SHA256(nfkd(trim(password)), k1, iters)    │
              │  │   └─ x  = accountKey.hash() XOR k2                               │
              │  │                                                                  │
              │  ├─→ Ephemeral exchange:                                            │
              │  │   ├─ a = random 256-bit                                          │
              │  │   ├─ A = g^a mod N                                               │
              │  │   ├─ POST /api/v2/auth                                           │
              │  │   │    Header: x-agilebits-session-id: {SessionID}               │
              │  │   │    Body:   { userA: hex(A) }                                 │
              │  │   │    Response: { userB: hex(B) }                               │
              │  │   └─ Reject B ≡ 0 or 1 (mod N)                                   │
              │  │                                                                  │
              │  ├─→ Shared key:                                                    │
              │  │   ├─ u = SHA256(A ‖ B)                                           │
              │  │   ├─ k = SHA256(N ‖ g)                                           │
              │  │   └─ K = SHA256(hex((B - k*g^x)^(a + u*x) mod N))                │
              │  │                                                                  │
              │  └─→ POST /api/v2/auth/confirm-key                                  │
              │      ├─ Body: { clientVerifyHash }                                  │
              │      └─ Checks the server's serverVerifyHash.                       │
              │         The only step that authenticates the server.                │
              │                                                                     │
              │  Returns: SessionKey = AesKey { id: SessionID, key: K }             │
              │           The session id labels the key; it is not a KDF input.     │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 3: COMPLETE AUTHENTICATION (v2/auth/complete)                  │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  verify_session_key()                                               │
              │  POST /api/v2/auth/complete                                         │
              │  │                                                                  │
              │  ├─→ Prepare request (MAC-signed + AES-GCM encrypted):              │
              │  │   ├─ MacSigner::sign(url, method)                                │
              │  │   │    Location: .../onepassword/access/mac.rs                   │
              │  │   │    ├─ salt    = HMAC-SHA256(sessionKey, SESSION_HMAC_SECRET) │
              │  │   │    ├─ message = "{sessionId}|{METHOD}|                       │
              │  │   │    │             {host}/{path}?{query}|v1|{requestId}"       │
              │  │   │    └─ header  = "v1|{requestId}|                             │
              │  │   │                  b64url(HMAC-SHA256(salt, message)[..12])"   │
              │  │   │    The request body is NOT part of the MAC.                  │
              │  │   │    requestId starts random and increments per request.       │
              │  │   │                                                              │
              │  │   └─ Encrypt { client, device } with SessionKey (AES-GCM)        │
              │  │                                                                  │
              │  ├─→ Headers:                                                       │
              │  │   ├─ x-agilebits-session-id: {SessionID}                         │
              │  │   └─ x-agilebits-mac: {HMAC}                                     │
              │  │                                                                  │
              │  └─→ Response: MfaInfo (2FA required status)                        │
              │      ├─ If 2FA enabled: list of available methods                   │
              │      └─ If 2FA disabled: ready for vault unlock                     │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              └─────────────────────────────────────────────────────────────────────┐
                │ STEP 4: TWO-FACTOR AUTHENTICATION (if needed)                     │
                ├───────────────────────────────────────────────────────────────────┤
                │                                                                   │
                │  IF mfa_required:                                                 │
                │  │                                                                │
                │  └──> perform_second_factor_authentication()                      │
                │       Location: .../onepassword/access/two_factor.rs              │
                │       │                                                           │
                │       ├─→ TwoFactorUi::provide_totp(attempt: u32)                 │
                │       │   Callback that supplies a passcode (no method choice)    │
                │       │   Returns: TotpResult::Code(String) or ::Cancel           │
                │       │   Prompted exactly once per login attempt.                │
                │       │                                                           │
                │       ├─→ POST /api/v1/auth/mfa                                   │
                │       │   │                                                       │
                │       │   ├─→ Headers:                                            │
                │       │   │   ├─ x-agilebits-session-id: {SessionID}              │
                │       │   │   └─ x-agilebits-mac: {HMAC}                          │
                │       │   │                                                       │
                │       │   ├─→ Body (encrypted): {                                 │
                │       │   │      sessionID,                                       │
                │       │   │      client,                                          │
                │       │   │      totp: { code }                                   │
                │       │   │   }                                                   │
                │       │   │                                                       │
                │       │   └─→ Response:                                           │
                │       │       ├─ Success          → Session complete              │
                │       │       ├─ BadOtp           → Retry from Step 1             │
                │       │       └─ Error/UserCancel → Abort                         │
                │       │                                                           │
                │       │   The max-3-attempts loop lives in Client::login          │
                │       │   (client.rs) and restarts the whole login.               │
                │       │                                                           │
                │       └─→ Note: Only TOTP supported currently                     │
                │           (WebAuthn/Duo not yet implemented)                      │
                │                                                                   │
                └───────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 5. UNLOCK VAULT KEYSETS & DECRYPT VAULT KEYS                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

    unlock() - After login succeeds
    Location: .../onepassword/access/client.rs
    │
    ├─→ GET /api/v1/account?attrs=billing,counts,groups,invite,me,settings,
    │                            tier,user-flags,users,vaults
    │   ├─ Headers: x-agilebits-session-id, x-agilebits-mac
    │   └─ Response: Encrypted account info and the vault list
    │   └─ Decrypted with: AES-GCM(SessionKey)
    │      Location: .../onepassword/access/opdata.rs
    │
    ├─→ GET /api/v1/account/keysets
    │   ├─ Headers: x-agilebits-session-id, x-agilebits-mac
    │   └─ Response: Encrypted master key material
    │
    ├─→ Keychain::decrypt_keysets()
    │   Location: .../onepassword/access/keychain.rs
    │   │
    │   ├─→ kdf::derive_master_key()
    │   │   Location: .../onepassword/access/kdf.rs
    │   │   ├─ KDF method: PBES2g-HS256 (modern) or PBES2-HS256 (legacy)
    │   │   ├─ k1 = HKDF-SHA256(ikm=salt, salt=lower(trim(email)), info=alg)
    │   │   │       (legacy skips the HKDF and uses the raw server salt)
    │   │   ├─ k2 = PBKDF2-HMAC-SHA256(nfkd(trim(password)), k1, iterations)
    │   │   │       (legacy substitutes "email:b64(SHA256(password))")
    │   │   └─ master key = accountKey.hash() XOR k2
    │   │      This IS the master key, kid "mp". It seeds the keychain as root.
    │   │
    │   └─→ decryption_order(): BFS over the encryptedBy graph from "mp",
    │       so every keyset is decrypted after the one that encrypts it.
    │       Keysets the root cannot reach are left out.
    │
    └─→ For each vault in the account info:
        │
        ├──> find_working_key(vault.access, keychain)   // client.rs
        │    ├─→ First access entry with the read bit (acl & 32)
        │    └─→ ...whose kid the keychain already holds
        │        None = a vault the account can see but not open (skipped)
        │
        └──> Keychain::decrypt_aes_key(enc_vault_key)
             │
             └─→ Keychain::decrypt() dispatches on the envelope scheme:
                 ├─ "A256GCM"                  → AesKey::decrypt  (opdata.rs)
                 └─ "RSA-OAEP" / "RSA-OAEP-256" → RsaKey::decrypt (rsa.rs)
                    └─ RSA-OAEP with SHA-1 or SHA-256


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 6. DOWNLOAD VAULT ITEMS (PAGINATED)                                             │
└─────────────────────────────────────────────────────────────────────────────────┘

    For each vault:
    │
    └──> download_vault_items(vault_id, keychain, session)
         │
         └─→ Cursor-based pagination loop (batch_id starts at 0):
             │
             ├─→ GET /api/v1/vault/{vault_id}/{batch_id}/items
             │   └─ Headers: x-agilebits-session-id, x-agilebits-mac
             │
             ├─→ For each item in response:
             │   │
             │   ├─→ Skip it when trashed == "Y"
             │   │
             │   ├─→ Decrypt encOverview:
             │   │   ├─ title, ainfo, url, urls, tags
             │   │   └─ Keychain::decrypt_json()
             │   │
             │   └─→ Decrypt encDetails:
             │       ├─ note, fields, sections, password,
             │       │  password_history
             │       │  (a Password-category item carries `password`
             │       │   and no `fields`)
             │       └─ Keychain::decrypt_json()
             │       Location: .../onepassword/access/keychain.rs
             │
             ├─→ Parse ItemCategory:
             │   ├─ Location: .../onepassword/access/model.rs
             │   ├─ Known: Login, CreditCard, SecureNote, Identity,
             │   │         Password, and 16 others
             │   └─ An unknown template id is kept as Unknown(String)
             │
             └─→ Continue until: batchComplete = true
                 ├─ batch_id advances to the response's contentVersion
                 └─ A cursor that does not advance is an error, not a loop


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 7. RETURN RESULT                                                                │
└─────────────────────────────────────────────────────────────────────────────────┘

    Result: Vec<Vault>
    │
    ├─→ Each Vault {
    │       id,
    │       name,
    │       description,
    │       items: Vec<Item>
    │   }
    │
    └─→ Each Item {
            id,
            category: ItemCategory,
            overview: VaultItemOverview {
                title,
                ainfo,              // subtitle line
                url,
                urls: Vec<VaultItemUrl>,
                tags,
            },
            details: VaultItemDetails {
                note,               // notesPlain on the wire
                fields,
                sections,
                password,           // the secret of a Password-category
                                    // item, which carries no fields
                password_history,
            }
        }
```

---

## HTTP Transport & Security

```
┌─ RestClient (Built on reqwest::Client)
│  Location: .../onepassword/access/rest.rs
│
├─ Headers Added to Every Request (Step 1 included):
│  ├─ x-agilebits-client:    {ClientInfo}
│  ├─ user-agent:            "1Password for {platform}/{version}"
│  └─ op-user-agent:         {metadata}
│
├─ Session Header (from the moment a session id exists,
│                  device registration in Step 1 onwards):
│  └─ x-agilebits-session-id: {SessionID}
│
├─ MAC Signing Header (Steps 3-6):
│  ├─ x-agilebits-mac:       "v1|{requestId}|{b64url(hmac[..12])}"
│  ├─ salt:                  HMAC-SHA256(SessionKey, SESSION_HMAC_SECRET)
│  └─ Computed over:         "{sessionId}|{METHOD}|
│                             {host}/{path}?{query}|v1|{requestId}"
│                            The request body is NOT signed.
│
├─ Encryption (Steps 3-6):
│  ├─ AES-256-GCM
│  ├─ Key:       SessionKey (the SRP shared key K)
│  └─ For:       Request/response bodies
│
└─ Base URL: https://{sign_in_address}/api
   Example: https://my.1password.com/api
```

---

## Error Handling & Recovery

All variants belong to `OnePasswordError` (error.rs).

```
OnePasswordError::BadCredentials (server code 102)
├─ Invalid username/password/Secret Key
└─ No retry

Device registration / reauthorization
├─ Trigger: Step 1 returns "device-not-registered" or "device-deleted"
├─ Recovery: POST /api/v1/device, or
│            PUT /api/v1/device/{uuid}/reauthorize, then retry Step 1
├─ Max attempts: 2
├─ A failing device call propagates whatever the transport layer produced:
│  Network, Parse, BadCredentials (102), or NotFound (117)
└─ Internal covers only: the status repeating past the attempt limit,
   an unrecognized server error code, or a response with success != 1
   (there are no DeviceNotRegistered / DeviceDeleted variants)

OnePasswordError::TwoFactorFailed
├─ Trigger: Wrong TOTP code or user cancellation
├─ Recovery: Restart full login from Step 1
└─ Max attempts: 3 per login

OnePasswordError::Decryption
├─ Trigger: An RSA-OAEP failure in RsaKey::decrypt. This is its only
│           production construction.
└─ Result: Aborts the entire import, not just the offending vault

AES-GCM failures do NOT produce Decryption
├─ Trigger: A bad key, IV, or auth tag on an account, response, or item
│           payload (opdata::decrypt)
└─ Result: OnePasswordError::Internal, and it aborts the whole import too

OnePasswordError::Parse
└─ Trigger: A server response could not be parsed as the expected JSON

OnePasswordError::Network
└─ Trigger: Network or transport failure

OnePasswordError::Unsupported
├─ Trigger: Unknown 2FA method, encryption scheme, or auth algorithm
└─ Result: Feature not yet implemented

OnePasswordError::NotFound (server code 117)
OnePasswordError::TwoFactorRequired  (currently never constructed)
OnePasswordError::Internal           (malformed input, "should not happen")
```

---

## Credential Security

```
Zeroized on Drop (owned buffers, each with a manual Drop impl):
├─ credentials.password    → Master password              (String)
├─ credentials.account_key → Secret Key (A3-...)          (String)
├─ AccountKey.key          → the key portion after parsing (String)
└─ AesKey.key              → session and vault keys        (Vec<u8>)

Other Sensitive Data:
├─ AccountKey.hash() → Computed on demand, never stored
├─ Vault items → Decrypted in memory (not zeroed after)
└─ SRP private key (a) → Ephemeral, not persisted

Persistence:
├─ Device UUID → Generated fresh per import; nothing reuses it afterwards
└─ No tokens saved → Fresh login required each time
```

---

## Key Function Signatures

```rust
// Client creation
pub fn new(http: reqwest::Client) -> Client

// Main entry point
pub async fn download_all_vaults(
    &self,
    credentials: &Credentials,
    ui: &dyn TwoFactorUi,
) -> Result<Vec<Vault>, OnePasswordError>

// Account Key parsing
pub(super) fn parse(input: &str) -> Result<AccountKey, OnePasswordError>

// Login (internal)
async fn login(
    &self,
    credentials: &Credentials,
    account_key: &AccountKey,
    ui: &dyn TwoFactorUi,
) -> Result<Session, OnePasswordError>

// 2FA callback trait (user-implemented)
#[async_trait]
pub trait TwoFactorUi: Send + Sync {
    async fn provide_totp(&self, attempt: u32) -> TotpResult;
}

// Result types
pub enum TotpResult {
    Code(String),
    Cancel,
}
```

---

## Known Limitations & TODOs

- ✅ TOTP 2FA supported
- ❌ WebAuthn / Duo not implemented
- ❌ SSO / service accounts not supported
- ⚠️ Vault data not zeroed after decryption (only secrets are)
- ⚠️ Wrong password reports as Internal error (should be BadCredentials)
- ⚠️ Wire DTOs derive Debug (logs secrets if printed)
- ⚠️ Vaults without keys silently skipped
- ⚠️ Any undecryptable item aborts entire import
- 🔧 Legacy PBES2-HS256 path untested
- 🔧 Need conversion layer to Bitwarden ciphers

---

## Module Layout

```
crates/bitwarden-importers/src/importers/onepassword/access/
├── mod.rs                      # Module exports
├── client.rs                   # Main Client struct & download_all_vaults()
├── credentials.rs              # Credentials struct
├── sign_in.rs                  # SignInAddress construction & validation
├── account_key.rs              # AccountKey parsing & HKDF
├── device.rs                   # ClientInfo & device registration
├── identity.rs                 # The client fingerprint we impersonate
├── login.rs                    # 4-step login orchestration
├── session.rs                  # SessionID management
├── srp.rs                      # SRP-4096 key exchange
├── kdf.rs                      # PBKDF2 & HKDF key derivation
├── keychain.rs                 # Decrypt keysets & vault keys
├── two_factor.rs               # TwoFactorUi trait & TOTP
├── rest.rs                     # HTTP transport (reqwest wrapper)
├── mac.rs                      # HMAC-SHA256 request signing
├── opdata.rs                   # AES-GCM en/decryption
├── rsa.rs                      # RSA-OAEP key decryption
├── model.rs                    # Data models (Vault, Item, etc.)
├── wire.rs                     # Wire protocol DTOs
└── error.rs                    # Error types

```

---
