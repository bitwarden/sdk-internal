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
        password: Secret<String>,      // Master password (zeroized)
        account_key: String,           // Format: A3-XXXXXX-... (zeroized)
        sign_in_address: String,       // my.1password.com or variant
        device_uuid: String            // Generated fresh per import
    }
         │
         └──> AccountKey::parse(&credentials.account_key)
              Location: crates/bitwarden-importers/src/importers/onepassword/access/account_key.rs
              │
              ├─→ Parse A3 format (34 chars): A3-{6-char-uuid}-{32-char-key}
              ├─→ Extract format, UUID, key portion
              └─→ Derives: HKDF-SHA256(ikm=key, salt=uuid, info="A3")


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 3. CLIENT INITIALIZATION & SIGN-IN ADDRESS VALIDATION                          │
└─────────────────────────────────────────────────────────────────────────────────┘

    SignInAddress::parse(&credentials.sign_in_address)
    Location: crates/bitwarden-importers/src/importers/onepassword/access/sign_in.rs
         │
         ├─→ Validates subdomain as DNS label
         ├─→ Supports domains: 1password.com, 1password.eu, 1password.ca, ent.1password.com
         └─→ Constructs base URL: https://{sign_in_address}/api


    ClientInfo::for_desktop(device_uuid)
    Location: crates/bitwarden-importers/src/importers/onepassword/access/device.rs
         │
         ├─→ Platform-specific client name: "1Password for {platform}"
         ├─→ User-Agent header with version 81210036
         └─→ op-user-agent header with client metadata


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 4. LOGIN FLOW - 4-STEP AUTHENTICATION SEQUENCE                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

    Client::download_all_vaults(&credentials, &two_factor_ui)
    Location: crates/bitwarden-importers/src/importers/onepassword/access/client.rs
         │
         └──> Client::login()
              Location: crates/bitwarden-importers/src/importers/onepassword/access/login.rs
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 1: START SESSION (v3/auth/start)                              │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  start_new_session()                                               │
              │  POST /api/v3/auth/start                                           │
              │  │                                                                 │
              │  ├─→ Body: {                                                       │
              │  │      username,                                                  │
              │  │      methodID: "SRPg-4096",                                    │
              │  │      srp.clientPublicEphemeral (A),                             │
              │  │      secretKey.Format + secretKey.UUID,                         │
              │  │      device_uuid                                                │
              │  │   }                                                             │
              │  │                                                                 │
              │  └─→ Response cases:                                               │
              │      ├─ "ok"                    → Continue to Step 2 (SRP)         │
              │      ├─ "device-not-registered" → Register at v1/device           │
              │      │  └─→ POST /api/v1/device (ClientInfo + device_uuid)        │
              │      │  └─→ Retry Step 1                                          │
              │      └─ "device-deleted"       → Reauthorize at v1/device/{uuid} │
              │         └─→ PUT /api/v1/device/{uuid}/reauthorize                │
              │         └─→ Retry Step 1                                          │
              │      (Max 2 device ops before failure)                            │
              │                                                                     │
              │  Returns: SessionID + SrpInfo (server ephemeral B)                │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 2: SRP KEY EXCHANGE & VERIFICATION (v2/auth)                  │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  srp::perform_and_verify()                                         │
              │  Location: .../onepassword/access/srp.rs                           │
              │  │                                                                 │
              │  ├─→ SRP-4096 Implementation:                                      │
              │  │   ├─ Algorithm: RFC 3526 4096-bit prime                        │
              │  │   ├─ Client secret: a (random)                                 │
              │  │   ├─ Client ephemeral: A = g^a mod N                           │
              │  │   ├─ Server ephemeral: B (from Step 1)                         │
              │  │   ├─ Shared secret computation:                                │
              │  │   │  └─ K = PBKDF2(password + accountKey.Hash, ...)            │
              │  │   ├─ Proof: M = H(A, B, K)                                     │
              │  │   └─ Session key derivation:                                   │
              │  │      └─ SK = HMAC-SHA256(K, "SESSION")                         │
              │  │                                                                 │
              │  ├─→ KDF Selection:                                               │
              │  │   ├─ "PBES2g-HS256" (Modern):                                  │
              │  │   │  └─ K = PBKDF2-HMAC-SHA256(password, server_salt, iter)   │
              │  │   │     + HKDF(accountKey.Hash)                                │
              │  │   └─ "PBES2-HS256" (Legacy):                                   │
              │  │      └─ K = PBKDF2-HMAC-SHA256(password, uuid, iter)           │
              │  │        + accountKey.Hash                                        │
              │  │                                                                 │
              │  └─→ POST /api/v2/auth                                            │
              │      ├─ Header: x-agilebits-session-id: {SessionID}              │
              │      └─ Body: {                                                   │
              │            username,                                              │
              │            clientProof: base64(M),                                │
              │            methodID: "SRPg-4096"                                 │
              │         }                                                         │
              │                                                                     │
              │  Returns: SessionKey (AES-256, derived from K)                    │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              ├─────────────────────────────────────────────────────────────────────┐
              │ STEP 3: VERIFY SESSION KEY (v2/auth/complete)                      │
              ├─────────────────────────────────────────────────────────────────────┤
              │                                                                     │
              │  verify_session_key()                                              │
              │  POST /api/v2/auth/complete                                        │
              │  │                                                                 │
              │  ├─→ Prepare request (MAC-signed + AES-GCM encrypted):            │
              │  │   ├─ Compute HMAC:                                             │
              │  │   │  └─ mac::sign_request(                                     │
              │  │   │      body=ClientInfo,                                      │
              │  │   │      path="/api/v2/auth/complete",                         │
              │  │   │      session_key)                                          │
              │  │   │      Location: .../onepassword/access/mac.rs               │
              │  │   │      └─ HMAC-SHA256(sessionKey, "${path}${body_bytes}")    │
              │  │   │                                                             │
              │  │   └─ Encrypt ClientInfo with SessionKey (AES-GCM)              │
              │  │                                                                 │
              │  ├─→ Headers:                                                      │
              │  │   ├─ x-agilebits-session-id: {SessionID}                       │
              │  │   └─ x-agilebits-mac: {HMAC}                                   │
              │  │                                                                 │
              │  └─→ Response: MfaInfo (2FA required status)                      │
              │      ├─ If 2FA enabled: list of available methods                │
              │      └─ If 2FA disabled: ready for vault unlock                   │
              │                                                                     │
              └─────────────────────────────────────────────────────────────────────┘
              │
              └─────────────────────────────────────────────────────────────────────┐
                │ STEP 4: TWO-FACTOR AUTHENTICATION (if needed)                    │
                ├─────────────────────────────────────────────────────────────────┤
                │                                                                 │
                │  IF mfa_required:                                               │
                │  │                                                              │
                │  └──> perform_second_factor_authentication()                    │
                │       Location: .../onepassword/access/two_factor.rs            │
                │       │                                                          │
                │       ├─→ TwoFactorUi::provide_totp(attempt: u32)                │
                │       │   Callback trait for 2FA method selection                │
                │       │   Returns: TotpResult::Code(String) or ::Cancel         │
                │       │                                                          │
                │       ├─→ Loop (max 3 attempts):                                │
                │       │   POST /api/v1/auth/mfa                                 │
                │       │   │                                                      │
                │       │   ├─→ Headers:                                           │
                │       │   │   ├─ x-agilebits-session-id: {SessionID}            │
                │       │   │   └─ x-agilebits-mac: {HMAC}                        │
                │       │   │                                                      │
                │       │   ├─→ Body (encrypted): {                               │
                │       │   │      method: "totp",                                │
                │       │   │      code: user_input                               │
                │       │   │   }                                                 │
                │       │   │                                                      │
                │       │   └─→ Response:                                         │
                │       │       ├─ Success          → Session complete            │
                │       │       ├─ BadOtp           → Retry from Step 1           │
                │       │       └─ Error/UserCancel → Abort                       │
                │       │                                                          │
                │       └─→ Note: Only TOTP supported currently                   │
                │           (WebAuthn/Duo not yet implemented)                     │
                │                                                                 │
                └─────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 5. UNLOCK VAULT KEYSETS & DECRYPT VAULT KEYS                                   │
└─────────────────────────────────────────────────────────────────────────────────┘

    unlock() - After login succeeds
    │
    ├─→ GET /api/v1/account
    │   ├─ Headers: x-agilebits-session-id, x-agilebits-mac
    │   └─ Response: Encrypted account info, vault list, keysets
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
    │   └─→ kdf::derive_key()
    │       Location: .../onepassword/access/kdf.rs
    │       ├─ KDF method: PBES2g-HS256 or PBES2-HS256
    │       ├─ Input: password + accountKey.Hash + server_salt
    │       ├─ PBKDF2-HMAC-SHA256(password, salt, iterations) → K1
    │       ├─ HKDF-SHA256(K1, accountKey.Hash) → K2
    │       └─ Uses K2 to decrypt master key from keyset
    │
    └─→ For each vault keyset:
        │
        └──> Keychain::decrypt_aes_key(vault_keyset)
             │
             ├─→ Find RSA private key in keysets
             ├─→ rsa::decrypt_key()
             │   Location: .../onepassword/access/rsa.rs
             │   └─ RSA-OAEP with SHA-1 or SHA-256
             │
             └─→ Decrypt AES-256 key for vault (from RSA envelope)


┌─────────────────────────────────────────────────────────────────────────────────┐
│ 6. DOWNLOAD VAULT ITEMS (PAGINATED)                                            │
└─────────────────────────────────────────────────────────────────────────────────┘

    For each vault:
    │
    └──> download_vault_items(vault_id, aes_key)
         │
         └─→ Cursor-based pagination loop:
             │
             ├─→ GET /api/v1/vault/{vault_id}/{batch_id}/items
             │   ├─ Headers: x-agilebits-session-id, x-agilebits-mac
             │   └─ Query: ?pageSize=500 (configurable)
             │
             ├─→ For each item in response:
             │   │
             │   ├─→ Decrypt encOverview (AES-GCM):
             │   │   ├─ Title, tags, websites
             │   │   └─ opdata::decrypt()
             │   │
             │   └─→ Decrypt encDetails (AES-GCM):
             │       ├─ Fields, sections, passwords
             │       └─ opdata::decrypt()
             │       Location: .../onepassword/access/opdata.rs
             │
             ├─→ Parse ItemCategory:
             │   ├─ Location: .../onepassword/access/model.rs
             │   ├─ Supported: Login, CreditCard, SecureNote, Identity,
             │   │            Password, and 16 others
             │   └─ Unsupported types are logged and skipped
             │
             └─→ Continue until: batchComplete = true
                 (No more items in current batch)


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
            overview: {
                title,
                tags,
                websites,
                ...
            },
            details: {
                fields: Vec<Field>,
                sections: Vec<Section>,
                ...
            }
        }
```

---

## HTTP Transport & Security

All HTTP communication after Step 1:

```
┌─ RestClient (Built on reqwest::Client)
│  Location: .../onepassword/access/rest.rs
│
├─ Headers Added to All Requests:
│  ├─ x-agilebits-client:    {ClientInfo}
│  ├─ user-agent:            "1Password/{version} ..."
│  └─ op-user-agent:         {metadata}
│
├─ Session Header (Steps 2-4):
│  └─ x-agilebits-session-id: {SessionID}
│
├─ MAC Signing Header (Steps 3-6):
│  ├─ x-agilebits-mac:       {HMAC-SHA256}
│  └─ Computed over:         {endpoint_path}{body_json}
│      Using:                {SessionKey}
│
├─ Encryption (Steps 3-6):
│  ├─ AES-256-GCM
│  ├─ Key:       SessionKey (derived during SRP)
│  └─ For:       Request/response bodies
│
└─ Base URL: https://{sign_in_address}/api
   Example: https://my.1password.com/api
```

---

## Error Handling & Recovery

```
Error::BadCredentials (server code 102)
├─ Invalid username/password/Secret Key
└─ No retry

Error::DeviceNotRegistered
├─ Trigger: Step 1 returns "device-not-registered"
├─ Recovery: POST /api/v1/device, retry Step 1
└─ Max attempts: 2

Error::DeviceDeleted
├─ Trigger: Step 1 returns "device-deleted"
├─ Recovery: PUT /api/v1/device/{uuid}/reauthorize, retry Step 1
└─ Max attempts: 2

Error::TwoFactorFailed
├─ Trigger: Wrong TOTP code or user cancellation
├─ Recovery: Restart full login from Step 1
└─ Max attempts: 3 per login

Error::Decryption
├─ Trigger: Cannot decrypt vault data
└─ Result: Import aborts for entire vault

Error::Parse
├─ Trigger: Server response invalid JSON
└─ Result: Network failure or server error

Error::Unsupported
├─ Trigger: Unknown 2FA method, item type, or auth algorithm
└─ Result: Feature not yet implemented
```

---

## Credential Security

```
Secret<String> Types (Zeroized on Drop):
├─ credentials.password    → Master password
└─ credentials.account_key → Secret Key (A3-...)

Other Sensitive Data:
├─ SessionKey    → In memory during session, not persisted
├─ AccountKey.derived_hash → Computed fresh per login
├─ Vault items → Decrypted in memory (not zeroed after)
└─ SRP private key (a) → Ephemeral, not persisted

Persistence:
├─ Device UUID → Must persist between calls (tied to this device)
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
    two_factor_ui: &impl TwoFactorUi,
) -> Result<Vec<Vault>>

// Account Key parsing
pub fn parse(account_key: &str) -> Result<AccountKey>

// Login (internal)
async fn login(&mut self, ...) -> Result<()>

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

pub enum Result<T> {
    Ok(T),
    Err(Error),
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
├── sign_in.rs                  # SignInAddress parsing
├── account_key.rs              # AccountKey parsing & HKDF
├── device.rs                   # ClientInfo & device registration
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
