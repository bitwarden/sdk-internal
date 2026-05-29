# Managed Settings — design notes

This crate (`bitwarden-managed-settings`) owns *resolution* of IT-administrator-forced
configuration. Clients (desktop, browser extension, mobile, CLI; **not** web vault) own
*acquisition* — talking to the OS-mediated policy channel — and *presentation* — disabling
controls in the UI, surfacing org-of-record diagnostics. The SDK is the single source of
truth for which value wins.

## Naming

The crate is called `bitwarden-managed-settings`. We did not call it `device-management`
because clients already use that term for the trusted-device-management flow
(`TDE` / trusted-device encryption). `managed_settings()` is the accessor on
`bitwarden_core::Client` and on `bitwarden_pm::PasswordManagerClient`.

## Architectural pattern: hybrid C1 + C3

Two patterns from the existing SDK were considered:

* **C1** — a small stateless `ClientExt` (e.g. `PoliciesClientExt::policies()` on
  `bitwarden-core::Client`, see `crates/bitwarden-policies/src/policy_client.rs:67-77`).
  Clean separation, fits FFI bindings well.
* **C3** — a feature crate that defines a cross-crate trait that other feature crates
  implement for their *own* types (e.g. how `bitwarden-policies` defines
  `PolicyType` and lets per-domain crates wire it in).

We use **both**. C1 gives us the small handle (`ManagedSettingsClient` returned by
`ManagedSettingsClientExt::managed_settings`) that we expose over WASM/UniFFI. C3 gives
us `ApplyManagedOverride`, the trait implemented in `bitwarden-generators` (and any
future feature crate) for its `*Request` structs, mapping dotted keys onto fields.

The dependency direction is `bitwarden-generators → bitwarden-managed-settings`, never
the reverse. `bitwarden-managed-settings` does not know anything about generators; it
exposes the profile and the trait.

## Trust model: no `locked`, no `recommended`

A `ManagementProfile` is a flat `HashMap<String, String>` plus diagnostic metadata
(`version`, `source`, `fetched_at`). There is **no** `locked: bool` flag and there is
**no** `recommended` tier.

Every supported acquisition source is OS-mediated and writable only by root/admin:

| Source                       | Channel                                                          | Writable by             |
| ---------------------------- | ---------------------------------------------------------------- | ----------------------- |
| `MdmApple`                   | Apple managed app configuration (`NSUserDefaults`)               | Apple MDM / device admin |
| `MdmAndroid`                 | Android `RestrictionsManager`                                    | Android device admin    |
| `PolicyWindows`              | `HKLM\SOFTWARE\Policies\Bitwarden`                               | Local administrators    |
| `PolicyLinux`                | `/etc/bitwarden/policies` (root-owned)                           | root                    |
| `ExtensionManagedStorage`    | Chromium `chrome.storage.managed` (extension policies JSON)      | Local administrators    |

The host OS is what gives us the guarantee, not the SDK. **Presence of a key in the
profile *is* the lock.** There is nothing for the user to override, so we don't carry
the flag.

Likewise, no `recommended` tier: a recommended-only value is indistinguishable from no
policy at all from the SDK's perspective, and surfacing it would be presentation
logic, which belongs in the client UI, not the SDK.

## Precedence

When resolving a setting:

```
managed > org-policy > user-set > sdk-default
```

`ApplyManagedOverride::apply_managed_override` is called **after** any existing policy
overrides (such as the `PasswordGeneratorPolicy` mapping in
`bitwarden-generators`) and **before** generation/validation. Anything the admin
specifies wins.

## JSON-string value rationale

`ManagementProfile.settings` is `HashMap<String, String>`, where the value is a
JSON-encoded fragment (e.g. `"20"`, `"true"`, `"\"a-string\""`). It is **not**
`HashMap<String, serde_json::Value>`.

`serde_json::Value` has no UniFFI representation: UniFFI does not know how to lower
an arbitrary recursive enum across the FFI boundary. Defining a parallel `BwValue`
enum would force every binding language to reimplement JSON, which is busywork that
adds no value over "this is a JSON string." The string-encoded form crosses UniFFI and
WASM identically, and `ManagementProfile::get_as<T>` does typed decoding on demand.

## Push (prototype) vs pull-provider (production)

The prototype API is **push**:

```rust
client.managed_settings().update_profile(Some(profile));
```

The host fetches the profile from its OS channel and pushes it into the SDK. A
process-global `RwLock<Option<ManagementProfile>>` (see `store.rs`) holds the active
profile.

The production design is a **pull provider trait** injected at PM-builder time, mirroring
`bitwarden-server-communication-config`'s `CookieProvider`
(see `crates/bitwarden-server-communication-config/src/cookie_provider.rs:13-32`):

```rust
#[async_trait::async_trait]
pub trait ManagementProfileProvider: Send + Sync + 'static {
    async fn current(&self) -> Option<ManagementProfile>;
}

PasswordManagerClient::builder()
    .with_management_profile_provider(Arc::new(MyHostProvider))
    .build();
```

The provider is held in an `Arc` inside the builder; the `ManagedSettingsClient` reads
it on demand instead of consulting a global. The public surface
(`is_managed`, `get`, `current_profile`) does not change, so swapping push for pull
is non-breaking for clients.

We use push here because the WASM and UniFFI bindings should be a plain struct +
methods, not an async trait with a host-implemented dyn callback. That second piece is
non-trivial across both binding generators, and the prototype's job is to prove the
override path, not the IPC plumbing.

## Per-platform client acquisition summary

The SDK does not vary behavior by source, but for completeness:

* **Apple (iOS, macOS):** `UserDefaults.standard.dictionary(forKey: "com.apple.configuration.managed")`
  yields the MDM-delivered config blob. Map known keys to `settings`, tag
  `source: MdmApple`, push.
* **Android:** `RestrictionsManager.getApplicationRestrictions()` returns a `Bundle`.
  Translate known keys, tag `source: MdmAndroid`.
* **Windows desktop:** read `HKLM\SOFTWARE\Policies\Bitwarden` (registry); each value
  becomes a dotted key. Tag `source: PolicyWindows`.
* **Linux desktop:** read JSON files under `/etc/bitwarden/policies/` (or the
  distro-conventional system-policy path). Tag `source: PolicyLinux`.
* **Browser extension (Chromium):** `chrome.storage.managed.get()` returns the
  policy JSON deployed by the admin (Group Policy on Windows, plist on macOS,
  `/etc/chromium/policies/managed/*.json` on Linux). Tag
  `source: ExtensionManagedStorage`.
* **Web vault:** out of scope. The web vault has no OS context to read from; admin
  configuration there continues to go through the existing organization-policy
  mechanism.

## Vignette: password generator

Milestone 2 wires `ApplyManagedOverride` into `PasswordGeneratorRequest` and
`PassphraseGeneratorRequest`. Supported dotted keys:

| Key                                | Type | Target field                  | Clamp                           |
| ---------------------------------- | ---- | ----------------------------- | ------------------------------- |
| `generator.password.length`        | u8   | `length`                      | `[MINIMUM_PASSWORD_LENGTH, MAXIMUM_PASSWORD_LENGTH]` |
| `generator.password.uppercase`     | bool | `uppercase`                   | —                               |
| `generator.password.lowercase`     | bool | `lowercase`                   | —                               |
| `generator.password.numbers`       | bool | `numbers`                     | —                               |
| `generator.password.special`       | bool | `special`                     | —                               |
| `generator.password.minUppercase`  | u8   | `min_uppercase`               | `[0, 9]`                        |
| `generator.password.minLowercase`  | u8   | `min_lowercase`               | `[0, 9]`                        |
| `generator.password.minNumber`     | u8   | `min_number`                  | `[0, 9]`                        |
| `generator.password.minSpecial`    | u8   | `min_special`                 | `[0, 9]`                        |
| `generator.password.avoidAmbiguous`| bool | `avoid_ambiguous`             | —                               |
| `generator.passphrase.numWords`    | u8   | `num_words`                   | `[MINIMUM_PASSPHRASE_NUM_WORDS, MAXIMUM_PASSPHRASE_NUM_WORDS]` |
| `generator.passphrase.wordSeparator` | String | `word_separator`           | non-empty                       |
| `generator.passphrase.capitalize`  | bool | `capitalize`                  | —                               |
| `generator.passphrase.includeNumber` | bool | `include_number`            | —                               |

The trait implementation is in `bitwarden-generators`. `GeneratorClient::password` and
`GeneratorClient::passphrase` consult `client.managed_settings().current_profile()`
and call `apply_managed_override` before delegating to the existing generation
function.

## Open prototype caveats

* `store.rs` uses a process-global `RwLock`. Acceptable per the trust model (every
  `Client` in a process is bound by the same OS-mediated policy). Documented in
  `store.rs` and replaced by an injected provider in production.
* No `unwrap_used` in production paths. Tests use `unwrap_or_else(into_inner)` for
  the `Mutex` that serializes the global-store tests; this is intentional, only in
  `#[cfg(test)]` code, and the deny-list does not apply to test code that explicitly
  recovers from poison.
* Error type is intentionally minimal (`ManagedSettingsError::Decode`). A real
  implementation would add `BadShape`, `OutOfRange`, etc. once we have downstream
  consumers that need to discriminate.
