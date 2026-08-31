# bitwarden-rotation-daemon

Bitwarden PAM credential rotation daemon.

This crate provides the `bw-rotation-daemon` binary. It continuously rotates PAM-managed credentials
by polling the Bitwarden server for claimable rotation jobs, executing each job (resolve credentials
→ generate password → rotate in the target system → verify → write re-encrypted vault cipher →
optionally terminate sessions → report outcome), and then returning to the poll loop.

## Usage

```
bw-rotation-daemon run [--config <PATH>]
```

All daemon settings live in the TOML configuration file (see
[Configuration file](#configuration-file)); they are **not** individual CLI flags.

### Environment variables

| Variable            | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `BWRD_TOKEN`        | Daemon access token (required)                                 |
| `BWRD_CONFIG`       | Path to the TOML configuration file (equivalent to `--config`) |
| `BWRD_API_URL`      | Bitwarden API server URL (overrides the config file)           |
| `BWRD_IDENTITY_URL` | Bitwarden identity server URL (overrides the config file)      |
| `RUST_LOG`          | Log filter directives; default `info` (e.g. `RUST_LOG=debug`)  |

### Flags and options

| Flag / option     | Description                         |
| ----------------- | ----------------------------------- |
| `--config <PATH>` | Path to the TOML configuration file |

### Token security

The daemon token contains the org-key encryption key. It is **never** accepted as a plain `--token`
argument — argv is visible via `ps`/`/proc/<pid>/cmdline`. Supply it via the `BWRD_TOKEN`
environment variable only.

After reading `BWRD_TOKEN` at startup, the daemon removes it from the process environment so that
child processes (e.g. custom scripts) cannot inherit the token value.

### Configuration file

The daemon is configured from a TOML file. Specify the file with `--config <PATH>` or the
`BWRD_CONFIG` environment variable. The server URLs may additionally be overridden with the
`BWRD_API_URL` / `BWRD_IDENTITY_URL` environment variables.

**Precedence** (highest to lowest):

1. `BWRD_API_URL` / `BWRD_IDENTITY_URL` environment variables
2. `[environment].api` / `[environment].identity` in the config file
3. Derived from `[environment].base` as `{base}/api` / `{base}/identity`
4. Error — startup fails with a message naming all three supply methods

The daemon token **cannot** be supplied via the config file. Any config file that contains a `token`
key is rejected at startup. Use `BWRD_TOKEN` only.

#### Example configuration file

```toml
# All fields are optional; omitted fields fall back to built-in defaults.

poll_interval      = 15   # seconds; minimum 15
heartbeat_interval = 30   # seconds; must be < 120
offline_grace      = 60   # seconds
max_retry_attempts = 5    # total attempts per retryable step
retry_base_delay   = 1    # seconds (exponential backoff base)
script_timeout     = 60   # seconds

# script_root = "/opt/scripts"   # uncomment to restrict custom script paths

entra_verify_probe = false   # set true only with MFA exemption for the service principal

[environment]
# Supply a base URL and let the daemon derive /api and /identity automatically:
base     = "https://bitwarden.example.com"
# Or override individual URLs (takes precedence over base-derived values):
# api      = "https://api.bitwarden.com"
# identity = "https://identity.bitwarden.com"
```

### Per-target credential configuration (`[targets]`)

The optional `[targets]` TOML section accepts UUID keys, each configuring per-target credential
overrides. Config-file values take precedence over environment variables **on a per-key basis**; the
environment variable is the fallback for any key not set in the config file.

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/scripts/rotate-thing.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id  = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

#### Accepted keys per target entry

| Key         | Overrides env suffix | Applicable kinds |
| ----------- | -------------------- | ---------------- |
| `script`    | `SCRIPT`             | `CustomScript`   |
| `tenant_id` | `TENANT_ID`          | `Entra`          |
| `client_id` | `CLIENT_ID`          | `Entra`          |

#### `client_secret` is env-only

The `client_secret` key is not accepted in `[targets]` entries. The config file is typically checked
into a repository and must not hold secrets. Supply client secrets via environment variables only
(e.g. `<TARGET_ID_UPPER_UNDERSCORE>_CLIENT_SECRET`). Any `client_secret` key in a `[targets]` entry
is a hard startup error (`deny_unknown_fields`).

#### Missing-key error messages

Missing-key errors always report the **env var name** as the actionable hint, regardless of which
source (config or env) was expected to provide the value.

### Logging

Log output is written to stderr. The log level is controlled by the `RUST_LOG` environment variable
(same syntax as `tracing-subscriber`'s `EnvFilter`):

```sh
RUST_LOG=debug bw-rotation-daemon run --config /etc/bwrd/config.toml
RUST_LOG=bitwarden_rotation_daemon=trace,info bw-rotation-daemon run --config /etc/bwrd/config.toml
```

The default level (`info`) produces one log line per lifecycle milestone; `RUST_LOG=debug` adds
per-tick and per-substep chatter.

#### Operator-visible events at `info` / `warn` / `error`

| Level   | Event                                          | Key fields                                                                 |
| ------- | ---------------------------------------------- | -------------------------------------------------------------------------- |
| `info`  | Daemon starting                                | `api_url`, `identity_url`, `poll_interval_secs`, `heartbeat_interval_secs` |
| `info`  | Session established / renewed                  | `retry` (on renewal)                                                       |
| `info`  | Shutdown signal received                       | —                                                                          |
| `info`  | Rotation job claimed                           | `job_id`, `target_system_name`                                             |
| `info`  | Starting rotation execution                    | `attempt_id`, `job_id`, `cipher_id`, `target_system_name`                  |
| `info`  | Step 1: credentials resolved                   | `attempt_id`                                                               |
| `info`  | Step 2: password generated                     | `attempt_id`                                                               |
| `info`  | Step 3: target rotate succeeded                | `attempt_id`, `kind`                                                       |
| `info`  | Step 4: verify succeeded                       | `attempt_id`                                                               |
| `info`  | Step 5: cipher written                         | `attempt_id`, `cipher_id`                                                  |
| `info`  | Step 6: session termination succeeded          | `attempt_id`                                                               |
| `info`  | Step 7: rotation succeeded and reported        | `attempt_id`, `termination`                                                |
| `info`  | Daemon shut down cleanly                       | —                                                                          |
| `warn`  | Session renewal failed (transient / protocol)  | `retry`, `sleep_ms`                                                        |
| `warn`  | Session entered Revoked phase                  | —                                                                          |
| `warn`  | Rotation failed (any step)                     | `attempt_id`, `failure_code`, `sync_state`, `detail`                       |
| `warn`  | Step 6: session termination aborted / failed   | `attempt_id`, `abort_reason`                                               |
| `warn`  | Transient poll error / backoff                 | backoff duration                                                           |
| `warn`  | Success report rejected/unknown by server      | `attempt_id`                                                               |
| `error` | Daemon credential refused (startup or mid-run) | —                                                                          |
| `error` | Daemon not eligible for rotation endpoints     | —                                                                          |

At `RUST_LOG=debug` the following additional events appear: poll ticks (with claimable job count),
heartbeat ticks, claim-race losses (409 per job), registered integration kinds, cipher-fetch
sub-step, and session-renewal details.

### Exit codes

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| `0`  | Clean shutdown (SIGTERM or Ctrl-C received).                         |
| `1`  | Startup error: invalid configuration, I/O error, or parse failure.   |
| `2`  | Daemon credential refused. An admin must reissue the credential      |
|      | server-side (via `ReissueDaemonCredential`) and restart the daemon   |
|      | with the new token.                                                  |
| `3`  | Daemon not eligible for rotation endpoints. Check: daemon record not |
|      | revoked or disabled, organisation license active, `UsePam` enabled.  |

---

## Per-target credential configuration (`[targets]`)

The optional `[targets]` TOML section lets you supply per-target credentials directly in the config
file, alongside or instead of environment variables. Each key must be a valid UUID (the target
system ID).

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/scripts/rotate-thing.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id  = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

### Per-key precedence (highest to lowest)

1. **Config file** (`[targets.<uuid>]`) — wins unconditionally for any key that is set.
2. **Environment variable** — fallback for any key absent from the config file.

Missing-key errors always report the **env var name** as the actionable hint, regardless of which
source was expected to provide the value.

### Accepted keys per target kind

| Kind              | Accepted config keys                |
| ----------------- | ----------------------------------- |
| `CustomScript`    | `script`                            |
| `Entra`           | `tenant_id`, `client_id`            |
| `ActiveDirectory` | `ldap_host`, `bind_dn`, `base_dn`, `ca_certificate` |

### Secrets are env-only

`client_secret` and `bind_password` are deliberately not accepted in the `[targets]` section. Config
files are typically committed to version control; storing a secret there would expose it. Always
supply them via the environment variable (`<TARGET_ID_UPPER_UNDERSCORE>_CLIENT_SECRET` /
`<TARGET_ID_UPPER_UNDERSCORE>_BIND_PASSWORD`).

An unknown field (including `client_secret` and `bind_password`) inside a `[targets.<uuid>]` block is
a hard startup error; the daemon will refuse to start.

### POSIX shell limitation

Environment variable names derived from a UUID that starts with a digit (e.g.
`85808642_BABA_4B8E_8C34_B48000D60A0A_SCRIPT`) are not valid POSIX shell identifiers — a name must
start with a letter or underscore — so the shell refuses to `export` them:

```
$ export 85808642_BABA_4B8E_8C34_B48000D60A0A_BIND_PASSWORD=…
bash: export: `85808642_BABA_4B8E_8C34_B48000D60A0A_BIND_PASSWORD=…': not a valid identifier
```

The `[targets]` config section sidesteps this restriction for `script`, `tenant_id`, `client_id`,
`ldap_host`, `bind_dn`, `base_dn`, and `ca_certificate`; only `client_secret` and `bind_password`
remain env-only. For a target whose UUID starts with a digit those two have no config-file escape
hatch, so set them with `env`, which places the name in the child's environment directly and never
applies the shell's identifier rules:

```sh
env 85808642_BABA_4B8E_8C34_B48000D60A0A_BIND_PASSWORD="$secret" \
  bw-rotation-daemon run --config /etc/bitwarden/rotation.toml
```

---

## Resolver: environment variable shape

The credential resolver reads credentials from environment variables with the naming convention:

```
<TARGET_SYSTEM_ID_UPPER_UNDERSCORE>_<SUFFIX>
```

where `<TARGET_SYSTEM_ID_UPPER_UNDERSCORE>` is the target system UUID string, uppercased and with
hyphens replaced by underscores, plus a trailing underscore.

**Example** — target system id `abc-1234-5678-abcd-000000000001`:

```
ABC_1234_5678_ABCD_000000000001_TENANT_ID=...
ABC_1234_5678_ABCD_000000000001_CLIENT_ID=...
ABC_1234_5678_ABCD_000000000001_CLIENT_SECRET=...
```

### Required suffixes per target kind

| Kind              | Required env-var suffixes                            |
| ----------------- | ---------------------------------------------------- |
| `Entra`           | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`            |
| `CustomScript`    | `SCRIPT`                                             |
| `ActiveDirectory` | `LDAP_HOST`, `BIND_DN`, `BASE_DN`, `BIND_PASSWORD` (plus optional `CA_CERTIFICATE`) |
| `Mssql`           | `HOST`, `USER`, `SECRET` (unsupported this build)    |

Any additional variables matching the prefix are collected and forwarded to the integration as extra
credentials. For example, a custom script may read `OUT_PATH` or `EXIT_CODE` from the `credentials`
map in the stdin payload.

If any required variable is absent the resolver returns `ResolveError::Missing` carrying the full
variable names (safe to log — names only, never values), and the rotation is aborted with failure
code `credentials_unresolved`.

---

## Custom-script integration

The `CustomScript` target kind invokes an operator-supplied executable for each rotation operation.
The binary is identified by the `SCRIPT` credential (resolved from `<ID>_SCRIPT` in the
environment).

### Security invariants

1. **Secrets via stdin only** — credentials are never passed via argv or process environment. `ps`,
   `/proc/<pid>/cmdline`, and child process inheritance cannot expose them.
2. **stdout/stderr suppressed** — both are redirected to `/dev/null`. Script output can echo
   credentials; piping unread output would also deadlock a chatty script.
3. **Script-root restriction** — if `script_root` is set in the config file, the canonicalized
   script path must be under the canonicalized root. `../` traversal and symlink escapes are
   rejected before the script is executed.
4. **RotationByAdministrativeReset** — the stdin payload never contains the current password.
   Scripts **must** perform an administrative (force) reset. A change-password script is
   incompatible with retry convergence: if the first attempt successfully changes the target
   credential but the vault write fails, the daemon retries with a new `newPassword`; a
   change-password script would then fail because the "old" password it was given is no longer
   valid.
5. **verify has no v0 opt-out** — `verify` is mandatory. A script that cannot
   round-trip-authenticate must still implement `verify` with its best available applied-check (e.g.
   querying a last-password-change timestamp or testing service reachability).

### Operations

The daemon invokes the script with a single argument: the operation name.

| Argument    | When called                                              |
| ----------- | -------------------------------------------------------- |
| `rotate`    | Immediately after password generation                    |
| `verify`    | After a successful `rotate`                              |
| `terminate` | After a successful `verify`, if `terminate_sessions` set |

### Stdin payload

One JSON document is written to stdin immediately after the process starts; stdin is then closed so
the script can read to EOF. No further input is sent.

```json
{
  "operation": "rotate",
  "targetSystemId": "…uuid…",
  "accountIdentity": "…opaque identity string…",
  "newPassword": "…new plaintext password…",
  "credentials": {
    "EXTRA_KEY": "value",
    "ANOTHER_KEY": "value"
  }
}
```

Notes:

- `newPassword` is **absent** for the `terminate` operation. The script has no need for it and
  withholding it prevents accidental echo in script-side logging.
- `credentials` contains all resolved env-var suffixes for this target, **excluding** `SCRIPT` (the
  script already knows its own path).
- Field names are camelCase.

### Exit codes

| Exit code | Meaning                                                            |
| --------- | ------------------------------------------------------------------ |
| `0`       | Success                                                            |
| `1`       | Fatal failure — credential not applied (target unchanged)          |
| `2`       | Fatal failure — credential was applied (target updated)            |
| `3`       | Fatal failure — unknown whether applied                            |
| `4`       | Transient failure — retry may succeed                              |
| other     | Fatal; rotate → unknown sync state, verify/terminate → not applied |
| signal    | Treated as `other` above                                           |

### Timeout behaviour

If the script does not exit within `script_timeout` (default 60 s) the daemon kills it (`SIGKILL`)
and maps the outcome per operation:

| Operation   | Timeout outcome (failure code `script_timeout`)                   |
| ----------- | ----------------------------------------------------------------- |
| `rotate`    | `Unknown` sync state — we don't know if the target was updated    |
| `verify`    | `Applied` sync state — conservatively assume the password was set |
| `terminate` | `NotApplied` sync state — no credential was changed               |

### Example script skeleton

```sh
#!/bin/sh
set -e

operation="$1"          # rotate | verify | terminate
payload="$(cat)"        # full JSON payload

new_password="$(printf '%s' "$payload" | jq -r '.newPassword // empty')"
account="$(printf '%s' "$payload" | jq -r '.accountIdentity')"

case "$operation" in
  rotate)
    # Perform an administrative reset — never a change-password call.
    my_admin_reset "$account" "$new_password" || exit 1
    ;;
  verify)
    # Check the target system accepted the new credential.
    my_admin_verify "$account" "$new_password" || exit 1
    ;;
  terminate)
    # Revoke active sessions (newPassword is absent in the payload).
    my_revoke_sessions "$account" || exit 1
    ;;
esac
exit 0
```

---

## Microsoft Entra ID integration

### Required permissions (app registration / service principal)

| Permission                           | Why needed                                   |
| ------------------------------------ | -------------------------------------------- |
| `User-PasswordProfile.ReadWrite.All` | Force-reset the user's password              |
| `User.Read.All`                      | Read `lastPasswordChangeDateTime` for verify |
| `User.RevokeSessions.All`            | Revoke active sessions (step 6)              |

The target user must not hold a higher-privileged directory role than the service principal
performing the rotation.

### Resolver env shape (Entra)

| Suffix          | Value                                            |
| --------------- | ------------------------------------------------ |
| `TENANT_ID`     | Azure AD tenant identifier                       |
| `CLIENT_ID`     | Application (client) ID of the service principal |
| `CLIENT_SECRET` | Client secret of the service principal           |

Example (target id `abc-1234-…`):

```
ABC_1234_…_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ABC_1234_…_CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
ABC_1234_…_CLIENT_SECRET=<secret>
```

---

## Active Directory integration

The `ActiveDirectory` target kind rotates an on-premises domain account by replacing its
`unicodePwd` attribute over LDAPS.

### LDAPS is mandatory

Every connection is made with an `ldaps://` URL (implicit TLS, port 636 by default). There is no
plaintext LDAP path, no StartTLS fallback, and no flag to skip certificate validation.

This is not only a Bitwarden policy: a domain controller refuses a `unicodePwd` write on an
unencrypted connection, answering `confidentialityRequired` (LDAP result code 13).

The domain controller's certificate is validated against the host's native trust store. A
deployment whose DC uses a private or self-signed certificate can name a PEM file of extra trust
anchors with `ca_certificate` — see [Trusting a private CA](#trusting-a-private-ca). A validation
failure ends the attempt at once, with no backoff and no second connection inside it; the job itself
is still re-claimed on later polls until its attempt budget is spent.

`ldap_host` is a bare host name, optionally with a `:port` suffix — never a URL. Anything containing
a scheme, a path, userinfo, or whitespace is rejected at rotation time so that a mistyped host cannot
silently downgrade the connection or redirect the bind.

### Trusting a private CA

Most AD deployments issue the LDAPS certificate from an internal enterprise CA, or use the
self-signed certificate the DC generates for itself. Neither chains to a public root, so the
connection fails with `TlsHandshakeFailed` unless that CA is trusted. An untrusted anchor therefore
shows up as a run of identical `target_unreachable` attempts, one per poll, not as a single failure.

Set `ca_certificate` to the path of a PEM file holding the issuing CA certificate (or the DC's own
self-signed certificate):

```toml
[targets.00000000-0000-0000-0000-000000000003]
ldap_host      = "dc01.corp.example"
bind_dn        = "CN=svc-rotate,OU=Service Accounts,DC=corp,DC=example"
base_dn        = "OU=Managed Accounts,DC=corp,DC=example"
ca_certificate = "/etc/bitwarden/ad-ca.pem"
```

Or via the environment: `<TARGET_ID_UPPER_UNDERSCORE>_CA_CERTIFICATE=/etc/bitwarden/ad-ca.pem`. It
is a file path, not a secret, so unlike `bind_password` it is accepted in either place; the usual
precedence applies (config file wins per key, environment is the fallback).

Three properties are worth being explicit about:

- **Additive, never substitutive.** The file's anchors are *added* to the platform trust store. Public CAs keep their standing, and the extra anchor applies only to that target's connections.
- **Verification is never relaxed.** The certificate chain and the host name are checked exactly as they are for a publicly-issued certificate. There is no `insecure`, `no_verify`, or `skip_hostname` flag, and none will be added: a private CA is an additional anchor, not a reason to stop checking. The `ldap_host` you configure must therefore match a SAN on the DC's certificate.
- **No silent fallback.** A missing file, an unreadable one, a malformed PEM, or a PEM with no certificate in it aborts the rotation with `credentials_unresolved`. The daemon will not quietly continue on platform roots, because that would leave an operator believing a connection is pinned when it is not.

When `ca_certificate` is absent the connection uses the platform trust store alone, exactly as it
did before the key existed.

To export a DC's current LDAPS certificate, on the DC:

```powershell
$c = Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -like "*$env:COMPUTERNAME*" -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
  Select-Object -First 1
@(
  '-----BEGIN CERTIFICATE-----'
  [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks')
  '-----END CERTIFICATE-----'
) | Set-Content -Encoding ascii C:\dc-ldaps.pem
```

### Bind identity: a delegated service account

The account named by `bind_dn` is expected to be a **delegated service account** whose only
privileges on the target OU are:

| Privilege        | Why needed                                             |
| ---------------- | ------------------------------------------------------ |
| `Reset Password` | Replace `unicodePwd` on the target accounts            |
| Read             | Resolve the account identity to a distinguished name   |

Delegate these with the Active Directory Users and Computers *Delegate Control* wizard, scoped to the
OU that holds the managed accounts. **Do not use a Domain Admin account.** A credential held by a
long-running daemon should never carry domain-wide authority, and nothing in this integration needs
it.

### How rotation works

1. Connect to `ldap_host` over LDAPS and simple-bind as `bind_dn`.
2. Search below `base_dn` (subtree scope) for exactly one user whose `sAMAccountName` or `userPrincipalName` matches the account identity. Zero matches and multiple matches are both fatal — rotating the wrong account is worse than not rotating.
3. `replace` the account's `unicodePwd` with the new password, wrapped in ASCII double quotes and encoded as little-endian UTF-16 (no BOM), as Active Directory requires.

This is an administrative reset: it never needs the account's current password, which is what allows
a failed attempt to be retried with a freshly generated password.

The account identity is escaped per RFC 4515 before it enters the search filter, so a hostile
identity cannot widen the search.

### Verification

`verify` opens a second LDAPS connection and simple-binds **as the rotated account** using the new
password. A successful bind is direct proof that the directory accepted the write — unlike a
timestamp read it cannot be stale, and unlike an attribute compare it cannot be satisfied by some
other change. A rejected bind is fatal.

### The previous password stays valid for a grace period

Rotating an AD password does **not** invalidate the previous one immediately. Windows keeps
accepting the immediately-preceding password for NTLM and LDAP simple binds for
`OldPasswordAllowedPeriod` — **60 minutes by default**, configured under
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

This is directory behaviour, not something the connector can override, and it is worth pairing with
the note below: for up to an hour after a rotation, both the old and the new credential
authenticate, and existing Kerberos tickets remain valid on top of that. Deployments that need a
hard cut-off must shorten `OldPasswordAllowedPeriod` and handle ticket lifetime separately.

`verify` is unaffected — it binds with the *new* password, which is valid immediately.

### Session termination is not supported

`terminate_sessions` always fails with `unsupported_kind`. An LDAP password reset cannot revoke
Kerberos ticket-granting tickets that have already been issued, and LDAP offers no revocation
operation; there is no honest implementation. The server advertises
`supportsSessionTermination: false` for this kind, so the executor should never call it.

Operators who need existing sessions cut off must do it out of band (for example by resetting the
account's `msDS-KeyVersionNumber`, disabling and re-enabling the account, or waiting out the ticket
lifetime).

### Resolver env shape (Active Directory)

| Suffix          | Value                                                             |
| --------------- | ----------------------------------------------------------------- |
| `LDAP_HOST`     | Domain controller host name, optionally `host:port`               |
| `BIND_DN`       | DN of the delegated service account                               |
| `BASE_DN`       | Search base DN for account lookup                                 |
| `BIND_PASSWORD` | Password of the delegated service account (**environment only**)  |
| `CA_CERTIFICATE` | *Optional.* Path to a PEM file of additional TLS trust anchors   |

Example (target id `abc-1234-…`):

```
ABC_1234_…_LDAP_HOST=dc01.corp.example
ABC_1234_…_BIND_DN=CN=svc-rotate,OU=Service Accounts,DC=corp,DC=example
ABC_1234_…_BASE_DN=OU=Managed Accounts,DC=corp,DC=example
ABC_1234_…_BIND_PASSWORD=<secret>
```

`LDAP_HOST`, `BIND_DN`, `BASE_DN`, and `CA_CERTIFICATE` may also be supplied in the
`[targets.<uuid>]` config section as `ldap_host`, `bind_dn`, `base_dn`, and `ca_certificate`.
`BIND_PASSWORD` may not — see [Secrets are env-only](#secrets-are-env-only).

### Error classification

**Class** applies within a single attempt: `Transient` is retried in place with exponential backoff
up to `max_retry_attempts`, `Fatal` ends the attempt on the spot. Neither ends the job. A reported
failure returns the job to the claimable pool and the daemon re-claims it on a later poll, until the
server's attempt budget is spent — so a `Fatal` misconfiguration still reaches the domain controller
once per attempt.

| Condition                                              | Class     | Sync state | Failure code             |
| ------------------------------------------------------ | --------- | ---------- | ------------------------ |
| Missing or malformed credential                        | Fatal     | unchanged  | `credentials_unresolved` |
| TCP failure, reset connection                          | Transient | unchanged  | `target_unreachable`     |
| TLS handshake or certificate rejected                  | Fatal     | unchanged  | `target_unreachable`     |
| `ca_certificate` missing, unreadable, or malformed     | Fatal     | unchanged  | `credentials_unresolved` |
| Bind rejected (rc 49, 50)                              | Fatal     | unchanged  | `target_rejected`        |
| Account not found or ambiguous                         | Fatal     | unchanged  | `target_rejected`        |
| Write rejected (rc 13, 19, 32, 53, schema errors)      | Fatal     | unchanged  | `target_rejected`        |
| DC busy / unavailable / admin limit (rc 51, 52, 11)    | Transient | unchanged  | `target_unreachable`     |
| Timeout or dropped connection after the write is sent  | Transient | **indeterminate** | `target_unreachable` |
| Rebind with the new password rejected                  | Fatal     | updated    | `verification_failed`    |

Only the numeric LDAP result code reaches the failure report. The directory's `diagnosticMessage` and
matched DN are never read: both can echo account names and password-policy text.

---

## References

- Spec: `rotation-daemon/rotation-daemon.allium`
- Architecture: https://contributing.bitwarden.com/architecture/sdk/
