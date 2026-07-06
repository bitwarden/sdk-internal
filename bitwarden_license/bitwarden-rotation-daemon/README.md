# bitwarden-rotation-daemon

Bitwarden PAM credential rotation daemon.

This crate provides the `bw-rotation-daemon` binary.  It continuously rotates
PAM-managed credentials by polling the Bitwarden server for claimable rotation
jobs, executing each job (resolve credentials → generate password → rotate in
the target system → verify → write re-encrypted vault cipher → optionally
terminate sessions → report outcome), and then returning to the poll loop.

## Usage

```
bw-rotation-daemon run [OPTIONS] --api-url <API_URL> --identity-url <IDENTITY_URL>
```

### Environment variables

| Variable            | Purpose                                                      |
|---------------------|--------------------------------------------------------------|
| `BWRD_API_URL`      | Bitwarden API server URL (overridden by `--api-url`)         |
| `BWRD_IDENTITY_URL` | Bitwarden identity server URL (overridden by `--identity-url`) |
| `BWRD_TOKEN`        | Daemon access token (exactly one of `BWRD_TOKEN` / `--token-file` required) |
| `RUST_LOG`          | Log filter directives; default `info` (e.g. `RUST_LOG=debug`) |

### Flags and options

| Flag / option               | Default | Minimum | Description                                          |
|-----------------------------|---------|---------|------------------------------------------------------|
| `--api-url <URL>`           | —       | —       | Bitwarden API server URL                             |
| `--identity-url <URL>`      | —       | —       | Bitwarden identity server URL                        |
| `--token-file <PATH>`       | —       | —       | File containing the daemon token (trimmed)           |
| `--poll-interval <SECS>`    | `15`    | `15`    | How often to poll for new jobs                       |
| `--heartbeat-interval <SECS>`| `30`   | —       | Heartbeat frequency during an executing rotation (< 120) |
| `--offline-grace <SECS>`    | `60`    | —       | Max time without server contact before pausing target steps |
| `--max-retry-attempts <N>`  | `5`     | —       | Total tries per retryable step (incl. first attempt) |
| `--retry-base-delay <SECS>` | `1`     | —       | Base for exponential backoff between retries         |
| `--script-root <DIR>`       | —       | —       | Restrict custom script paths to this directory       |
| `--script-timeout <SECS>`   | `60`    | —       | Kill a custom script after this many seconds         |
| `--entra-verify-probe`      | off     | —       | Enable ROPC verify probe for Entra (requires MFA exemption) |

### Token security

The daemon token contains the org-key encryption key.  It is **never** accepted
as a plain `--token` argument — argv is visible via `ps`/`/proc/<pid>/cmdline`.
Supply it via `BWRD_TOKEN` or `--token-file` only.

On Unix, if `--token-file` is used and the file is group- or world-readable
(mode `0o044`), a warning is logged.  Restrict permissions with `chmod 600`.

### Logging

Log output is written to stderr.  The log level is controlled by the `RUST_LOG`
environment variable (same syntax as `tracing-subscriber`'s `EnvFilter`):

```sh
RUST_LOG=debug bw-rotation-daemon run --api-url ... --identity-url ...
RUST_LOG=bitwarden_rotation_daemon=trace,info bw-rotation-daemon run ...
```

### Exit codes

| Code | Meaning                                                                |
|------|------------------------------------------------------------------------|
| `0`  | Clean shutdown (SIGTERM or Ctrl-C received).                           |
| `1`  | Startup error: invalid configuration, I/O error, or parse failure.     |
| `2`  | Daemon credential refused.  An admin must reissue the credential       |
|      | server-side (via `ReissueDaemonCredential`) and restart the daemon     |
|      | with the new token.                                                    |
| `3`  | Daemon not eligible for rotation endpoints.  Check: daemon record not  |
|      | revoked or disabled, organisation license active, `UsePam` enabled.    |

---

## Resolver: environment variable shape

The `EnvCredentialResolver` reads credentials from environment variables with
the naming convention:

```
<TARGET_SYSTEM_ID_UPPER_UNDERSCORE>_<SUFFIX>
```

where `<TARGET_SYSTEM_ID_UPPER_UNDERSCORE>` is the target system UUID string,
uppercased and with hyphens replaced by underscores, plus a trailing
underscore.

**Example** — target system id `abc-1234-5678-abcd-000000000001`:

```
ABC_1234_5678_ABCD_000000000001_TENANT_ID=...
ABC_1234_5678_ABCD_000000000001_CLIENT_ID=...
ABC_1234_5678_ABCD_000000000001_CLIENT_SECRET=...
```

### Required suffixes per target kind

| Kind           | Required env-var suffixes                        |
|----------------|--------------------------------------------------|
| `Entra`        | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`        |
| `CustomScript` | `SCRIPT`                                         |
| `Mssql`        | `HOST`, `USER`, `SECRET` (unsupported this build)|

Any additional variables matching the prefix are collected and forwarded to
the integration as extra credentials.  For example, a custom script may read
`OUT_PATH` or `EXIT_CODE` from the `credentials` map in the stdin payload.

If any required variable is absent the resolver returns
`ResolveError::Missing` carrying the full variable names (safe to log — names
only, never values), and the rotation is aborted with failure code
`credentials_unresolved`.

---

## Custom-script integration

The `CustomScript` target kind invokes an operator-supplied executable for each
rotation operation.  The binary is identified by the `SCRIPT` credential
(resolved from `<ID>_SCRIPT` in the environment).

### Security invariants

1. **Secrets via stdin only** — credentials are never passed via argv or
   process environment.  `ps`, `/proc/<pid>/cmdline`, and child process
   inheritance cannot expose them.
2. **stdout/stderr suppressed** — both are redirected to `/dev/null`.  Script
   output can echo credentials; piping unread output would also deadlock a
   chatty script.
3. **Script-root restriction** — if `--script-root` is set, the canonicalized
   script path must be under the canonicalized root.  `../` traversal and
   symlink escapes are rejected before the script is executed.
4. **RotationByAdministrativeReset** — the stdin payload never contains the
   current password.  Scripts **must** perform an administrative (force) reset.
   A change-password script is incompatible with retry convergence: if the first
   attempt successfully changes the target credential but the vault write fails,
   the daemon retries with a new `newPassword`; a change-password script would
   then fail because the "old" password it was given is no longer valid.
5. **verify has no v0 opt-out** — `verify` is mandatory.  A script that cannot
   round-trip-authenticate must still implement `verify` with its best available
   applied-check (e.g. querying a last-password-change timestamp or testing
   service reachability).

### Operations

The daemon invokes the script with a single argument: the operation name.

| Argument    | When called                                              |
|-------------|----------------------------------------------------------|
| `rotate`    | Immediately after password generation                    |
| `verify`    | After a successful `rotate`                              |
| `terminate` | After a successful `verify`, if `terminate_sessions` set |

### Stdin payload

One JSON document is written to stdin immediately after the process starts;
stdin is then closed so the script can read to EOF.  No further input is sent.

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

- `newPassword` is **absent** for the `terminate` operation.  The script has
  no need for it and withholding it prevents accidental echo in script-side
  logging.
- `credentials` contains all resolved env-var suffixes for this target,
  **excluding** `SCRIPT` (the script already knows its own path).
- Field names are camelCase.

### Exit codes

| Exit code | Meaning                                                        |
|-----------|----------------------------------------------------------------|
| `0`       | Success                                                        |
| `1`       | Fatal failure — credential not applied (target unchanged)      |
| `2`       | Fatal failure — credential was applied (target updated)        |
| `3`       | Fatal failure — unknown whether applied                        |
| `4`       | Transient failure — retry may succeed                          |
| other     | Fatal; rotate → unknown sync state, verify/terminate → not applied |
| signal    | Treated as `other` above                                       |

### Timeout behaviour

If the script does not exit within `--script-timeout` (default 60 s) the
daemon kills it (`SIGKILL`) and maps the outcome per operation:

| Operation   | Timeout outcome (failure code `script_timeout`) |
|-------------|--------------------------------------------------|
| `rotate`    | `Unknown` sync state — we don't know if the target was updated |
| `verify`    | `Applied` sync state — conservatively assume the password was set |
| `terminate` | `NotApplied` sync state — no credential was changed              |

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

| Permission                          | Why needed                                    |
|-------------------------------------|-----------------------------------------------|
| `User-PasswordProfile.ReadWrite.All`| Force-reset the user's password               |
| `User.Read.All`                     | Read `lastPasswordChangeDateTime` for verify  |
| `User.RevokeSessions.All`           | Revoke active sessions (step 6)               |

The target user must not hold a higher-privileged directory role than the
service principal performing the rotation.

### Resolver env shape (Entra)

| Suffix          | Value                                               |
|-----------------|-----------------------------------------------------|
| `TENANT_ID`     | Azure AD tenant identifier                          |
| `CLIENT_ID`     | Application (client) ID of the service principal    |
| `CLIENT_SECRET` | Client secret of the service principal              |

Example (target id `abc-1234-…`):

```
ABC_1234_…_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ABC_1234_…_CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
ABC_1234_…_CLIENT_SECRET=<secret>
```

---

## References

- Plan: `~/.claude/plans/let-s-explore-implementing-the-spicy-sun.md`
- Spec: `rotation-daemon/rotation-daemon.allium`
- Architecture: https://contributing.bitwarden.com/architecture/sdk/
