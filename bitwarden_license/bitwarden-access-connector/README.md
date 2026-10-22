# bitwarden-access-connector

Bitwarden PAM access connector.

This crate provides the `bwac` binary. It polls the Bitwarden server for claimable rotation jobs and
runs each one: resolve credentials, generate a password, rotate it in the target system, verify,
write the re-encrypted vault cipher, optionally terminate sessions, and report the outcome.

## Usage

| Command                    | Description                                            |
| -------------------------- | ------------------------------------------------------ |
| `bwac run`                 | Start the connector poll loop                          |
| `bwac run --config <PATH>` | Use this configuration file, also set by `BWAC_CONFIG` |
| `bwac --version`           | Print the version                                      |
| `bwac --help`              | Print help; `bwac run --help` for the run options      |

Connector settings live in the [configuration file](#configuration-file), not in command-line flags.

### Environment variables

| Variable            | Purpose                                                  |
| ------------------- | -------------------------------------------------------- |
| `BWAC_TOKEN`        | Access connector token (required)                        |
| `BWAC_CONFIG`       | Path to the TOML configuration file, same as `--config`  |
| `BWAC_API_URL`      | Bitwarden API server URL, overrides the config file      |
| `BWAC_IDENTITY_URL` | Bitwarden identity server URL, overrides the config file |
| `RUST_LOG`          | Log filter directives, default `info`                    |

### Token security

The token contains the org-key encryption key, so it is only read from `BWAC_TOKEN`, never from a
flag, since argv is visible in `ps` and `/proc/<pid>/cmdline`. The connector removes it from its
environment after reading it, so custom scripts and other child processes do not inherit it.

### Configuration file

Pass the file with `--config <PATH>` or `BWAC_CONFIG`. Unknown keys are a startup error, and so is a
`token` key; see [Token security](#token-security).

Server URLs resolve in this order, highest first. If none is set, startup fails with an error naming
all three.

1. `BWAC_API_URL` / `BWAC_IDENTITY_URL` environment variables
2. `[environment].api` / `[environment].identity` in the config file
3. Derived from `[environment].base` as `{base}/api` / `{base}/identity`

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

# PowerShell host, used for any script the connector launches through PowerShell.
powershell_execution_policy = "Bypass"   # set "AllSigned" if you sign your scripts
# powershell_path = "C:\\Program Files\\PowerShell\\7\\pwsh.exe"   # else discovered on PATH

entra_verify_probe = false   # set true only with MFA exemption for the service principal

[environment]
# Supply a base URL and let the connector derive /api and /identity automatically:
base     = "https://bitwarden.example.com"
# Or override individual URLs (takes precedence over base-derived values):
# api      = "https://api.bitwarden.com"
# identity = "https://identity.bitwarden.com"
```

Per-target credential overrides go in the `[targets]` section; see
[Per-target overrides](#per-target-overrides-targets).

### Logging

Log output is written to stderr. The log level is controlled by the `RUST_LOG` environment variable
(same syntax as `tracing-subscriber`'s `EnvFilter`):

```sh
RUST_LOG=debug bwac run --config /etc/bwac/config.toml
RUST_LOG=bitwarden_access_connector=trace,info bwac run --config /etc/bwac/config.toml
```

#### Operator-visible events at `info` / `warn` / `error`

| Level   | Event                                                | Key fields                                                                                       |
| ------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `info`  | Access connector starting                            | `api_url`, `identity_url`, `poll_interval_secs`, `heartbeat_interval_secs`, `configured_targets` |
| `info`  | Session authenticated                                | `retry`                                                                                          |
| `info`  | Shutdown signal received                             |                                                                                                  |
| `info`  | Rotation job claimed                                 | `job_id`, `target_system_name`                                                                   |
| `info`  | Starting rotation execution                          | `attempt_id`, `job_id`, `cipher_id`, `target_system_name`                                        |
| `info`  | Pre-flight cipher check passed                       | `attempt_id`                                                                                     |
| `info`  | Step 1: credentials resolved                         | `attempt_id`                                                                                     |
| `info`  | Step 2: password generated                           | `attempt_id`                                                                                     |
| `info`  | Step 3: target rotate succeeded                      | `attempt_id`, `kind`                                                                             |
| `info`  | Step 4: verify succeeded                             | `attempt_id`                                                                                     |
| `info`  | Step 5: cipher written                               | `attempt_id`, `cipher_id`                                                                        |
| `info`  | Step 6: session termination succeeded                | `attempt_id`                                                                                     |
| `info`  | Step 7: rotation succeeded and reported              | `attempt_id`, `termination`                                                                      |
| `info`  | Access connector shut down cleanly                   |                                                                                                  |
| `warn`  | Session renewal failed (transient / protocol)        | `retry`, `sleep_ms`                                                                              |
| `warn`  | Session entered Revoked phase                        |                                                                                                  |
| `warn`  | Rotation failed (any step)                           | `attempt_id`, `failure_code`, `sync_state`, `detail`                                             |
| `warn`  | Step 6: session termination aborted / failed         | `attempt_id`, `abort_reason`                                                                     |
| `warn`  | Transient poll error / backoff                       |                                                                                                  |
| `warn`  | Success report rejected/unknown by server            | `attempt_id`                                                                                     |
| `error` | Access connector credential refused                  |                                                                                                  |
| `error` | Access connector could not authenticate at startup   |                                                                                                  |
| `error` | Access connector not eligible for rotation endpoints |                                                                                                  |

`RUST_LOG=debug` adds: poll ticks (with claimable job count), heartbeat ticks, claim-race losses
(409 per job), cipher fetches and reported attempts.

### Exit codes

| Code | Meaning                                                                                               |
| ---- | ----------------------------------------------------------------------------------------------------- |
| `0`  | Clean shutdown (SIGTERM or Ctrl-C)                                                                    |
| `1`  | Startup error: invalid configuration, token or arguments, I/O error, or parse failure                 |
| `2`  | Credential refused. An admin reissues it (`ReissueConnectorCredential`); restart with the new token   |
| `3`  | Not eligible. Check the connector isn't revoked or disabled, the license is active and `UsePam` is on |
| `4`  | Startup authentication failed transiently. Check connectivity and the identity URL, then restart      |

## Credential resolution

Credentials for a target system are read from environment variables, optionally overridden per key
from the `[targets]` section of the connector's TOML configuration file.

### Environment variable shape

```
<TARGET_SYSTEM_ID_UPPER_UNDERSCORE>_<SUFFIX>
```

The prefix is the target system UUID, uppercased, with hyphens replaced by underscores, followed by
an underscore.

**Example** for target system id `ec2c1d46-6a4b-4751-a310-af9601317f2d`:

```
EC2C1D46_6A4B_4751_A310_AF9601317F2D_TENANT_ID=...
EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_ID=...
EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_SECRET=...
```

Any additional variable matching the prefix is collected and forwarded to the integration as an
extra credential. For example, a custom script may read `OUT_PATH` from the `credentials` map in the
stdin payload.

#### Required suffixes per target kind

| Kind           | Required env-var suffixes                 |
| -------------- | ----------------------------------------- |
| `Entra`        | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` |
| `CustomScript` | `SCRIPT` (`SCRIPT_TYPE` optional)         |

A target kind with no registered integration fails with `unsupported_kind`.

If a required value is absent from both sources, resolution fails with the full environment variable
names (names only, never values), and the rotation is aborted with failure code
`credentials_unresolved`.

#### POSIX shell limitation

Variable names derived from a UUID that starts with a digit (for example
`85808642_BABA_4B8E_8C34_B48000D60A0A_SCRIPT`) cannot be `export`ed from a POSIX `/bin/sh`: names
must start with a letter or underscore. The `[targets]` section sidesteps this for `script`,
`script_type`, `tenant_id` and `client_id`; only `client_secret` remains env-only.

### Per-target overrides (`[targets]`)

The optional `[targets]` TOML section is keyed by target system UUID. Each entry overrides
individual credentials.

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/scripts/rotate-thing.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

**Precedence** is per key: a value set in `[targets.<uuid>]` wins; the environment variable is the
fallback for any key the entry does not set.

#### Accepted keys per target entry

| Key           | Overrides env suffix | Applicable kinds |
| ------------- | -------------------- | ---------------- |
| `script`      | `SCRIPT`             | `CustomScript`   |
| `script_type` | `SCRIPT_TYPE`        | `CustomScript`   |
| `tenant_id`   | `TENANT_ID`          | `Entra`          |
| `client_id`   | `CLIENT_ID`          | `Entra`          |

#### `client_secret` is env-only

`client_secret` is deliberately not accepted in `[targets]` entries: configuration files are
typically committed to version control and must not hold secrets. Supply it through the
`<TARGET_ID_UPPER_UNDERSCORE>_CLIENT_SECRET` environment variable. Entries reject unknown keys
(`deny_unknown_fields`), so a `client_secret` key is a configuration error.

Missing-value errors always name the **environment variable**, regardless of which source was
expected to supply it.

---

## Custom-script integration

The `CustomScript` target kind invokes an operator-supplied script for each rotation operation. The
script is identified by the `SCRIPT` credential (`<ID>_SCRIPT` in the environment, or `script` in
`[targets]`).

### Security invariants

1. **Secrets via stdin only.** Credentials are never passed through argv or the process environment,
   so `ps`, `/proc/<pid>/cmdline` and child process inheritance cannot expose them. A directly
   executed script starts with an empty environment.
2. **stdout and stderr are discarded.** Both go to the null device. Script output can echo
   credentials, and unread piped output would deadlock a chatty script.
3. **Script-root restriction.** When the connector has a script root configured, the canonicalised
   script path must lie under the canonicalised root. `../` traversal and symlink escapes are
   rejected before the script runs. A script that cannot be found, or a root that cannot be
   resolved, fails with `credentials_unresolved`.
4. **Administrative reset.** The stdin payload never contains the current password, so scripts
   **must** perform an administrative (force) reset. A change-password script is incompatible with
   retry convergence: if the first attempt changes the target credential but the vault write fails,
   the connector retries with a new `newPassword`, and the change-password script would fail because
   the "old" password it was given is no longer valid.
5. **`verify` is mandatory.** A script that cannot round-trip-authenticate must still implement
   `verify` with its best available applied-check, such as reading a last-password-change timestamp
   or testing service reachability.
6. **`accountIdentity` is untrusted input.** It comes from a blob the admin client sealed, so the
   server cannot read or change it, but it is still chosen by whoever saved the rotation config.
   Never interpolate it unsanitised into a shell command, SQL query or API path.

### Operations

The connector invokes the script with a single argument: the operation name.

| Argument    | When called                                                      |
| ----------- | ---------------------------------------------------------------- |
| `rotate`    | Immediately after password generation                            |
| `verify`    | After a successful `rotate`                                      |
| `terminate` | After a successful `verify`, if session termination is requested |

A failed `terminate` does not fail the rotation.

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

- Field names are camelCase.
- `newPassword` is **absent** for the `terminate` operation. The script has no need for it, and
  withholding it prevents accidental echo in script-side logging.
- `credentials` contains every resolved suffix for the target **except** `SCRIPT` and `SCRIPT_TYPE`.
  Those two configure how the connector launches the script, not the target.

### Exit codes

| Exit code | Meaning                                                          |
| --------- | ---------------------------------------------------------------- |
| `0`       | Success                                                          |
| `1`       | Fatal failure: credential not applied (target unchanged)         |
| `2`       | Fatal failure: credential was applied (target updated)           |
| `3`       | Fatal failure: unknown whether applied                           |
| `4`       | Transient failure: retry may succeed (target unchanged)          |
| other     | Fatal; rotate: unknown sync state, verify/terminate: not applied |
| signal    | Treated as `other`; the failure detail names it, e.g. `signal 9` |

Failures from a non-zero exit report failure code `script_failed`.

### Timeout behaviour

If the script does not exit within the connector's script timeout, the connector kills it and fails
the operation with failure code `script_timeout`. The sync state depends on the operation:

| Operation   | Sync state on timeout                                            |
| ----------- | ---------------------------------------------------------------- |
| `rotate`    | Indeterminate: it is not known whether the target was updated    |
| `verify`    | Target updated: the password is conservatively assumed to be set |
| `terminate` | Target unchanged: no credential was changed                      |

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
    # Perform an administrative reset, never a change-password call.
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

## PowerShell scripts

A `.ps1` is not an executable; it needs a PowerShell host to interpret it. The connector launches
one for you. Everything else about the integration is unchanged, so the contract above (stdin
payload, exit codes, timeouts, script root) applies verbatim.

### When PowerShell is used

| `script_type` | Script path   | Launcher          |
| ------------- | ------------- | ----------------- |
| _unset_       | `*.ps1`       | PowerShell host   |
| _unset_       | anything else | executed directly |
| `powershell`  | any           | PowerShell host   |
| `direct`      | any           | executed directly |

The extension (matched case-insensitively) decides by default, so the common case needs no
configuration:

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = 'C:\bwac\rotate-sqlsa.ps1'
```

Set `script_type` only when the filename cannot say what the file is: an extensionless script that
needs PowerShell, or a `.ps1` that must run some other way:

```toml
[targets.00000000-0000-0000-0000-000000000003]
script      = "/opt/bwac/rotate-appliance"
script_type = "powershell"
```

An explicit `script_type` (or `SCRIPT_TYPE` environment variable) always wins over the extension.
The file decides rather than the host OS, so a `.ps1` rotates from a Linux or macOS connector
running PowerShell 7, and a native `.exe` target on Windows keeps executing directly.

An unrecognised `script_type` fails the rotation with `credentials_unresolved` rather than falling
back to direct execution.

### Host discovery

In order: the connector's configured PowerShell path, then `pwsh` / `pwsh.exe` on `PATH`, then
`powershell.exe` on `PATH`. PowerShell 7 is preferred over Windows PowerShell 5.1.

A configured path is used exactly as given and never falls back to a discovered host, so a mistyped
path fails loudly instead of silently running your script under a different interpreter. If no host
is found at all, the rotation fails with `credentials_unresolved`; targets that do not use
PowerShell are unaffected.

### Invocation

```
<host> -NoProfile -NonInteractive -ExecutionPolicy <policy> -File <script> <operation>
```

`-NoProfile` keeps an operator profile from changing rotation behaviour and `-NonInteractive` stops
the host blocking on a prompt. `-File` is used rather than `-Command` so the operation arrives as a
real argument instead of being interpolated into a command string.

Windows PowerShell 5.1 requires a `.ps1` extension for `-File`; PowerShell 7 does not. An
extensionless script forced to PowerShell therefore works only under `pwsh`.

### Execution policy

The execution policy is a connector setting passed to the host verbatim. Windows Server ships
`RemoteSigned`, which refuses to run an unsigned `.ps1`; a policy that does not permit your scripts
makes the first rotation on a fresh host fail with a bare exit 1. If you sign your rotation scripts,
use `AllSigned`.

### Environment

Directly executed scripts get a completely empty environment. A PowerShell host cannot start that
way. On Windows it needs `SystemRoot` to locate system assemblies and `PSModulePath` to find
modules, so it receives a fixed allowlist instead: `SystemRoot`, `windir`, `PATHEXT`, `COMSPEC`,
`PSModulePath`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMDATA`, `APPDATA`, `LOCALAPPDATA`,
`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `PATH`, `TEMP`, `TMP`, `HOME`, `TMPDIR`, `LANG`. Variables
not set in the connector's environment are omitted.

Nothing else is forwarded. Per-target credentials and the new password are absent from the child
environment; secrets still reach your script only through the stdin payload.

### Example script skeleton

```powershell
# rotate.ps1, invoked as: rotate.ps1 <rotate|verify|terminate>
param([Parameter(Mandatory)][string]$Operation)

# Required. PowerShell's default is 'Continue', which would let a failed reset fall through to
# `exit 0` and be reported as a success. See "Reporting the right exit code" below.
$ErrorActionPreference = 'Stop'

$payload  = [Console]::In.ReadToEnd() | ConvertFrom-Json
$account  = $payload.accountIdentity
$password = $payload.newPassword          # absent for 'terminate'

switch ($Operation) {
    'rotate' {
        # An administrative reset, never a change-password call.
        Reset-MyAccountPassword -Identity $account -NewPassword $password
    }
    'verify' {
        if (-not (Test-MyAccountPassword -Identity $account -Password $password)) {
            exit 1
        }
    }
    'terminate' {
        Revoke-MySessions -Identity $account
    }
}

exit 0
```

### Reporting the right exit code

The exit-code table is what tells Bitwarden whether the target actually changed, and PowerShell
makes it easier to get wrong than a shell script does:

- **Set `$ErrorActionPreference = 'Stop'` as the first line.** Under the default `Continue`, a
  cmdlet that fails writes an error and execution carries on to your `exit 0`, reporting a failed
  rotation as a success.
- **Anything that throws after the password was already reset must exit 2, not 1.** An uncaught
  exception exits 1, which means "target unchanged". If the reset succeeded and a later step blew
  up, the target has changed, and reporting otherwise leaves the vault out of sync with it. Wrap the
  post-reset work:

  ```powershell
  Reset-MyAccountPassword -Identity $account -NewPassword $password
  try {
      Confirm-MyReset -Identity $account
  } catch {
      exit 2      # target updated, but we could not finish
  }
  ```

- **Use exit 4 for anything worth retrying**: a timeout, a throttling response, an unreachable
  endpoint.

### Troubleshooting

The connector discards script stdout and stderr, because either can echo the credentials it just
handed you. That also means a host-level failure (an execution-policy block, an unsigned script, a
parse error, a module that will not load) arrives as `script_failed` with nothing but `exit code 1`.

To see the actual error, run the script by hand as the account the connector runs under, which also
reproduces the environment allowlist:

```
runas /user:svc_bwac "pwsh -NoProfile -NonInteractive -File C:\bwac\rotate-sqlsa.ps1 rotate"
```

---

## Microsoft Entra ID integration

The `Entra` target kind rotates a user's password through Microsoft Graph, authenticating as a
service principal with the client-credentials flow.

### Credentials

| Suffix          | Value                                            |
| --------------- | ------------------------------------------------ |
| `TENANT_ID`     | Azure AD tenant identifier                       |
| `CLIENT_ID`     | Application (client) ID of the service principal |
| `CLIENT_SECRET` | Client secret of the service principal           |

```
EC2C1D46_6A4B_4751_A310_AF9601317F2D_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_SECRET=<secret>
```

### Required permissions (app registration / service principal)

| Permission                           | Graph call                                                | Why needed                                   |
| ------------------------------------ | --------------------------------------------------------- | -------------------------------------------- |
| `User-PasswordProfile.ReadWrite.All` | `PATCH /v1.0/users/{id}` (`passwordProfile`)              | Force-reset the user's password              |
| `User.Read.All`                      | `GET /v1.0/users/{id}?$select=lastPasswordChangeDateTime` | Read `lastPasswordChangeDateTime` for verify |
| `User.RevokeSessions.All`            | `POST /v1.0/users/{id}/revokeSignInSessions`              | Revoke active sessions                       |

The account identity is the user's object id or user principal name. The reset sets
`forceChangePasswordNextSignIn` to `false`.

### Verification

`verify` polls Graph for the user's `lastPasswordChangeDateTime` and succeeds once it is no older
than the start of the rotation (minus five minutes of clock slack). It polls every 5 seconds for up
to 60 seconds to tolerate Graph replication lag, and fails with `verification_failed` if the
timestamp stays stale.

An optional sign-in probe runs first when enabled. It attempts a resource-owner password grant
(ROPC) with the new password: success, or an MFA challenge (`AADSTS50076`, `AADSTS50079`), counts as
verified; a wrong-password response (`AADSTS50126`) fails the verification; any other outcome falls
through to the directory check. The probe is off unless enabled, because MFA or Conditional Access
blocks ROPC in most tenants.
