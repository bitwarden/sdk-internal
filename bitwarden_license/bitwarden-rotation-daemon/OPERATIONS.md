# Bitwarden PAM Rotation Daemon

`bw-rotation-daemon` automatically rotates the passwords of privileged accounts (domain admins,
service accounts, appliance root logins, database roles) and stores each new password in your
Bitwarden organisation vault.

You run it inside your own network. Bitwarden's server decides _what_ should be rotated and _when_;
the daemon does the actual rotating, because only it can reach the systems being rotated. The server
never sees a plaintext password.

> **Commercial feature.** The rotation daemon requires an active organisation licence with PAM
> enabled.

## Contents

- [How it works](#how-it-works)
- [Security model](#security-model)
- [Requirements](#requirements)
- [Getting started](#getting-started)
- [Configuration reference](#configuration-reference)
- [Per-target credentials](#per-target-credentials)
- [Supported target systems](#supported-target-systems)
- [Writing a custom rotation script](#writing-a-custom-rotation-script)
- [PowerShell scripts](#powershell-scripts)
- [Running in production](#running-in-production)
- [Observability](#observability)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## How it works

The daemon makes outbound connections only. It never listens on a port, and nothing needs to connect
to it. It sits in whatever network segment can reach your target systems, and polls Bitwarden for
work.

```
   your network                                  Bitwarden server
  ┌──────────────────────────┐                  ┌──────────────────┐
  │  bw-rotation-daemon      │  ── poll ──────▶ │  rotation jobs   │
  │                          │  ◀─ job ───────  │                  │
  │                          │                  │                  │
  │      │ rotate            │  ── cipher ────▶ │  org vault       │
  │      ▼                   │  ── report ────▶ │  audit log       │
  │  target systems          │                  └──────────────────┘
  │  (Entra, servers, DBs…)  │
  └──────────────────────────┘
```

### The loop

Every `poll_interval` seconds (default 15) the daemon asks the server for claimable jobs and tries
to claim one. If it claims a job it runs the rotation to completion, reports the outcome, and
returns to polling.

### One rotation, step by step

1. **Resolve credentials.** Look up how to authenticate to this target system (see
   [Per-target credentials](#per-target-credentials)).
2. **Generate a password.** Using the password policy attached to the target system in Bitwarden.
3. **Rotate.** Set the new password on the target system.
4. **Verify.** Prove the new password took effect.
5. **Write the vault entry.** Encrypt the new password and save it to the organisation vault.
6. **Terminate sessions.** If the job asks for it, revoke the account's active sessions. A failure
   here never fails the rotation.
7. **Report.** Tell the server the attempt succeeded, or why it failed.

Transient failures are retried with exponential backoff (`max_retry_attempts`, default 5 total
tries); fatal ones stop immediately. Before every attempt at a target-side step the daemon re-checks
that it still holds a valid session and that the job's execution window has not expired, so it will
not touch a target system after losing its authorisation to do so.

The vault write and the final report are not cut off by that window, so a rotation that changed the
target is always recorded.

### Throughput and scaling

One daemon handles one rotation at a time, and claims at most one job per poll tick. To rotate more
accounts in parallel, run more daemons. They compete safely: if two daemons try to claim the same
job, one wins and the other moves on to the next job.

Run daemons in different network segments to reach targets that no single host can reach. Each
daemon only needs credentials for the targets it is responsible for.

---

## Security model

### What the daemon can access

The daemon token grants two things: the ability to call the rotation endpoints, and the ability to
decrypt and encrypt your organisation's vault entries. Anyone holding it can read organisation vault
data.

So the daemon accepts the token only through the `BWRD_TOKEN` environment variable:

- A `--token` flag would expose it. `argv` is world-readable via `ps` and `/proc/<pid>/cmdline`.
- A config-file key would end up in a repository. Any config containing `token` is a hard startup
  error.

At startup the daemon reads `BWRD_TOKEN` and then removes it from its own environment, so any child
process it spawns (such as a custom rotation script) cannot inherit it.

### What the server sees

New passwords are generated on the daemon host and encrypted there before being sent. The Bitwarden
server stores ciphertext it cannot read. Failure reports draw on a fixed vocabulary (error codes,
HTTP status codes, script exit codes, variable _names_) and never contain credential values.

### Administrative reset

The daemon never sends a target account's _current_ password to an integration or script. Rotation
is always an administrative reset. The daemon authenticates as a separate privileged identity that
has authority to reset the account, the way a helpdesk resets a password without knowing the old
one.

If a change-password flow set the target to `X` and the vault write then failed, the vault would
still hold the old password, every subsequent retry would be rejected, and the account would be
permanently locked out of the vault. An administrative reset does not depend on the previous state,
so retries converge.

Practically, this means each target system needs a rotation identity for the daemon to use: a
service principal, an SSH key with sudo rights, a dedicated admin API token, a database role with
`ALTER ROLE` privileges, and so on. That identity is the credential you configure below.

### Secrets on the daemon host

Target credentials live in the daemon's environment, or in its config file for non-secret values.

- Keep the token and target credentials in a root-owned file with mode `0400`, loaded via systemd
  `EnvironmentFile=`.
- Run the daemon as a dedicated unprivileged user.
- Set `script_root` so the daemon will only execute scripts from one directory you control, and make
  that directory non-writable by the daemon user.

---

## Requirements

|                     |                                                                              |
| ------------------- | ---------------------------------------------------------------------------- |
| **Platform**        | Linux (x86-64 or ARM64), macOS (ARM64), or Windows (x86-64).                 |
| **Privileges**      | No root required for the daemon itself. Scripts may need their own.          |
| **Inbound network** | None.                                                                        |
| **Bitwarden**       | Organisation licence active, PAM enabled, daemon registered and not revoked. |

### Outbound network access

| Destination                     | Purpose                                                     |
| ------------------------------- | ----------------------------------------------------------- |
| Your Bitwarden **identity** URL | Authenticate and refresh the daemon session                 |
| Your Bitwarden **API** URL      | Poll, claim, read/write ciphers, report outcomes            |
| `login.microsoftonline.com`     | Token acquisition (Entra targets only)                      |
| `graph.microsoft.com`           | Password reset, verify, session revoke (Entra targets only) |
| Your target systems             | Whatever your scripts and integrations connect to           |

The API endpoints used are all under `/access-connectors/rotation/`:

```
GET   /access-connectors/rotation/jobs
POST  /access-connectors/rotation/jobs/{id}/claim
GET   /access-connectors/rotation/attempts/{id}/cipher
PUT   /access-connectors/rotation/attempts/{id}/cipher
POST  /access-connectors/rotation/attempts/{id}/success
POST  /access-connectors/rotation/attempts/{id}/failure
```

---

## Getting started

### 1. Register the daemon

An organisation admin registers a rotation daemon and receives a daemon token. It looks like this:

```
0.daemon.<api-key-id>.<client-secret>:<encryption-key>
```

The token is shown once. Copy the whole string, including everything after the `:`.

### 2. Install the binary

Place `bw-rotation-daemon` somewhere on the daemon host, for example `/usr/local/bin/`.

### 3. Write a config file

`/etc/bwrd/config.toml`:

```toml
[environment]
base = "https://bitwarden.example.com"

script_root = "/opt/bwrd/scripts"
```

For Bitwarden Cloud, set `api` and `identity` explicitly instead of `base`.

### 4. Supply the token and target credentials

`/etc/bwrd/env` (root-owned, mode `0400`):

```sh
BWRD_TOKEN=0.daemon.…:…
```

See [Per-target credentials](#per-target-credentials) for the target entries that go alongside it.

### 5. Run it

```sh
set -a; . /etc/bwrd/env; set +a
bw-rotation-daemon run --config /etc/bwrd/config.toml
```

You should see:

```
INFO daemon starting api_url=… identity_url=… poll_interval_secs=15 …
INFO session established
```

For a real deployment use the [systemd unit](#systemd) instead.

---

## Configuration reference

### Command line

```
bw-rotation-daemon run [--config <PATH>]
```

There is exactly one subcommand and one flag. Every other setting lives in the config file, so that
settings are reviewable in one place and secrets can never reach `argv`.

| Flag              | Description                                                |
| ----------------- | ---------------------------------------------------------- |
| `--config <PATH>` | Path to the TOML configuration file (or set `BWRD_CONFIG`) |

### Environment variables

| Variable               | Purpose                                                         |
| ---------------------- | --------------------------------------------------------------- |
| `BWRD_TOKEN`           | **Required.** Daemon token. The only accepted way to supply it. |
| `BWRD_CONFIG`          | Path to the config file (equivalent to `--config`)              |
| `BWRD_API_URL`         | Bitwarden API URL; overrides the config file                    |
| `BWRD_IDENTITY_URL`    | Bitwarden identity URL; overrides the config file               |
| `RUST_LOG`             | Log filter; default `info`                                      |
| `<TARGET_ID>_<SUFFIX>` | Per-target credentials (see below)                              |

### Config file

Every key is optional except the server URLs. Unknown keys are a hard startup error, so a typo fails
loudly instead of being silently ignored.

```toml
poll_interval      = 15   # seconds between polls; minimum 15
heartbeat_interval = 30   # seconds; must be < 120
offline_grace      = 60   # seconds a rotation may continue without server contact
max_retry_attempts = 5    # total tries per retryable step, including the first
retry_base_delay   = 1    # seconds; backoff is base * 2^(n-1)
script_timeout     = 60   # seconds before a custom script is killed

script_root = "/opt/bwrd/scripts"   # restrict scripts to this directory (recommended)

powershell_execution_policy = "Bypass"   # see "PowerShell scripts" below
# powershell_path = 'C:\Program Files\PowerShell\7\pwsh.exe'   # else discovered on PATH

entra_verify_probe = false          # see "Microsoft Entra ID" below

[environment]
base = "https://bitwarden.example.com"
# api      = "https://api.bitwarden.com"
# identity = "https://identity.bitwarden.com"

[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/bwrd/scripts/rotate-appliance.sh"
```

#### Setting reference

| Key                           | Default   | Notes                                                                            |
| ----------------------------- | --------- | -------------------------------------------------------------------------------- |
| `poll_interval`               | `15`      | Seconds. Values below 15 are rejected at startup.                                |
| `heartbeat_interval`          | `30`      | Seconds. Must be < 120. Only active during a rotation.                           |
| `offline_grace`               | `60`      | Seconds a rotation may proceed after losing server contact.                      |
| `max_retry_attempts`          | `5`       | Total tries, not extra retries. `5` means 4 backoff sleeps.                      |
| `retry_base_delay`            | `1`       | Seconds. Doubles each retry, capped at 32×.                                      |
| `script_timeout`              | `60`      | Seconds. The script is `SIGKILL`ed at this point.                                |
| `script_root`                 | _(unset)_ | If set, scripts must resolve under this directory.                               |
| `powershell_path`             | _(unset)_ | PowerShell host. Unset discovers `pwsh`, then `powershell.exe`, on `PATH`.       |
| `powershell_execution_policy` | `Bypass`  | `-ExecutionPolicy` for the PowerShell host. Use `AllSigned` if you sign scripts. |
| `entra_verify_probe`          | `false`   | Enables an authoritative Entra verify probe.                                     |

#### URL precedence

Highest to lowest:

1. `BWRD_API_URL` / `BWRD_IDENTITY_URL`
2. `[environment].api` / `[environment].identity`
3. Derived from `[environment].base` as `{base}/api` and `{base}/identity`
4. Startup error naming all three options

---

## Per-target credentials

Each target system needs credentials the daemon can use to authenticate. They are keyed by the
target system UUID, which you can find in the Bitwarden admin console.

### Environment variables

Uppercase the UUID, replace hyphens with underscores, and append the suffix:

```
85808642_BABA_4B8E_8C34_B48000D60A0A_SCRIPT=/opt/bwrd/scripts/rotate.sh
85808642_BABA_4B8E_8C34_B48000D60A0A_API_URL=https://appliance.internal/api
85808642_BABA_4B8E_8C34_B48000D60A0A_ADMIN_TOKEN=…
```

Required suffixes depend on the target kind:

| Kind           | Required suffixes                         |
| -------------- | ----------------------------------------- |
| `Entra`        | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` |
| `CustomScript` | `SCRIPT`                                  |

Any additional variable matching the prefix is collected and passed to the integration. That is how
a custom script receives arbitrary configuration: `…_API_URL` above arrives in the script's input as
`credentials.API_URL`.

### The `[targets]` config section

Non-secret values can live in the config file instead, which is easier to review and version:

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/bwrd/scripts/rotate-appliance.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

Only `script`, `script_type`, `tenant_id`, and `client_id` are accepted. `client_secret` is
deliberately excluded, because config files end up in repositories. Anything else, including any
extra credentials your script needs, must come from the environment.

`script_type` is `direct` or `powershell`, and you rarely need it: a `.ps1` is launched through a
PowerShell host automatically. Set it only for a script whose filename cannot say what it is. See
[PowerShell scripts](#powershell-scripts).

Precedence is per key: a value in `[targets]` wins; otherwise the environment variable is used.
Missing-value errors always name the environment variable, since that is the option that always
works.

### A note on UUIDs starting with a digit

POSIX `/bin/sh` cannot `export` a variable whose name begins with a digit, and most target UUIDs do.
The `[targets]` section sidesteps this for `script`, `script_type`, `tenant_id`, and `client_id`.
For everything else, use a mechanism that does not go through a shell: systemd's `Environment=` and
`EnvironmentFile=` both work, as does Docker's `--env-file`.

---

## Supported target systems

| Kind                 | Status                                                         |
| -------------------- | -------------------------------------------------------------- |
| Microsoft Entra ID   | Supported                                                      |
| Custom script        | Supported                                                      |
| Microsoft SQL Server | Not available in this build; jobs fail with `unsupported_kind` |

### Microsoft Entra ID

Create an app registration (service principal) and grant it these **application** permissions, with
admin consent:

| Permission                           | Used for                                       |
| ------------------------------------ | ---------------------------------------------- |
| `User-PasswordProfile.ReadWrite.All` | Force-resetting the user's password            |
| `User.Read.All`                      | Reading `lastPasswordChangeDateTime` to verify |
| `User.RevokeSessions.All`            | Revoking active sessions                       |

The service principal must not be outranked by the accounts it rotates, because Entra refuses
password resets on users holding a higher-privileged directory role.

Configure it with `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` (the secret via environment variable
only).

**Verification.** By default the daemon verifies by reading the user's `lastPasswordChangeDateTime`
from Microsoft Graph and checking it is newer than the rotation start. This is subject to directory
replication lag.

Setting `entra_verify_probe = true` additionally attempts to sign in as the rotated user with the
new password, which is authoritative and immune to replication lag. It is off by default because
Conditional Access policies block this style of sign-in in most production tenants. Enable it only
if you know the rotated accounts are exempt.

### Custom script

For everything else (Linux and Windows servers, network appliances, databases, SaaS admin APIs),
write a script. See the next section.

A `.ps1` is run through a PowerShell host automatically, so a Windows target can be rotated with
PowerShell directly rather than through a wrapper executable. See
[PowerShell scripts](#powershell-scripts).

---

## Writing a custom rotation script

The daemon runs your executable once per operation and communicates entirely through argv (the
operation name), stdin (JSON), and the exit code.

### The contract

|                     |                                                             |
| ------------------- | ----------------------------------------------------------- |
| **argv**            | Exactly one argument: `rotate`, `verify`, or `terminate`    |
| **stdin**           | One JSON document, then EOF                                 |
| **environment**     | **Empty.** No `PATH`, no `HOME`, no daemon token            |
| **stdout / stderr** | Both redirected to `/dev/null`                              |
| **exit code**       | The only output channel                                     |
| **timeout**         | `SIGKILL` at `script_timeout` seconds; no cleanup trap runs |

The three operations are separate process invocations of the same script:

| Operation   | When                                                         |
| ----------- | ------------------------------------------------------------ |
| `rotate`    | After the new password is generated                          |
| `verify`    | After `rotate` succeeds. Mandatory, no opt-out               |
| `terminate` | After `verify`, only if the job requests session termination |

### Input

```json
{
  "operation": "rotate",
  "targetSystemId": "85808642-baba-4b8e-8c34-b48000d60a0a",
  "accountIdentity": "svc-backup@corp.example.com",
  "newPassword": "hK9$mQ2vTx8pLw4nZr6E",
  "credentials": {
    "API_URL": "https://appliance.internal/api",
    "ADMIN_TOKEN": "…"
  }
}
```

- `newPassword` is absent for `terminate`. The script has no use for it, and withholding it prevents
  accidental logging.
- `credentials` holds every resolved suffix for this target except `SCRIPT`.
- The account's _current_ password is never included. Your script must perform an administrative
  reset.
- Field names are camelCase.

### Exit codes

The exit code tells the daemon two things: whether to retry, and whether the target system was
changed. If the second is wrong, the vault and the target diverge and nothing flags it.

| Code  | Retry?  | Target state                       | Use when                                        |
| ----- | ------- | ---------------------------------- | ----------------------------------------------- |
| `0`   | —       | —                                  | Success                                         |
| `1`   | No      | Unchanged                          | Rejected before anything was modified           |
| `2`   | No      | **Updated**                        | The password was set, but a later step failed   |
| `3`   | No      | Unknown                            | You cannot tell whether it applied              |
| `4`   | **Yes** | Unchanged                          | Network blip, rate limit, 5xx; a retry may work |
| other | No      | `rotate` → unknown; else unchanged | Unexpected                                      |

On timeout the daemon assumes conservatively: `rotate` → unknown, `verify` → applied, `terminate` →
unchanged.

### Example

```sh
#!/bin/sh
# Rotate a service account on an appliance admin API.
set -eu

# The daemon clears the environment, so PATH is only your shell's compiled-in
# default. Set it explicitly, or use absolute paths for every tool.
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

operation="$1"
payload="$(cat)"          # one JSON document, then EOF

field() { printf '%s' "$payload" | jq -r "$1 // empty"; }

account="$(field '.accountIdentity')"
api="$(field '.credentials.API_URL')"
token="$(field '.credentials.ADMIN_TOKEN')"
new_password="$(field '.newPassword')"   # empty for terminate

# Keep secrets off argv: the token goes in a header file, the body via stdin.
hdr="$(mktemp)"; trap 'rm -f "$hdr"' EXIT
printf 'Authorization: Bearer %s\n' "$token" > "$hdr"

call() {  # call METHOD PATH [send-body-from-stdin]
    curl -sS -o /dev/null -w '%{http_code}' \
        -X "$1" -H @"$hdr" -H 'Content-Type: application/json' \
        ${3:+--data @-} "$api$2" 2>/dev/null || echo 000
}

case "$operation" in
  rotate)
    # Administrative reset, NOT a change-password call.
    body="$(jq -nc --arg p "$new_password" '{password: $p, mustChange: false}')"
    status="$(printf '%s' "$body" | call PUT "/users/$account/password" body)"
    case "$status" in
      2??)     exit 0 ;;   # applied
      000|5??) exit 4 ;;   # transient; retry may succeed
      409)     exit 3 ;;   # ambiguous
      *)       exit 1 ;;   # 4xx: rejected, target unchanged
    esac
    ;;

  verify)
    # Round-trip: authenticate as the account with the new password.
    body="$(jq -nc --arg u "$account" --arg p "$new_password" \
              '{username: $u, password: $p}')"
    status="$(printf '%s' "$body" | call POST "/auth/token" body)"
    case "$status" in
      2??)     exit 0 ;;
      000|5??) exit 4 ;;
      *)       exit 1 ;;   # rotate claimed success but the password does not work
    esac
    ;;

  terminate)
    status="$(call DELETE "/users/$account/sessions")"
    case "$status" in
      2??|404) exit 0 ;;
      000|5??) exit 4 ;;
      *)       exit 1 ;;
    esac
    ;;

  *) exit 1 ;;
esac
```

### Checklist

- [ ] The file is executable and has a shebang, or it is a `.ps1` (see
      [PowerShell scripts](#powershell-scripts)). `SCRIPT` must be a path, not a command line with
      arguments.
- [ ] `PATH` is set explicitly, or every external tool is called by absolute path.
- [ ] `rotate` performs an administrative reset and never needs the old password.
- [ ] Running `rotate` twice with the same password succeeds, because in-attempt retries reuse it.
- [ ] `verify` does a real check. If you cannot authenticate as the account, check a last-changed
      timestamp or equivalent; do not just `exit 0`.
- [ ] Secrets stay off `argv` inside the script too; use stdin, files, or headers.
- [ ] No `set -x`, and nothing writes `newPassword` to a log file.
- [ ] The script finishes well within `script_timeout`.

Minimal reference scripts live in `tests/fixtures/`, in both shell and PowerShell. `copy_stdin.sh`
and `copy_stdin.ps1` are useful during development: point a test target at one and it will dump a
real payload to a file.

---

## PowerShell scripts

A `.ps1` is not an executable, so the daemon launches a PowerShell host to run it. Nothing else
changes. The contract in [Writing a custom rotation script](#writing-a-custom-rotation-script)
applies exactly as written: the stdin payload, the exit codes, the timeout, `script_root`.

### When PowerShell is used

The file decides rather than the operating system. A `.ps1` is launched through a host; anything
else is executed directly, as before. So a PowerShell script rotates from a Linux daemon running
PowerShell 7, and a native `.exe` target on Windows is unaffected.

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = 'C:\bwrd\rotate-sqlsa.ps1'          # no other configuration needed
```

Set `script_type` only when the filename cannot say what the file is:

```toml
[targets.00000000-0000-0000-0000-000000000003]
script      = "/opt/bwrd/rotate-appliance"   # no extension
script_type = "powershell"
```

`script_type` accepts `direct` or `powershell`. A value that is neither fails the rotation rather
than falling back.

### Which host is used

In order: `powershell_path` from the config file, then `pwsh` / `pwsh.exe` on `PATH`, then
`powershell.exe`. PowerShell 7 is preferred over Windows PowerShell 5.1.

A `powershell_path` you set is used exactly as given and never quietly replaced by a discovered
host. If no host is found at all the rotation fails with `credentials_unresolved`; the daemon still
starts, so a machine without PowerShell can serve its other targets.

The host is invoked as:

```
<host> -NoProfile -NonInteractive -ExecutionPolicy <policy> -File <script> <operation>
```

Windows PowerShell 5.1 requires a `.ps1` extension for `-File`, so forcing `script_type` on an
extensionless script works only under `pwsh`.

### Execution policy

`powershell_execution_policy` defaults to `Bypass`, because Windows Server ships `RemoteSigned` and
will refuse to run an unsigned `.ps1`; the first rotation on a new host would otherwise fail with
nothing but `exit code 1`. The script is one you installed at a path already pinned by
`script_root`, so the policy check is largely redundant here. If you sign your rotation scripts, set
`AllSigned`.

### What the script inherits

A directly executed script gets an empty environment. A PowerShell host cannot start that way, so it
receives a fixed allowlist instead: `SystemRoot`, `windir`, `PATH`, `PATHEXT`, `COMSPEC`,
`PSModulePath`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMDATA`, `APPDATA`, `LOCALAPPDATA`,
`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `TEMP`, `TMP`, and on Unix `HOME`, `TMPDIR`, `LANG`.

Nothing else crosses. The daemon token, every target credential, and the new password are all absent
from the child environment; secrets still arrive only in the stdin payload.

### Getting the exit code right

The exit code is what tells Bitwarden whether the target changed, and PowerShell's defaults work
against you in two specific ways.

**Always set `$ErrorActionPreference = 'Stop'` as the first line.** The default is `Continue`: a
cmdlet that fails writes an error record and execution carries on to your `exit 0`. A rotation that
failed would be reported as a success, and the vault would then hold a password the target never
accepted.

**Exit 2, not 1, if anything fails after the password was already reset.** An uncaught exception
exits 1, and 1 means "target unchanged". If the reset succeeded and a later step threw, the target
has changed, and saying otherwise leaves the vault out of sync with it:

```powershell
Reset-MyAccountPassword -Identity $account -NewPassword $password
try {
    Confirm-MyReset -Identity $account
} catch {
    exit 2      # the target was updated, we just could not finish
}
```

Use exit 4 for anything a retry might fix: throttling, a timeout, an endpoint that was briefly
unreachable.

### Example

```powershell
# rotate.ps1, invoked as: rotate.ps1 <rotate|verify|terminate>
param([Parameter(Mandatory)][string]$Operation)

$ErrorActionPreference = 'Stop'

$payload  = [Console]::In.ReadToEnd() | ConvertFrom-Json
$account  = $payload.accountIdentity
$password = $payload.newPassword          # absent for 'terminate'

switch ($Operation) {
    'rotate' {
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

---

## Running in production

### systemd

`/etc/systemd/system/bw-rotation-daemon.service`:

```ini
[Unit]
Description=Bitwarden PAM rotation daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bwrd
Group=bwrd

EnvironmentFile=/etc/bwrd/env
ExecStart=/usr/local/bin/bw-rotation-daemon run --config /etc/bwrd/config.toml

Restart=always
RestartSec=10s

# Hardening. Review each line against what your scripts need.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/bwrd
RestrictSUIDSGID=yes
# NoNewPrivileges=yes   # omit if your scripts use sudo

[Install]
WantedBy=multi-user.target
```

`/etc/bwrd/env` holds `BWRD_TOKEN` and all per-target credentials, owned by root with mode `0400`.
Because systemd sets these directly rather than through a shell, target UUIDs beginning with a digit
are not a problem here.

### Shutdown and restarts

`SIGTERM` and Ctrl-C trigger a graceful shutdown: the daemon stops claiming new work, closes its
session, and exits `0`. A rotation interrupted mid-flight is abandoned without a report; the server
handles the unreported attempt on its side. Prefer restarting between rotations where you can. The
logs make it obvious when one is in progress.

### Running several daemons

Run as many as you need. They share nothing and race safely for jobs. Give each one only the target
credentials it needs, which also limits what a single compromised host exposes.

---

## Observability

Logs go to stderr, filtered by `RUST_LOG` (default `info`):

```sh
RUST_LOG=debug bw-rotation-daemon run --config /etc/bwrd/config.toml
RUST_LOG=bitwarden_rotation_daemon=trace,info bw-rotation-daemon run --config /etc/bwrd/config.toml
```

At `info` you get one line per lifecycle milestone. At `debug` you additionally get poll ticks,
heartbeats, lost claim races, and per-substep detail.

| Level   | Event                                              | Key fields                                                                 |
| ------- | -------------------------------------------------- | -------------------------------------------------------------------------- |
| `info`  | Daemon starting                                    | `api_url`, `identity_url`, `poll_interval_secs`, `heartbeat_interval_secs` |
| `info`  | Session established / renewed                      | `retry`                                                                    |
| `info`  | Rotation job claimed                               | `job_id`, `target_system_name`                                             |
| `info`  | Starting rotation execution                        | `attempt_id`, `job_id`, `cipher_id`, `target_system_name`                  |
| `info`  | Steps 1–7 completed                                | `attempt_id`, plus `kind` / `cipher_id` / `termination`                    |
| `info`  | Shutdown signal received; daemon shut down cleanly | —                                                                          |
| `warn`  | Session renewal failed                             | `retry`, `sleep_ms`                                                        |
| `warn`  | Session revoked                                    | —                                                                          |
| `warn`  | **Rotation failed**                                | `attempt_id`, `failure_code`, `sync_state`, `detail`                       |
| `warn`  | Session termination aborted or failed              | `attempt_id`, `abort_reason`                                               |
| `warn`  | Transient poll error / backoff                     | backoff duration                                                           |
| `error` | Daemon credential refused                          | —                                                                          |
| `error` | Daemon not eligible for rotation endpoints         | —                                                                          |

Log output contains no secrets by construction: only identifiers, status codes, exit codes, and
variable names.

### Exit codes

| Code | Meaning                                                    | What to do                                                                             |
| ---- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `0`  | Clean shutdown                                             | Nothing                                                                                |
| `1`  | Startup error (bad config, unreadable file, missing token) | Fix the config; the log line names the problem                                         |
| `2`  | Daemon credential refused                                  | Have an admin reissue the credential, then restart with the new token                  |
| `3`  | Not eligible for rotation endpoints                        | Check the daemon is not revoked or disabled, the licence is active, and PAM is enabled |

`Restart=always` is safe: codes `2` and `3` need human action, and the daemon will keep restarting
and re-logging the reason until someone fixes it.

---

## Troubleshooting

### The daemon will not start

| Log message                                                             | Cause                                                             |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `daemon token must be supplied via the BWRD_TOKEN environment variable` | `BWRD_TOKEN` unset or empty                                       |
| `Has the wrong number of parts` / `Has the wrong prefix`                | Token truncated on copy; it must include everything after the `:` |
| `api URL must be supplied via …`                                        | No `base`, no `api`, no `BWRD_API_URL`                            |
| `config file … is invalid TOML: unknown field`                          | A typo, or `client_secret` inside a `[targets]` block             |
| `poll_interval must be >= 15 seconds`                                   | Value below the floor                                             |

### The daemon runs but nothing is rotated

Raise the level to `RUST_LOG=debug` and look at the poll ticks. `claimable_jobs=0` every tick means
the server has no work. Check the rotation schedule on the target system in the admin console.
Frequent `claim race lost (409)` means another daemon is picking up the work first, which is normal
with several daemons running.

### Rotations fail

Every failure is logged at `warn` with a `failure_code` and a `sync_state`, and the same pair is
recorded server-side.

| `failure_code`           | Meaning                                                                                          | Where to look                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| `credentials_unresolved` | A required variable is missing, or the script path does not exist or falls outside `script_root` | The `detail` field names the variable or the reason           |
| `unsupported_kind`       | This build has no driver for that target kind                                                    | See [Supported target systems](#supported-target-systems)     |
| `target_rejected`        | The target system refused the reset                                                              | Permissions on the rotation identity; role hierarchy in Entra |
| `target_unreachable`     | Network failure reaching the target                                                              | Firewall, DNS, TLS from the daemon host                       |
| `verification_failed`    | The reset reported success but verification did not confirm it                                   | Replication lag, or a `rotate` that silently no-ops           |
| `script_failed`          | Your script exited non-zero                                                                      | The `detail` field carries the exit code                      |
| `script_timeout`         | The script exceeded `script_timeout`                                                             | Raise the timeout, or make the script faster                  |
| `cipher_write_rejected`  | The vault entry changed underneath the daemon                                                    | Usually resolves on the next attempt                          |
| `invalid_policy`         | The password policy cannot be satisfied                                                          | Review the policy on the target system                        |

The accompanying `sync_state` tells you the blast radius:

- `target_unchanged`: nothing happened; safe.
- `target_updated`: the target has a new password the vault does not have. Needs attention.
- `indeterminate`: unknown. Verify manually.

### Script debugging

Because stdout and stderr are discarded, a script cannot print its way out of a problem. Have it
write to a log file instead, never logging `newPassword`, or point the target temporarily at
`tests/fixtures/copy_stdin.sh` to capture a real payload.

The most common script failure is a missing `PATH`: the daemon clears the environment, so tools in
`/usr/local/bin` or `/opt/homebrew/bin` are not found unless you say where they are.

For a PowerShell script, `script_failed` with `exit code 1` and no other detail is usually a
host-level failure that happened before your code ran: an execution-policy block, an unsigned
script, a syntax error, or a module that would not load. None of those can reach the failure report,
because the host writes them to stderr. Reproduce it by hand as the account the daemon runs under,
which also reproduces the environment allowlist:

```
runas /user:svc_bwrd "pwsh -NoProfile -NonInteractive -File C:\bwrd\rotate-sqlsa.ps1 rotate"
```

---

## Development

Internal notes for working on the crate itself.

```sh
# Build and test
cargo test -p bitwarden-rotation-daemon --all-features
cargo check --all-features --all-targets

# Run against a local server
BWRD_TOKEN="…" cargo run -p bitwarden-rotation-daemon -- run \
  --config bitwarden_license/bitwarden-rotation-daemon/dev-config.toml
```

`dev-config.toml` points at the dev proxy on `https://localhost:8080`.

### Test-only registration helper

Until the admin console flow ships, `examples/register.rs` generates a registration payload and
token template locally. It handles a plaintext organisation key and is **not for production use**:

```sh
export BWRD_ORG_KEY_B64="<base64 org key>"
cargo run -p bitwarden-rotation-daemon --example register -- --name my-daemon
```

### References

- [SDK architecture](https://contributing.bitwarden.com/architecture/sdk/)
- [Security definitions](https://contributing.bitwarden.com/architecture/security/definitions)
