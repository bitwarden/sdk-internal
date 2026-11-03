# Bitwarden Access Connector

`bwac` rotates the passwords of privileged accounts, such as domain admins, service accounts,
appliance root logins and database roles, and saves each new password to your Bitwarden organization
vault.

It runs on your own network. The Bitwarden server decides what to rotate and when, and the connector
does the rotating, since only it can reach your systems. The server never sees a plaintext password.

The access connector is a commercial feature. It needs an active organization license with PAM
enabled.

For the security model and hardening advice, see [SECURITY.md](SECURITY.md).

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Target credentials](#target-credentials)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Custom scripts](#custom-scripts)
- [PowerShell scripts](#powershell-scripts)
- [Running in production](#running-in-production)
- [Logs and exit codes](#logs-and-exit-codes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## How it works

The connector only makes outbound connections and doesn't listen on any port. Run it somewhere that
can reach both your target systems and Bitwarden.

```
   your network                                  Bitwarden server
  ┌──────────────────────────┐                  ┌──────────────────┐
  │  bwac                    │  ── poll ──────▶ │  rotation jobs   │
  │    │                     │  ◀─ job ───────  │                  │
  │    │ rotate              │  ── cipher ────▶ │  org vault       │
  │    ▼                     │  ── report ────▶ │  audit log       │
  │  target systems          │                  └──────────────────┘
  │  (Entra, servers, DBs…)  │
  └──────────────────────────┘
```

Every `poll_interval` seconds (15 by default), the connector asks the server for jobs and tries to
claim one. It first checks that the vault item can be updated, then runs the rotation:

1. Look up the credentials for the target system.
2. Generate a password using the policy set on the target system in Bitwarden.
3. Reset the account's password on the target system.
4. Verify the new password took effect.
5. Encrypt the new password and save it to the vault item.
6. End the account's active sessions, if the job asks for it. A failure here doesn't fail the
   rotation.
7. Report the result to the server.

Temporary failures, such as a network error or rate limit, are retried with exponential backoff, up
to `max_retry_attempts` tries in total. Before each attempt at a step that touches the target, the
connector checks that it still has a valid session and that the job's time window hasn't closed. The
vault write and the report aren't bound by that window, so a rotation that changed the target is
always recorded.

A connector runs one rotation at a time. To rotate more accounts in parallel, run more connectors.
If two connectors try to claim the same job, one gets it and the other moves on. You can also put
connectors in different network segments to reach targets that no single host can reach. Each one
only needs credentials for its own targets.

## Requirements

- Linux (x86-64 or ARM64), macOS (ARM64) or Windows (x86-64).
- No root access for the connector itself. Your scripts may need their own privileges.
- No inbound network access.
- A registered access connector that hasn't been revoked, in an organization with an active license
  and PAM enabled.

The connector needs outbound access to:

| Destination                 | Used for                                              |
| --------------------------- | ----------------------------------------------------- |
| Your Bitwarden identity URL | Signing in and renewing the connector's session       |
| Your Bitwarden API URL      | Fetching and claiming jobs, the vault item, reporting |
| `login.microsoftonline.com` | Getting Graph tokens (Entra targets only)             |
| `graph.microsoft.com`       | Resetting passwords and ending sessions (Entra only)  |
| Your target systems         | Whatever your scripts connect to                      |

## Getting started

### 1. Register the connector

An organization admin registers an access connector in the Admin Console and gets a token that looks
like this:

```
0.access-connector.<api-key-id>.<client-secret>:<encryption-key>
```

The token is only shown once. Copy all of it, including the part after the `:`.

### 2. Install the binary

Copy `bwac` to the connector host, for example to `/usr/local/bin/`.

### 3. Write a config file

Create `/etc/bwac/config.toml`:

```toml
script_root = "/opt/bwac/scripts"

[environment]
base = "https://bitwarden.com"
```

Set `base` to your server's URL if you self-host. For the EU cloud, set it to
`https://bitwarden.eu`. For the US cloud, you can leave `[environment]` out.

### 4. Add the token and target credentials

Create `/etc/bwac/env`, owned by root with mode `0400`:

```sh
BWAC_TOKEN=0.access-connector.…:…
```

Target credentials go in the same file. See [Target credentials](#target-credentials).

### 5. Run it

```sh
set -a; . /etc/bwac/env; set +a
bwac run --config /etc/bwac/config.toml
```

You should see:

```
INFO access connector starting api_url=… identity_url=… poll_interval_secs=15 …
INFO session authenticated
```

This is fine for a first test, but a shell can't load variables whose names start with a digit,
which most target credentials have. For a real deployment, use the [systemd unit](#systemd).

## Configuration

| Command                    | Description                                       |
| -------------------------- | ------------------------------------------------- |
| `bwac run`                 | Start the connector                               |
| `bwac run --config <PATH>` | Use this config file. `BWAC_CONFIG` does the same |
| `bwac --version`           | Print the version                                 |
| `bwac --help`              | Print help                                        |

Everything else is set in the config file or the environment.

### Environment variables

| Variable               | Purpose                                                           |
| ---------------------- | ----------------------------------------------------------------- |
| `BWAC_TOKEN`           | Required. The access connector token                              |
| `BWAC_CONFIG`          | Path to the config file                                           |
| `BWAC_API_URL`         | Bitwarden API URL. Overrides the config file                      |
| `BWAC_IDENTITY_URL`    | Bitwarden identity URL. Overrides the config file                 |
| `RUST_LOG`             | Log filter. Defaults to `info`                                    |
| `<TARGET_ID>_<SUFFIX>` | Target credentials. See [Target credentials](#target-credentials) |

The token can only be set with `BWAC_TOKEN`. A `token` key in the config file fails at startup.

### Config file

Every key is optional. Unknown keys fail at startup, so a typo doesn't go unnoticed.

```toml
poll_interval      = 15   # seconds between polls
heartbeat_interval = 30   # seconds
offline_grace      = 60   # seconds
max_retry_attempts = 5    # tries per retryable step
retry_base_delay   = 1    # seconds
script_timeout     = 60   # seconds

script_root = "/opt/bwac/scripts"

powershell_execution_policy = "Bypass"
# powershell_path = 'C:\Program Files\PowerShell\7\pwsh.exe'

entra_verify_probe = false

[environment]
base = "https://bitwarden.example.com"
# api      = "https://api.bitwarden.com"
# identity = "https://identity.bitwarden.com"

[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/bwac/scripts/rotate-appliance.sh"
```

| Key                           | Default  | Notes                                                                                          |
| ----------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `poll_interval`               | `15`     | Seconds between polls. The minimum is 15.                                                      |
| `heartbeat_interval`          | `30`     | Seconds between heartbeats during a rotation. Must be between 1 and 119.                       |
| `offline_grace`               | `60`     | Seconds a rotation can continue without reaching the server. Must be at least 1.               |
| `max_retry_attempts`          | `5`      | Tries per retryable step, including the first. `5` means up to 4 retries.                      |
| `retry_base_delay`            | `1`      | Seconds before the first retry. Doubles with each retry, up to 32 times the base.              |
| `script_timeout`              | `60`     | Seconds before a script is killed. Must be at least 1.                                         |
| `script_root`                 | none     | If set, scripts must be inside this directory. Recommended.                                    |
| `powershell_path`             | none     | PowerShell host to use. If unset, `pwsh` and then `powershell.exe` are looked up on `PATH`.    |
| `powershell_execution_policy` | `Bypass` | Passed to the PowerShell host as `-ExecutionPolicy`. Use `AllSigned` if you sign your scripts. |
| `entra_verify_probe`          | `false`  | Also verify Entra rotations by signing in. See [Verification](#verification).                  |

The API and identity URLs are each taken from the first of these that is set:

1. `BWAC_API_URL` and `BWAC_IDENTITY_URL`
2. `api` and `identity` in `[environment]`
3. `base` in `[environment]`

A `base` of `https://bitwarden.com` or `https://vault.bitwarden.com` means the US cloud, and
`https://bitwarden.eu` or `https://vault.bitwarden.eu` means the EU cloud. Any other `base` is
treated as a self-hosted server, with the URLs `{base}/api` and `{base}/identity`.

If none of these is set, the connector uses the US cloud. If only some are set and one URL is still
missing, for example `api` without `identity`, the connector fails at startup.

## Target credentials

Each target system needs credentials the connector can use to reset passwords on it. They're keyed
by the target system's UUID, which is shown in the Admin Console.

The connector supports Microsoft Entra ID and custom script targets. Other target kinds, such as
Microsoft SQL Server, aren't available in this build and fail with `unsupported_kind`.

### Environment variables

Take the UUID, make it uppercase, replace the hyphens with underscores, and add `_` and a suffix:

```
85808642_BABA_4B8E_8C34_B48000D60A0A_SCRIPT=/opt/bwac/scripts/rotate.sh
85808642_BABA_4B8E_8C34_B48000D60A0A_API_URL=https://appliance.internal/api
85808642_BABA_4B8E_8C34_B48000D60A0A_ADMIN_TOKEN=…
```

| Target kind   | Required suffixes                         |
| ------------- | ----------------------------------------- |
| Entra         | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` |
| Custom script | `SCRIPT`                                  |

Any other variable with the same prefix is passed to the integration. That's how a script gets its
own settings: `…_API_URL` above reaches the script as `credentials.API_URL`.

If a required value is missing, the rotation fails with `credentials_unresolved` and the error names
the environment variable to set.

### The `[targets]` section

Values that aren't secret can go in the config file instead:

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/bwac/scripts/rotate-appliance.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

Only `script`, `script_type`, `tenant_id` and `client_id` are accepted here. Everything else,
including `client_secret` and any extra values your script needs, has to come from the environment.
If a key is set in both places, the `[targets]` value wins.

`script_type` is only needed for scripts whose file extension doesn't say how to run them. See
[PowerShell scripts](#powershell-scripts).

### UUIDs that start with a digit

A POSIX shell can't `export` a variable whose name starts with a digit, and most target UUIDs do.
The `[targets]` section avoids this for the four keys it accepts. For everything else, load the
variables without going through a shell: systemd's `Environment=` and `EnvironmentFile=` both work,
as does Docker's `--env-file`.

## Microsoft Entra ID

The connector resets Entra passwords through Microsoft Graph, signing in as a service principal.

Create an app registration and grant it these application permissions, with admin consent:

| Permission                           | Used for                                       |
| ------------------------------------ | ---------------------------------------------- |
| `User-PasswordProfile.ReadWrite.All` | Resetting the user's password                  |
| `User.Read.All`                      | Reading `lastPasswordChangeDateTime` to verify |
| `User.RevokeSessions.All`            | Ending the user's sessions                     |

Entra won't let the service principal reset a user who holds a higher-privileged directory role. To
limit which accounts it can reach, see
[Scope the target credentials](SECURITY.md#scope-the-target-credentials).

Set `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` for the target. `CLIENT_SECRET` can only come from
the environment.

The account identity on the target system is the user's object ID or user principal name. The user
isn't asked to change the password at next sign-in.

### Verification

The connector reads the user's `lastPasswordChangeDateTime` from Graph and checks that it's no older
than the start of the rotation, allowing five minutes for clock differences. It checks every 5
seconds for up to 60 seconds, to allow for replication delay, and fails with `verification_failed`
if the timestamp doesn't update.

With `entra_verify_probe = true`, the connector first tries to sign in as the user with the new
password. A successful sign-in or an MFA prompt counts as verified, and a wrong-password response
fails verification. Any other response falls back to the timestamp check. The probe is off by
default because MFA or Conditional Access blocks this kind of sign-in in most tenants.

## Custom scripts

For anything else, such as Linux and Windows servers, network appliances, databases or SaaS admin
APIs, write a script.

The connector runs the script once per operation. It passes the operation name as the only argument,
writes a JSON document to stdin, and reads the result from the exit code:

| Operation   | When it runs                                    |
| ----------- | ----------------------------------------------- |
| `rotate`    | After the new password is generated             |
| `verify`    | After `rotate` succeeds. Always runs            |
| `terminate` | After `verify`, if the job asks to end sessions |

The script runs with:

- an empty environment, with no `PATH` or `HOME`
- stdout and stderr discarded
- a time limit of `script_timeout` seconds, after which it's killed without a chance to clean up

`SCRIPT` must be the path to a single file, with no arguments. The file must be executable with a
shebang line, or a `.ps1` file.

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

- `newPassword` isn't included for `terminate`.
- `credentials` has every value configured for the target except `SCRIPT` and `SCRIPT_TYPE`.
- The account's current password is never included. The script has to reset the password as an admin
  rather than change it. See
  [Rotation is an administrative reset](SECURITY.md#rotation-is-an-administrative-reset).
- `accountIdentity` is untrusted input. Don't put it unescaped into a shell command, SQL query or
  API path.

### Exit codes

The exit code tells the connector whether to retry and whether the target's password changed. If it
reports the wrong state, the vault and the target can end up with different passwords and nothing
will flag it.

| Code   | Retried | Target password                      | Use when                                            |
| ------ | ------- | ------------------------------------ | --------------------------------------------------- |
| `0`    |         |                                      | The operation succeeded                             |
| `1`    | No      | Unchanged                            | It was rejected before anything changed             |
| `2`    | No      | Changed                              | The password was set, then a later step failed      |
| `3`    | No      | Unknown                              | You can't tell whether it was set                   |
| `4`    | Yes     | Unchanged                            | A retry might work: network error, rate limit, 5xx  |
| other  | No      | Unknown for `rotate`, else unchanged | Anything unexpected                                 |
| signal | No      | Unknown for `rotate`, else unchanged | The script was killed. The failure names the signal |

If the script times out, the connector assumes the password state is unknown for `rotate`, changed
for `verify`, and unchanged for `terminate`.

### Example

```sh
#!/bin/sh
# Rotate a service account on an appliance admin API.
set -eu

# The environment is empty, so set PATH or use absolute paths.
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

operation="$1"
payload="$(cat)"

field() { printf '%s' "$payload" | jq -r "$1 // empty"; }

account="$(field '.accountIdentity')"
api="$(field '.credentials.API_URL')"
token="$(field '.credentials.ADMIN_TOKEN')"
new_password="$(field '.newPassword')"   # empty for terminate

# Keep secrets out of curl's arguments: the token goes in a header file, the body on stdin.
hdr="$(mktemp)"; trap 'rm -f "$hdr"' EXIT
printf 'Authorization: Bearer %s\n' "$token" > "$hdr"

call() {  # call METHOD PATH [send-body-from-stdin]
    curl -sS -o /dev/null -w '%{http_code}' \
        -X "$1" -H @"$hdr" -H 'Content-Type: application/json' \
        ${3:+--data @-} "$api$2" 2>/dev/null || echo 000
}

case "$operation" in
  rotate)
    # An admin reset, which doesn't need the current password.
    body="$(jq -nc --arg p "$new_password" '{password: $p, mustChange: false}')"
    status="$(printf '%s' "$body" | call PUT "/users/$account/password" body)"
    case "$status" in
      2??)     exit 0 ;;
      000|5??) exit 4 ;;   # try again
      409)     exit 3 ;;   # unclear whether it applied
      *)       exit 1 ;;   # rejected, nothing changed
    esac
    ;;

  verify)
    # Sign in as the account with the new password.
    body="$(jq -nc --arg u "$account" --arg p "$new_password" \
              '{username: $u, password: $p}')"
    status="$(printf '%s' "$body" | call POST "/auth/token" body)"
    case "$status" in
      2??)     exit 0 ;;
      000|5??) exit 4 ;;
      *)       exit 1 ;;
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

- [ ] `PATH` is set, or every tool is called by its full path.
- [ ] `rotate` resets the password without needing the current one.
- [ ] Running `rotate` twice with the same password succeeds. Retries reuse the password.
- [ ] `verify` really checks. If you can't sign in as the account, check a last-changed timestamp or
      similar.
- [ ] Secrets aren't passed as command-line arguments inside the script either.
- [ ] Nothing logs `newPassword`, and there's no `set -x`.
- [ ] The script finishes well within `script_timeout`.

There are minimal shell and PowerShell examples in `scripts/examples/`.

## PowerShell scripts

A `.ps1` script runs through a PowerShell host. Everything in [Custom scripts](#custom-scripts)
still applies.

The file extension decides how a script runs, not the operating system. A `.ps1` runs through
PowerShell, including on Linux or macOS with PowerShell 7, and anything else runs directly. No extra
configuration is needed:

```toml
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = 'C:\bwac\rotate-sqlsa.ps1'
```

If the extension doesn't match how the script should run, set `script_type` to `powershell` or
`direct`:

```toml
[targets.00000000-0000-0000-0000-000000000003]
script      = "/opt/bwac/rotate-appliance"
script_type = "powershell"
```

Any other `script_type` value fails the rotation. Windows PowerShell 5.1 can only run files ending
in `.ps1`, so an extensionless PowerShell script needs `pwsh`.

### Which host runs it

The connector uses `powershell_path` if it's set. Otherwise it looks for `pwsh` on `PATH`, then
`powershell.exe`. If `powershell_path` is set but wrong, the rotation fails rather than falling back
to another host. If there's no host at all, PowerShell rotations fail with `credentials_unresolved`,
but the connector still runs your other targets.

The host is started as:

```
<host> -NoProfile -NonInteractive -ExecutionPolicy <policy> -File <script> <operation>
```

`powershell_execution_policy` defaults to `Bypass`. Windows Server defaults to `RemoteSigned`, which
won't run unsigned scripts, and the rotation would fail with just `exit code 1`. If you sign your
scripts, set it to `AllSigned`.

### What the script inherits

A PowerShell host can't start with an empty environment, so it gets these variables from the
connector's environment, where set: `SystemRoot`, `windir`, `PATH`, `PATHEXT`, `COMSPEC`,
`PSModulePath`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMDATA`, `APPDATA`, `LOCALAPPDATA`,
`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `TEMP`, `TMP`, `HOME`, `TMPDIR` and `LANG`. Nothing else is
passed, and secrets still only arrive on stdin.

### Getting the exit code right

Set `$ErrorActionPreference = 'Stop'` at the top of the script. With the default, `Continue`, a
failing cmdlet writes an error and the script carries on to `exit 0`. The connector would record a
failed rotation as a success.

An uncaught exception exits with `1`, which tells the connector the password didn't change. If the
reset succeeded and something after it fails, exit with `2` instead:

```powershell
Reset-MyAccountPassword -Identity $account -NewPassword $password
try {
    Confirm-MyReset -Identity $account
} catch {
    exit 2      # the password was changed
}
```

Exit with `4` for anything worth retrying, such as throttling, a timeout, or an endpoint that's
briefly unreachable.

### Example

```powershell
# rotate.ps1 <rotate|verify|terminate>
param([Parameter(Mandatory)][string]$Operation)

$ErrorActionPreference = 'Stop'

$payload  = [Console]::In.ReadToEnd() | ConvertFrom-Json
$account  = $payload.accountIdentity
$password = $payload.newPassword          # not set for 'terminate'

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

## Running in production

### systemd

Create `/etc/systemd/system/bwac.service`:

```ini
[Unit]
Description=Bitwarden PAM access connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bwac
Group=bwac

EnvironmentFile=/etc/bwac/env
ExecStart=/usr/local/bin/bwac run --config /etc/bwac/config.toml

Restart=always
RestartSec=10s

# Hardening. Check each line against what your scripts need.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# ReadWritePaths=/var/lib/bwac   # only if your scripts write there
RestrictSUIDSGID=yes
# NoNewPrivileges=yes            # leave out if your scripts use sudo

[Install]
WantedBy=multi-user.target
```

`/etc/bwac/env` holds `BWAC_TOKEN` and the target credentials, owned by root with mode `0400`.
systemd reads it directly, so variable names starting with a digit work.

`Restart=always` is fine to use. If the token is refused or the connector isn't eligible, it keeps
restarting and logging the reason until someone fixes it.

### Stopping and restarting

On `SIGTERM` or Ctrl-C, the connector stops taking new jobs, closes its session and exits with `0`.
A rotation in progress is abandoned without a report, and the server deals with the unreported
attempt. Where you can, restart between rotations. The logs show when one is running.

The connector keeps no state on disk and writes no log file.

### More than one organization

An access connector token belongs to one organization, so a host that rotates for several
organizations runs one connector per organization. Give each one its own:

- environment file with its token and target credentials
- config file, passed with `--config`, for example `/etc/bwac/acme/config.toml`
- systemd unit, for example `bwac-acme.service`, pointing at those two files

If the connectors need their own scripts, point each `script_root` at a different directory. They
can share the binary. Each unit's logs are separate in the journal.

## Logs and exit codes

Logs go to stderr. Set the level with `RUST_LOG`, which defaults to `info`:

```sh
RUST_LOG=debug bwac run --config /etc/bwac/config.toml
RUST_LOG=bitwarden_access_connector=trace,info bwac run --config /etc/bwac/config.toml
```

At `info` you get a line for each step of a rotation. `debug` adds poll ticks with the number of
available jobs, heartbeats, jobs another connector claimed first, and more detail per step.

| Level   | Event                                                        | Fields                                                                                           |
| ------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `info`  | Access connector starting                                    | `api_url`, `identity_url`, `poll_interval_secs`, `heartbeat_interval_secs`, `configured_targets` |
| `info`  | Session authenticated                                        | `retry`                                                                                          |
| `info`  | Rotation job claimed                                         | `job_id`, `target_system_name`                                                                   |
| `info`  | Starting rotation execution                                  | `attempt_id`, `job_id`, `cipher_id`, `target_system_name`                                        |
| `info`  | Pre-flight cipher check passed, steps 1–7                    | `attempt_id`, and `kind`, `cipher_id` or `termination`                                           |
| `info`  | Shutdown signal received, access connector shut down cleanly |                                                                                                  |
| `warn`  | Session renewal failed                                       | `retry`, `sleep_ms`                                                                              |
| `warn`  | Session revoked                                              |                                                                                                  |
| `warn`  | Rotation failed                                              | `attempt_id`, `failure_code`, `sync_state`, `detail`                                             |
| `warn`  | Session termination aborted or failed                        | `attempt_id`, `abort_reason`                                                                     |
| `warn`  | Success report rejected or unknown                           | `attempt_id`                                                                                     |
| `warn`  | Transient poll error                                         | backoff duration                                                                                 |
| `error` | Access connector credential refused                          |                                                                                                  |
| `error` | Access connector could not authenticate at startup           |                                                                                                  |
| `error` | Access connector not eligible for rotation endpoints         |                                                                                                  |

Logs never contain passwords, tokens or other credential values.

### Exit codes

| Code | Meaning                                                                      | What to do                                                                              |
| ---- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `0`  | Clean shutdown                                                               | Nothing                                                                                 |
| `1`  | Startup error, such as bad config, arguments or a missing token              | Fix what the log line names                                                             |
| `2`  | The token was refused                                                        | Have an admin issue a new token, then restart with it                                   |
| `3`  | The connector isn't allowed to rotate                                        | Check the connector isn't revoked or disabled, the license is active and PAM is enabled |
| `4`  | Couldn't sign in at startup, for example the identity server was unreachable | Check the network and the identity URL, then restart                                    |

## Troubleshooting

### The connector won't start

| Log message                                                                       | Cause                                                                 |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `access connector token must be supplied via the BWAC_TOKEN environment variable` | `BWAC_TOKEN` is missing or empty                                      |
| `Has the wrong number of parts` or `Has the wrong prefix`                         | The token was cut off when copied. Include the part after the `:`     |
| `api URL must be supplied via …`                                                  | `identity` or `BWAC_IDENTITY_URL` is set without an API URL or `base` |
| `config file … is invalid TOML: unknown field`                                    | A typo, or `client_secret` in a `[targets]` block                     |
| `poll_interval must be >= 15 seconds`                                             | `poll_interval` is below 15                                           |

### Nothing gets rotated

Set `RUST_LOG=debug` and watch the poll ticks. If every tick shows `claimable_jobs=0`, the server
has no work for the connector, so check the rotation schedule on the target system in the Admin
Console. Frequent `claim race lost (409)` lines mean another connector is claiming the jobs first,
which is normal when you run several.

### Rotations fail

Each failure is logged at `warn` with a `failure_code` and a `sync_state`, and the same pair is
recorded in Bitwarden.

| `failure_code`           | Meaning                                                                        | Where to look                                                    |
| ------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| `credentials_unresolved` | A required value is missing, or the script is missing or outside `script_root` | `detail` names the variable or the reason                        |
| `unsupported_kind`       | This build doesn't support the target kind                                     | [Target credentials](#target-credentials)                        |
| `target_rejected`        | The target system refused the reset                                            | The rotation identity's permissions, or Entra role hierarchy     |
| `target_unreachable`     | The connector couldn't reach the target                                        | Firewall, DNS or TLS from the connector host                     |
| `verification_failed`    | The reset seemed to work, but verification didn't confirm it                   | Replication delay, or a `rotate` that silently does nothing      |
| `script_failed`          | The script exited with a non-zero code                                         | `detail` has the exit code                                       |
| `script_timeout`         | The script ran longer than `script_timeout`                                    | Raise the timeout or speed up the script                         |
| `cipher_write_rejected`  | The vault item changed while the connector was updating it                     | Usually fixes itself on the next attempt                         |
| `cipher_encrypt_failed`  | The updated vault item couldn't be encrypted                                   | The item must be a login that fully decrypts and has an item key |
| `sealed_data_rejected`   | The job's sealed settings failed a check, and nothing was changed              | `detail` names the check                                         |
| `no_active_session`      | The connector's session had already ended when the job started                 | An earlier credential-refused warning in the log                 |
| `invalid_policy`         | The password policy can't be satisfied                                         | The policy on the target system                                  |
| `internal`               | An unexpected error in the connector                                           | `detail`                                                         |

`sync_state` tells you whether the target and the vault still agree:

- `target_unchanged`: nothing changed.
- `target_updated`: the target has a new password that the vault doesn't. Fix this by hand.
- `indeterminate`: the connector can't tell. Check the target by hand.

### Debugging scripts

Script output is thrown away, so have the script write to its own log file instead, without logging
`newPassword`. You can also point a test target at `tests/fixtures/copy_stdin.sh` (or
`copy_stdin.ps1`), which saves the payload it receives to a file.

The most common script problem is `PATH`. The environment is empty, so tools in `/usr/local/bin` or
`/opt/homebrew/bin` aren't found unless the script sets `PATH`.

For a PowerShell script, `script_failed` with `exit code 1` and nothing else usually means the host
failed before your code ran. Common causes are an execution policy block, an unsigned script, a
syntax error, or a module that won't load. To see the error, run the script by hand as the
connector's user:

```
runas /user:svc_bwac "pwsh -NoProfile -NonInteractive -File C:\bwac\rotate-sqlsa.ps1 rotate"
```

## Development

```sh
cargo test -p bitwarden-access-connector --all-features

# Run against a local server through the dev proxy on https://localhost:8080
BWAC_TOKEN="…" cargo run -p bitwarden-access-connector -- run \
  --config bitwarden_license/bitwarden-access-connector/dev-config.toml
```

Test scripts used by the integration tests are in `tests/fixtures/`. The build workflow in
`.github/workflows/build-access-connector.yml` produces release binaries for each supported
platform.

See also the [SDK architecture](https://contributing.bitwarden.com/architecture/sdk/) and
[security definitions](https://contributing.bitwarden.com/architecture/security/definitions).
