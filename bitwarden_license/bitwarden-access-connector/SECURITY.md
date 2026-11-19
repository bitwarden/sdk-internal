# Access connector security

What the access connector (`bwac`) can reach, what it trusts, and how to limit the damage if a host,
a credential, or the server is compromised. For setup and operation, see the [README](README.md). To
report a vulnerability, see the repository's [security policy](../../SECURITY.md).

## The access connector token

The token lets the connector call the rotation endpoints, and it carries a key that decrypts the
organization's vault items. Anyone holding it can read organization vault data.

The connector only accepts it from the `BWAC_TOKEN` environment variable:

- There is no command-line flag. Command-line arguments are visible to other users through `ps` and
  `/proc/<pid>/cmdline`.
- A config file with a `token` key fails at startup. Config files tend to end up in version control.

After reading the token, the connector removes `BWAC_TOKEN` from its own environment, so scripts it
launches can't inherit it.

## What the server sees

New passwords are generated and encrypted on the connector host. The Bitwarden server only ever
stores ciphertext.

Failure reports and logs contain error codes, HTTP status codes, script exit codes and variable
names. They never contain credential values.

## Sealed rotation settings

The settings that decide what a rotation does are the target kind, the password policy, the account
identity, and whether to end the account's sessions. The admin's client encrypts them into two
sealed values, one for the target and one for the rotation config. Each is an encrypted envelope
with a content key wrapped by the organization key. The server stores and relays them but can't read
or change them.

When the connector claims a job, it unseals both values and checks that the IDs and the vault item
match the job, and that the target system is set to rotate automatically. If either value is
missing, fails to unseal, or doesn't match, the connector refuses the job before touching anything.
Only IDs, the target name, the automatic or manual setting and scheduling fields reach the server in
plaintext. The connector trusts only the sealed copy of the automatic or manual setting.

So a compromised or impersonated server can't choose which account is rotated, weaken the password
policy, or send the new password to a different vault item. It can still:

- Replay older settings. A previously sealed value is still valid, so the server can bring back an
  earlier account identity or policy, or turn session termination back on.
- Control timing. The schedule and the enabled flag are plaintext, so the server decides when and
  how often a job runs. It can skip rotations or trigger them repeatedly.
- Control who reads the vault item. The connector checks that the item ID matches the sealed
  settings. Who can read that item afterwards is ordinary collection access, which the server
  controls.

Anyone with the organization key can also seal valid settings, with any policy the password
generator accepts. That includes a malicious organization member.

### Scope the target credentials

Sealing limits what the server can ask for. It doesn't limit what the connector's own target
credentials can do, so those are the real boundary.

- In Entra, grant the service principal rights over an Administrative Unit that contains only the
  accounts it should rotate. Avoid the tenant-wide Privileged Authentication Administrator role
  unless admin accounts are themselves meant to be rotated.
- For a custom script, give its admin credential the narrowest role that can reset the target
  accounts.

## Rotation is an administrative reset

The connector never sends an account's current password to an integration or script. It resets the
password as a separate privileged identity, the way a helpdesk resets a password without knowing the
old one.

This is what makes retries safe. Suppose a change-password call set the account's password to `X`
and the vault write then failed. The vault would still hold the old password, every retry would be
rejected because the "old" password no longer works, and nobody would know the account's password. A
reset doesn't depend on the current password, so retrying is always safe.

Each target system therefore needs a rotation identity for the connector: a service principal, an
SSH key with sudo rights, an admin API token, a database role that can `ALTER ROLE`, and so on.

## Custom scripts

The connector keeps its own secrets away from custom scripts:

- Secrets reach a script only on stdin, never through arguments or environment variables.
- A directly executed script starts with an empty environment. A PowerShell host gets the fixed list
  of system variables it needs to start, and nothing else. See
  [What the script inherits](README.md#what-the-script-inherits).
- stdout and stderr go to the null device, because script output can echo credentials.
- `newPassword` is left out of the `terminate` payload, since the script doesn't need it.
- When `script_root` is set, the script path is resolved, following symlinks, and must lie inside
  that directory. `../` paths and symlinks pointing outside are refused before anything runs.

`accountIdentity` reaches the script exactly as the admin sealed it. The server can't read or change
it, but it is still untrusted input: anyone who can save a rotation config chose that string. Never
put it unescaped into a shell command, SQL query or API path.

## The vault item

Before touching the target system, the connector fetches the vault item and does a dry run of the
write with a placeholder password. It refuses an item that:

- isn't a login in the connector's organization
- the server sent with some fields withheld, since rewriting it would erase them
- doesn't fully decrypt
- has no item key (editing the item in a current Bitwarden client gives it one)

The real write replaces only the login password, moving the old one into password history, and
re-encrypts the item. It sends the item key back unchanged and never creates or replaces it. The
server rejects the write if someone edited the item after the connector read it.

## Hardening the host

- Keep `BWAC_TOKEN` and the target credentials in a root-owned file with mode `0400`, loaded with
  systemd's `EnvironmentFile=`.
- Run the connector as a dedicated unprivileged user.
- Set `script_root` to a directory the connector user can't write to.
- Give each connector only the target credentials it needs. Connectors that run as the same user on
  one host can read each other's token and credentials, so give each its own user or host if they
  must be isolated.
- Review the hardening options in the [systemd unit](README.md#systemd) against what your scripts
  need.
