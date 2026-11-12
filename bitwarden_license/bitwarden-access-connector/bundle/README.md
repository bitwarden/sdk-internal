# Bitwarden Access Connector

The archive contains `bwac` (`bwac.exe` on Windows), the access connector, and a `templates/` folder
with the files you copy and fill in while installing it. The steps below install the connector as a
service on Linux, macOS or Windows. Their paths are a suggested layout, so change them to suit your
host.

## Before you start

You need:

- An access connector token. An organization admin registers a connector in the Admin Console and
  gets a token that looks like `0.access-connector.<id>.<secret>:<key>`. It is only shown once. Copy
  all of it, including the part after the `:`.
- The URL of your Bitwarden server, for example `https://bitwarden.example.com`. For Bitwarden's
  cloud, use `https://bitwarden.com` (US) or `https://bitwarden.eu` (EU).
- Outbound HTTPS from the host to your Bitwarden server and to the systems you rotate. Entra ID
  targets also need `login.microsoftonline.com` and `graph.microsoft.com`. The connector doesn't
  listen on any port.

The connector reads its token only from the `BWAC_TOKEN` environment variable. Keep the token out of
command lines and shell history. The steps below put it in a file that only administrators and the
connector can read.

## Linux (systemd)

Run these commands from the unpacked archive.

1. Create a service account:

   ```sh
   sudo groupadd --system bwac
   sudo useradd --system --gid bwac --home-dir /var/lib/bwac --no-create-home \
       --shell /usr/sbin/nologin bwac
   ```

2. Install the binary and create its directories:

   ```sh
   sudo install -m 0755 -o root -g root bwac /usr/local/bin/bwac
   sudo install -d -m 0755 -o root -g root /etc/bwac /opt/bwac/scripts
   sudo install -d -m 0700 -o bwac -g bwac /var/lib/bwac
   /usr/local/bin/bwac --version
   ```

   Your rotation scripts go in `/opt/bwac/scripts`. It is owned by root, so the connector can run
   the scripts but can't change them.

3. Create `/etc/bwac/config.toml`, for example with `sudoedit`:

   ```toml
   script_root = "/opt/bwac/scripts"

   [environment]
   base = "https://bitwarden.example.com"
   ```

   The service account can read this file, so it must not contain secrets. The connector won't start
   if it finds a token or a client secret in it, or any key it doesn't recognize.

4. Create the environment file, which holds the token:

   ```sh
   sudo install -m 0400 -o root -g root templates/bwac.env.in /etc/bwac/env
   sudoedit /etc/bwac/env
   ```

   Replace `@TOKEN@` with your token. The credentials for your target systems go in the same file
   (see [Target credentials](#target-credentials)). systemd reads this file directly, so don't
   `source` it from a shell.

5. Install the systemd unit:

   ```sh
   sed -e 's|@SERVICE_USER@|bwac|g' \
       -e 's|@ENV_FILE@|/etc/bwac/env|g' \
       -e 's|@BINARY_PATH@|/usr/local/bin/bwac|g' \
       -e 's|@CONFIG_FILE@|/etc/bwac/config.toml|g' \
       -e 's|@STATE_DIR@|/var/lib/bwac|g' \
       templates/bwac.service.in | sudo tee /etc/systemd/system/bwac.service >/dev/null
   ```

   The unit makes the file system read-only for the connector and your scripts, except for
   `/var/lib/bwac` and a private `/tmp`, and hides home directories. Check those hardening lines
   against what your scripts need.

6. Start the connector and watch the log:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now bwac
   sudo journalctl -u bwac -f
   ```

On a host without systemd, run `bwac run --config /etc/bwac/config.toml` under the process
supervisor you already use, with `BWAC_TOKEN` and the target credentials in its environment.

## macOS (launchd)

Run these commands from the unpacked archive.

1. Create a hidden service account. Pick an ID between 300 and 400 that no user or group has yet.
   `dscl . -list /Users UniqueID` and `dscl . -list /Groups PrimaryGroupID` show the IDs already
   taken. This example uses 310:

   ```sh
   sudo dscl . -create /Groups/_bwac PrimaryGroupID 310
   sudo dscl . -create /Users/_bwac UniqueID 310
   sudo dscl . -create /Users/_bwac PrimaryGroupID 310
   sudo dscl . -create /Users/_bwac UserShell /usr/bin/false
   sudo dscl . -create /Users/_bwac NFSHomeDirectory /var/empty
   sudo dscl . -create /Users/_bwac IsHidden 1
   sudo dscl . -create /Users/_bwac Password '*'
   ```

2. Install the binary and create its directories:

   ```sh
   sudo mkdir -p /usr/local/bin
   sudo install -m 0755 -o root -g wheel bwac /usr/local/bin/bwac
   sudo install -d -m 0755 -o root -g wheel /etc/bwac /opt/bwac/scripts
   sudo install -d -m 0700 -o _bwac -g _bwac /var/lib/bwac
   sudo install -d -m 0750 -o _bwac -g wheel /var/log/bwac
   /usr/local/bin/bwac --version
   ```

3. Create `/etc/bwac/config.toml` as in step 3 for Linux.

4. Install the launchd job. launchd has no environment file, so on macOS the token and the target
   credentials go in the job file itself:

   ```sh
   sudo install -m 0600 -o root -g wheel templates/launchd.plist.in \
       /Library/LaunchDaemons/com.bitwarden.bwac.plist
   sudo vi /Library/LaunchDaemons/com.bitwarden.bwac.plist
   ```

   Replace each placeholder:

   | Placeholder       | Value                                             |
   | ----------------- | ------------------------------------------------- |
   | `@LAUNCHD_LABEL@` | `com.bitwarden.bwac`                              |
   | `@BINARY_PATH@`   | `/usr/local/bin/bwac`                             |
   | `@BINARY_NAME@`   | `bwac`                                            |
   | `@CONFIG_FILE@`   | `/etc/bwac/config.toml`                           |
   | `@SERVICE_USER@`  | `_bwac`                                           |
   | `@STATE_DIR@`     | `/var/lib/bwac`                                   |
   | `@LOG_DIR@`       | `/var/log/bwac`                                   |
   | `@PLIST_FILE@`    | `/Library/LaunchDaemons/com.bitwarden.bwac.plist` |
   | `@TOKEN@`         | your token                                        |

   The file is XML, so write any `&`, `<` or `>` in a credential as `&amp;`, `&lt;` or `&gt;`. Check
   it with `sudo plutil -lint /Library/LaunchDaemons/com.bitwarden.bwac.plist`.

5. Start the connector and watch the log:

   ```sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.bitwarden.bwac.plist
   sudo tail -f /var/log/bwac/bwac.log
   ```

   After you edit the plist, reload it:

   ```sh
   sudo launchctl bootout system/com.bitwarden.bwac
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.bitwarden.bwac.plist
   ```

## Windows

On Windows the connector runs as a scheduled task, because `bwac.exe` can't talk to the Windows
service manager and so can't run as a service. The task starts the launcher,
`Start-AccessConnector.ps1`. The launcher loads the environment file into the connector's process
only and writes the connector's output to a log file, which a scheduled task would otherwise throw
away.

Run these commands in an elevated PowerShell window, from the unpacked archive. Use the same window
for all three steps, since later steps reuse `$install` and `$data`.

1. Copy the files and set permissions:

   ```powershell
   $install = 'C:\Program Files\Bitwarden\bwac'
   $data    = 'C:\ProgramData\Bitwarden\bwac'
   New-Item -ItemType Directory -Force -Path $install, $data, "$data\scripts", "$data\logs" | Out-Null
   Copy-Item .\bwac.exe $install
   Copy-Item .\templates\bwac-launcher.ps1 "$install\Start-AccessConnector.ps1"
   & "$install\bwac.exe" --version

   # Administrators and SYSTEM get full control. NETWORK SERVICE, which runs the connector,
   # can read the data directory, run scripts and write logs.
   icacls $data /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-20:(OI)(CI)R'
   icacls "$data\scripts" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-20:(OI)(CI)RX'
   icacls "$data\logs" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-20:(OI)(CI)M'
   ```

   Your rotation scripts go in `C:\ProgramData\Bitwarden\bwac\scripts`.

2. Write the config file and the environment file. Both must be UTF-8 without a byte order mark
   (BOM). Windows PowerShell's `Set-Content` and `Out-File` add one, and the connector would read it
   as part of the first line, so write them like this:

   ```powershell
   [IO.File]::WriteAllLines("$data\config.toml", [string[]] @(
       "script_root = 'C:\ProgramData\Bitwarden\bwac\scripts'"
       ''
       '[environment]'
       'base = "https://bitwarden.example.com"'
   ))

   # Prompts for the token, so it stays out of the command history.
   $secure = Read-Host 'Access connector token' -AsSecureString
   New-Item -ItemType File -Force -Path "$data\env" | Out-Null
   icacls "$data\env" /inheritance:r /grant:r '*S-1-5-32-544:F' /grant:r '*S-1-5-18:R' /grant:r '*S-1-5-20:R'
   [IO.File]::WriteAllLines("$data\env", [string[]] @(
       'BWAC_TOKEN=' + [Net.NetworkCredential]::new('', $secure).Password
       'RUST_LOG=info'
   ))
   Remove-Variable secure
   ```

   To add target credentials later, edit `env` in an elevated Notepad and save it without a BOM.

3. Register the task and start it:

   ```powershell
   $task = 'Bitwarden PAM access connector'
   $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
   $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}\Start-AccessConnector.ps1" -Exe "{0}\bwac.exe" -Config "{1}\config.toml" -EnvFile "{1}\env" -LogFile "{1}\logs\bwac.log"' -f $install, $data

   $action    = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $install
   $trigger   = New-ScheduledTaskTrigger -AtStartup
   $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\NETWORK SERVICE' -LogonType ServiceAccount -RunLevel Limited
   $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

   Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
   Start-ScheduledTask -TaskName $task
   Get-Content "$data\logs\bwac.log" -Tail 20 -Wait
   ```

To restart the connector, for example after editing `env` or `config.toml`, stop the task, wait for
`(Get-ScheduledTask -TaskName 'Bitwarden PAM access connector').State` to read `Ready`, then start
it again. `Stop-ScheduledTask` returns before the connector has exited, and the task ignores a start
request while the connector is still running. Stopping the task kills the connector straight away,
so restart between rotations where you can.

## Target credentials

Each target system needs credentials that the connector uses to reset passwords on it. They are
keyed by the target system's ID, which is shown in the Admin Console. Make the ID uppercase, replace
the hyphens with underscores, and add `_` and a suffix:

```
85808642_BABA_4B8E_8C34_B48000D60A0A_TENANT_ID=…
85808642_BABA_4B8E_8C34_B48000D60A0A_CLIENT_ID=…
85808642_BABA_4B8E_8C34_B48000D60A0A_CLIENT_SECRET=…
```

Entra ID targets need the suffixes `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET`. Custom script
targets need `SCRIPT`, the path to the script inside `script_root`. A custom script receives any
other variable with the same prefix as `credentials.<SUFFIX>` in its input.

Where the credentials go:

- Linux: `/etc/bwac/env`, one `NAME=value` per line.
- macOS: the `EnvironmentVariables` dict in the plist, as `<key>NAME</key><string>value</string>`.
- Windows: `C:\ProgramData\Bitwarden\bwac\env`, one `NAME=value` per line.

Restart the connector after any change.

## Checking it works

Within a few seconds of starting, the log should show:

```
INFO access connector starting api_url=… identity_url=… …
INFO session authenticated
```

If the connector stops instead, check the log and the exit code:

| Code | Meaning                                       | What to do                                                                  |
| ---- | --------------------------------------------- | --------------------------------------------------------------------------- |
| `1`  | Startup error, such as a bad config file      | Fix what the log names                                                      |
| `2`  | The token was refused                         | Have an admin issue a new token                                             |
| `3`  | The connector isn't allowed to rotate         | Check the connector isn't revoked, the license is active and PAM is enabled |
| `4`  | Couldn't sign in, for example a network error | Check the host can reach your Bitwarden server                              |
| `5`  | Another `bwac` is running with the same token | Stop the other one, for example a `bwac` started from a console             |

To see the exit code, run `systemctl status bwac` on Linux,
`sudo launchctl print system/com.bitwarden.bwac` on macOS, or
`Get-ScheduledTaskInfo -TaskName 'Bitwarden PAM access connector'` on Windows, where it appears as
`LastTaskResult`.

## Upgrading

Replace the binary and restart the connector. The config file and credentials stay as they are.

```sh
# Linux
sudo install -m 0755 -o root -g root bwac /usr/local/bin/bwac
sudo systemctl restart bwac

# macOS
sudo install -m 0755 -o root -g wheel bwac /usr/local/bin/bwac
sudo launchctl kickstart -k system/com.bitwarden.bwac
```

On Windows, stop every connector task on the host first, since Windows can't replace a running
program. Then copy the new `bwac.exe` over `C:\Program Files\Bitwarden\bwac\bwac.exe` and start the
tasks again.

## More than one connector

A token belongs to one organization, so a host that rotates for several organizations runs one
connector per organization. Give each its own config file, environment file, state directory and
service, for example `/etc/bwac/acme/config.toml`, `/etc/bwac/acme/env`, `/var/lib/bwac/acme` and
`bwac-acme.service`. The connectors can share the binary, the service account and the scripts
directory, but not a token: a second `bwac` started with the same token exits with `5`.

## Uninstalling

Linux:

```sh
sudo systemctl disable --now bwac
sudo rm /etc/systemd/system/bwac.service /usr/local/bin/bwac
sudo rm -rf /etc/bwac /var/lib/bwac
sudo userdel bwac
```

macOS:

```sh
sudo launchctl bootout system/com.bitwarden.bwac
sudo rm /Library/LaunchDaemons/com.bitwarden.bwac.plist /usr/local/bin/bwac
sudo rm -rf /etc/bwac /var/lib/bwac /var/log/bwac
sudo dscl . -delete /Users/_bwac
sudo dscl . -delete /Groups/_bwac
```

On Linux and macOS, these commands leave your scripts in `/opt/bwac/scripts` alone.

Windows:

```powershell
Unregister-ScheduledTask -TaskName 'Bitwarden PAM access connector' -Confirm:$false
Remove-Item -Recurse 'C:\Program Files\Bitwarden\bwac'
Remove-Item -Recurse 'C:\ProgramData\Bitwarden\bwac'
```

This also deletes `C:\ProgramData\Bitwarden\bwac\scripts`, so move your scripts out first if you
want to keep them.
