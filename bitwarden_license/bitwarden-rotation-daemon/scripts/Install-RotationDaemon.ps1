#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs bw-rotation-daemon as a scheduled task that starts at boot. A URL, and an
    optional name.

.DESCRIPTION
        .\Install-RotationDaemon.ps1 https://bitwarden.example.com
        .\Install-RotationDaemon.ps1 https://bitwarden.example.com acme

    The binary is the bw-rotation-daemon.exe sitting next to this script, which is how
    the release archive is laid out. The layout it installs is fixed:

        C:\Program Files\Bitwarden\bw-rotation-daemon\
            bw-rotation-daemon.exe          the daemon; shared
            Start-RotationDaemon.ps1        launcher (see below); shared
        C:\ProgramData\Bitwarden\bwrd\
            config.toml                     settings; never secrets
            env                             token and per-target credentials, ACL-locked
            scripts\                        script_root; the daemon reads, cannot write
            logs\                           stderr, rolled at 10 MB

    A name is only needed to run more than one daemon on one host, which a host rotating
    for more than one organisation has to do, since a daemon token belongs to a single
    organisation. It moves everything the daemon writes, or reads its token from, into a
    directory of its own, and leaves the shared pieces alone:

        C:\ProgramData\Bitwarden\bwrd\<name>\
            config.toml
            env
            logs\

    with the task named 'Bitwarden PAM rotation daemon (<name>)'. The binary, the
    launcher and scripts\ stay shared: the daemon cannot write to the script directory,
    so there is nothing to keep apart there, and one script can serve every daemon.
    Point that daemon's script_root elsewhere if you would rather they were separate.

    None of that is configurable. If you want a different layout, a different task
    principal, or Bitwarden Cloud's separate api and identity URLs, install by hand:
    the config file and the task this registers show you every piece.

    Four things here are not arbitrary:

    * It registers a scheduled task, not a Windows service. bw-rotation-daemon is an
      ordinary console program with no service control handler, so sc.exe would start
      it and then fail with error 1053 when it never called StartServiceCtrlDispatcher.
      A scheduled task with an at-startup trigger is the built-in way to run a console
      program unattended; the alternative is a third-party wrapper such as NSSM.

    * A launcher sits between the task and the daemon. The daemon reads its token and
      every per-target credential from environment variables, and most target UUIDs
      begin with a digit. A machine-level environment variable is the wrong place for a
      token -- it lands in a registry key any user can read -- so the launcher reads the
      ACL-restricted env file and sets the values on its own process only. It also
      captures stderr, which a scheduled task otherwise discards.

    * The token is not a parameter. It comes from BWRD_TOKEN or a hidden prompt. A
      -Token parameter would put it in this process's command line, readable by anything
      that can call Get-CimInstance Win32_Process -- the same reason the daemon itself
      refuses --token.

    * Windows locks a running image, so the binary cannot be replaced while any daemon
      on the host is running from it. Nothing has to stop when the bundled binary is the
      one already installed, which is the usual case when a second daemon comes from the
      same archive; an actual upgrade means stopping the other tasks first, and the
      installer says so rather than failing obscurely.

    OPERATIONS.md lists Windows among the supported platforms. Entra ID targets work
    here, and a CustomScript target runs a .ps1 through a PowerShell host.

    Re-running replaces the binary and the launcher and leaves config.toml and the env
    file alone, so upgrading cannot lose credentials you added. Every daemon on the host
    runs the one binary, so replacing it replaces it for all of them.

    Stopping the task terminates the daemon rather than asking it to shut down, because
    Windows has no SIGTERM. A rotation interrupted that way is abandoned without a
    report and the server reconciles it, as OPERATIONS.md describes for a hard restart.

    To remove it:

        Unregister-ScheduledTask -TaskName 'Bitwarden PAM rotation daemon' -Confirm:$false
        Remove-Item -Recurse 'C:\Program Files\Bitwarden\bw-rotation-daemon'
        Remove-Item -Recurse 'C:\ProgramData\Bitwarden\bwrd'

    A named daemon comes off the same way, with '(<name>)' on the task name and
    C:\ProgramData\Bitwarden\bwrd\<name> in place of that last path. Leave the install
    directory until the last daemon on the host is gone.

    Rotation scripts under C:\ProgramData\Bitwarden\bwrd\scripts are yours; move them out
    first if you want to keep them.

.PARAMETER ServerUrl
    Your Bitwarden server, for example https://bitwarden.example.com.

.PARAMETER Name
    Which daemon on this host is being installed, for a host that runs more than one.
    Lowercase letters, digits, '-' and '_'. Leave it out for the single-daemon layout.

.EXAMPLE
    $env:BWRD_TOKEN = '0.access-connector.<id>.<secret>:<key>'
    .\Install-RotationDaemon.ps1 https://bitwarden.example.com

.EXAMPLE
    # Prompts for the token, with the input hidden.
    .\Install-RotationDaemon.ps1 https://bitwarden.example.com

.EXAMPLE
    # A second daemon on the same host, kept separate from the first.
    .\Install-RotationDaemon.ps1 https://bitwarden.example.com acme
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^https?://')]
    [string] $ServerUrl,

    [Parameter(Position = 1)]
    [string] $Name = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Fixed layout
# ---------------------------------------------------------------------------

$BinaryName   = 'bw-rotation-daemon.exe'
$LauncherName = 'Start-RotationDaemon.ps1'
$TaskPrefix   = 'Bitwarden PAM rotation daemon'
$RunAsUser    = 'NT AUTHORITY\NETWORK SERVICE'

$InstallDir   = Join-Path $env:ProgramFiles 'Bitwarden\bw-rotation-daemon'
$DataDir      = Join-Path $env:ProgramData 'Bitwarden\bwrd'
$ScriptDir    = Join-Path $DataDir 'scripts'

$ExePath      = Join-Path $InstallDir $BinaryName
$LauncherPath = Join-Path $InstallDir $LauncherName

# Names that would land on top of something already sitting beside a named daemon's
# directory.
$ReservedNames = @('scripts', 'logs', 'env')

# Set by Resolve-Layout, once the name has been checked. An unnamed daemon gets the data
# directory itself, which is the layout every install had before names existed.
$TaskName   = $null
$DaemonDir  = $null
$LogDir     = $null
$ConfigPath = $null
$EnvPath    = $null
$LogPath    = $null

# Well-known SIDs, so the ACLs are the same on a localised Windows.
$SidSystem         = '*S-1-5-18'
$SidAdministrators = '*S-1-5-32-544'

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Item { param([string] $Message) Write-Host "    $Message" }
function Fail       { param([string] $Message) throw $Message }

function Invoke-Native {
    param([string] $Command, [string[]] $Arguments, [string] $What)
    $output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "$What failed (exit $LASTEXITCODE): $($output -join '; ')" }
}

# Replaces inherited permissions outright, so a permissive ACL further up the tree
# cannot widen access to the token.
function Set-ExplicitAcl {
    param([string] $Path, [string[]] $Grants, [string] $What)
    $icaclsArgs = @($Path, '/inheritance:r')
    foreach ($grant in $Grants) { $icaclsArgs += '/grant:r'; $icaclsArgs += $grant }
    Invoke-Native -Command 'icacls.exe' -Arguments $icaclsArgs -What "setting permissions on $What"
}

# UTF-8 without a BOM: the daemon's TOML parser and the launcher's env reader both
# treat a BOM as part of the first key.
function Write-TextFile {
    param([string] $Path, [string[]] $Lines)
    [IO.File]::WriteAllText($Path, ($Lines -join "`r`n") + "`r`n",
        (New-Object Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------

# Checks the name and settles everything that depends on it: the task, and the directory
# holding this daemon's config, token and logs. The name becomes part of a scheduled task
# name, a systemd unit file name on the other platforms, and a path, so it is kept to a
# plain lowercase word.
function Resolve-Layout {
    param([string] $Name)

    if ($Name) {
        # -cnotmatch, because -notmatch would accept 'ACME' and the shell installer does not.
        if ($Name -cnotmatch '^[a-z0-9][a-z0-9_-]*$') {
            Fail ("The name '$Name' must be lowercase letters, digits, '-' or '_', and " +
                'start with a letter or a digit.')
        }
        if ($Name.Length -gt 32) { Fail "The name '$Name' is longer than 32 characters." }
        if ($ReservedNames -contains $Name) {
            Fail ("'$Name' is taken: the layout already uses that name next to the " +
                'directory this daemon would get. Pick another.')
        }
    }

    $script:TaskName   = if ($Name) { "$TaskPrefix ($Name)" } else { $TaskPrefix }
    $script:DaemonDir  = if ($Name) { Join-Path $DataDir $Name } else { $DataDir }
    $script:LogDir     = Join-Path $script:DaemonDir 'logs'
    $script:ConfigPath = Join-Path $script:DaemonDir 'config.toml'
    $script:EnvPath    = Join-Path $script:DaemonDir 'env'
    $script:LogPath    = Join-Path $script:LogDir 'bw-rotation-daemon.log'
}

# Windows locks a running image, and Stop-ScheduledTask returns before the process is gone.
# -MultipleInstances IgnoreNew then makes a too-early Start-ScheduledTask a silent no-op, so
# both callers wait for the task to leave Running.
function Stop-DaemonTask {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { return }

    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    foreach ($attempt in 1..50) {
        $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
        if ($state -ne 'Running') { return }
        Start-Sleep -Milliseconds 200
    }
    Fail "'$TaskName' is still running after 10s. Stop it and re-run the installer."
}

# Copies the bundled binary into place after checking it runs here. Those are the two
# checks CI runs after building, and they catch an archive for the wrong architecture
# now rather than as a task that will not stay running.
function Install-DaemonBinary {
    Write-Step 'Binary'
    $bundled = Join-Path $PSScriptRoot $BinaryName

    if (-not (Test-Path -LiteralPath $bundled)) {
        Fail ("No $BinaryName next to this script. Expected it at`n         $bundled`n" +
            '       Run the script from the unpacked release archive.')
    }

    & $bundled --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail ("$bundled does not run on this host. Check you unpacked the archive built " +
            'for x86_64-pc-windows-msvc.')
    }
    $version = (& $bundled --version 2>&1 | Select-Object -First 1)
    & $bundled run --help 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "$bundled does not accept 'run --help'; is it really $BinaryName?" }

    # Nothing has to stop if the installed binary is already this build, which is the
    # usual case when another daemon on this host came from the same archive.
    if ((Test-Path -LiteralPath $ExePath) -and
        (Get-FileHash -LiteralPath $bundled).Hash -eq (Get-FileHash -LiteralPath $ExePath).Hash) {
        Write-Item "$ExePath is already this build ($version); left in place"
        return
    }

    Stop-DaemonTask
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    try {
        Copy-Item -LiteralPath $bundled -Destination $ExePath -Force
    } catch {
        # Windows locks a running image, and every daemon on this host runs this one.
        Fail ("Cannot replace $ExePath while another daemon on this host is running " +
            "from it. Stop the other tasks, run this again, and start them afterwards:`n" +
            "         Get-ScheduledTask -TaskName '$TaskPrefix*' | Stop-ScheduledTask")
    }
    Write-Item "$ExePath ($version)"
}

# Reads the token from the environment or prompts for it, then checks the two things
# that actually go wrong when a token is pasted: it gets cut at the ':', or it is not a
# daemon token at all. The daemon validates the rest properly at startup.
function Get-DaemonToken {
    Write-Step 'Daemon token'

    $token = $null
    if ($env:BWRD_TOKEN) {
        $token = $env:BWRD_TOKEN
        Write-Item 'taken from BWRD_TOKEN'
    } else {
        $secure = Read-Host -Prompt '    Paste the daemon token (input hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    $token = ($token -replace '\s', '')
    if (-not $token) { Fail 'The token is empty.' }
    if (-not $token.StartsWith('0.access-connector.')) {
        Fail ("The token does not start '0.access-connector.'. This looks like a different " +
            'kind of Bitwarden key, not a rotation daemon token.')
    }
    $colon = $token.IndexOf(':')
    if ($colon -lt 0 -or $colon -eq $token.Length - 1) {
        Fail ("The token has nothing after a ':'. It was truncated on copy -- copy the whole " +
            'string, including the encryption key at the end.')
    }
    return $token
}

function Initialize-Layout {
    Write-Step 'Directories'
    $sid = try {
        (New-Object Security.Principal.NTAccount($RunAsUser)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        Fail "Cannot resolve '$RunAsUser' to a SID: $($_.Exception.Message)"
    }

    foreach ($dir in @($InstallDir, $DataDir, $ScriptDir, $DaemonDir, $LogDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # InstallDir sits under Program Files and inherits the right thing already:
    # administrators and SYSTEM can write, everyone else reads and executes. A named
    # daemon's directory inherits this one, which is read-only for the task principal.
    Set-ExplicitAcl -Path $DataDir -What 'the data directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)R")

    # script_root: the daemon reads and executes what is here and cannot add to it, so
    # it cannot install a new script for itself to run.
    Set-ExplicitAcl -Path $ScriptDir -What 'the script directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)RX")

    # The launcher writes the log, so this one directory is writable. It belongs to this
    # daemon alone, named or not.
    Set-ExplicitAcl -Path $LogDir -What 'the log directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)M")

    Write-Item "$InstallDir, $DataDir"
    return $sid
}

function Write-DaemonConfig {
    Write-Step 'Configuration'
    if (Test-Path -LiteralPath $ConfigPath) {
        Write-Item "$ConfigPath exists; left alone"
        return
    }

    # Paths use TOML literal strings (single quotes), which take no escapes, so
    # Windows backslashes go in as written.
    Write-TextFile -Path $ConfigPath -Lines @(
        '# bw-rotation-daemon configuration. The installer writes this once and never touches'
        '# it again; edit it and restart the scheduled task.'
        '#'
        '# Secrets do not belong here. The daemon treats a config containing a token as a'
        '# startup error, and rejects client_secret inside [targets], because config files end'
        '# up in repositories. Unknown keys are a startup error too, so a typo is loud.'
        '#'
        '# Defaults not shown: poll_interval 15, heartbeat_interval 30, offline_grace 60,'
        '# max_retry_attempts 5, retry_base_delay 1, script_timeout 60. See OPERATIONS.md.'
        ''
        "script_root = '$ScriptDir'"
        ''
        '[environment]'
        "base = `"$ServerUrl`""
        ''
        '# Bitwarden Cloud does not derive from base; set these two and delete the line above:'
        '# api      = "https://api.bitwarden.com"'
        '# identity = "https://identity.bitwarden.com"'
    )
    Write-Item $ConfigPath
}

function Write-DaemonEnv {
    param([string] $Token, [string] $Sid)
    Write-Step 'Token and target credentials'
    if (Test-Path -LiteralPath $EnvPath) {
        Write-Item "$EnvPath exists; left alone (edit it to change the token)"
        return
    }

    Write-TextFile -Path $EnvPath -Lines @(
        '# Environment for bw-rotation-daemon, read by Start-RotationDaemon.ps1 and set on'
        '# the daemon process only, so nothing here reaches the registry or any other'
        '# process. Restricted by ACL to administrators, SYSTEM and the task principal.'
        '#'
        '# Per-target credentials go here, keyed by target system UUID: uppercase the UUID,'
        '# replace hyphens with underscores, append the suffix.'
        '#'
        '#   Entra         TENANT_ID, CLIENT_ID, CLIENT_SECRET'
        '#   CustomScript  SCRIPT'
        '#'
        '# Any other variable with the same prefix reaches a custom script as'
        '# credentials.<SUFFIX> in its stdin JSON:'
        '#'
        '#   85808642_BABA_4B8E_8C34_B48000D60A0A_TENANT_ID=...'
        '#   85808642_BABA_4B8E_8C34_B48000D60A0A_CLIENT_SECRET=...'
        '#'
        '# Names starting with a digit are fine: the launcher sets them through'
        '# SetEnvironmentVariable, which has no identifier rules. Restart the task after'
        '# editing:'
        "#   Stop-ScheduledTask -TaskName '$TaskName'; Start-ScheduledTask -TaskName '$TaskName'"
        ''
        "BWRD_TOKEN=$Token"
        'RUST_LOG=info'
    )
    Set-ExplicitAcl -Path $EnvPath -What 'the env file' -Grants @(
        "$($SidAdministrators):F", "$($SidSystem):R", "*$($Sid):R")
    Write-Item "$EnvPath (read-only for $RunAsUser, no inherited permissions)"
}

function Write-Launcher {
    Write-Step 'Launcher'
    # Copied rather than generated: the launcher takes its paths as parameters from the
    # scheduled task, so nothing in it needs interpolating at install time.
    $template = Join-Path (Join-Path $PSScriptRoot 'templates') 'bw-rotation-daemon-launcher.ps1'
    if (-not (Test-Path -LiteralPath $template)) {
        Fail ("No launcher template next to this script. Expected it at`n         $template`n" +
            '         Run the script from the unpacked release archive.')
    }

    # Split so the launcher gets CRLF like every other file this writes.
    Write-TextFile -Path $LauncherPath -Lines (Get-Content -LiteralPath $template)
    Write-Item $LauncherPath
}

function Register-DaemonTask {
    Write-Step 'Scheduled task'

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argument = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" ' +
        '-Exe "{1}" -Config "{2}" -EnvFile "{3}" -LogFile "{4}"') -f
        $LauncherPath, $ExePath, $ConfigPath, $EnvPath, $LogPath

    # ExecutionTimeLimit zero means no limit, which is what a daemon needs. The restart
    # settings are the nearest equivalent to systemd's Restart=always; one minute is the
    # shortest interval the task scheduler accepts.
    Register-ScheduledTask -TaskName $TaskName -Force `
        -Action (New-ScheduledTaskAction -Execute $powershell -Argument $argument -WorkingDirectory $InstallDir) `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Limited) `
        -Settings (New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero)) `
        -Description 'Bitwarden PAM credential rotation daemon.' | Out-Null

    Stop-DaemonTask
    Start-ScheduledTask -TaskName $TaskName
    Write-Item "registered '$TaskName' as $RunAsUser, started, and set to start at boot"
}

# ---------------------------------------------------------------------------

try {
    Resolve-Layout -Name $Name
    Install-DaemonBinary
    $token = Get-DaemonToken
    $sid = Initialize-Layout
    Write-DaemonConfig
    Write-DaemonEnv -Token $token -Sid $sid
    Write-Launcher
    Register-DaemonTask

    Write-Host ''
    Write-Host '==> Installed' -ForegroundColor Green
    Write-Host ''
    Write-Host '    Check it came up:'
    Write-Host "      Get-ScheduledTaskInfo -TaskName '$TaskName'"
    Write-Host "      Get-Content -Path '$LogPath' -Tail 20 -Wait"
    Write-Host ''
    Write-Host '    You want "session established". "Daemon credential refused" means the token'
    Write-Host '    needs reissuing; "not eligible" means the daemon record, the licence or the'
    Write-Host '    PAM flag needs attention on the server.'
    Write-Host ''
    Write-Host '    Next, add the credentials for each target system to'
    Write-Host "      $EnvPath"
    Write-Host '    then restart the task. That file explains the naming.'
    Write-Host ''
} catch {
    Write-Host ''
    Write-Host "Install-RotationDaemon.ps1: error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
