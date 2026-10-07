#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs bwac as a scheduled task that starts at boot. Takes a URL and an
    optional name.

.DESCRIPTION
        .\Install-AccessConnector.ps1 https://bitwarden.example.com
        .\Install-AccessConnector.ps1 https://bitwarden.example.com acme

    The binary is the bwac.exe next to this script, as in the release archive. The layout it
    installs is fixed:

        C:\Program Files\Bitwarden\bwac\
            bwac.exe                        the connector; shared
            Start-AccessConnector.ps1       launcher (see below); shared
        C:\ProgramData\Bitwarden\bwac\
            config.toml                     settings; never secrets
            env                             token and per-target credentials, ACL-locked
            scripts\                        script_root; the connector reads, cannot write
            logs\                           stderr, rolled at 10 MB

    A name is only needed to run more than one connector on one host, as a host rotating for
    several organisations must, since a token belongs to one organisation. It moves the
    connector's config, token and logs into a directory of its own:

        C:\ProgramData\Bitwarden\bwac\<name>\
            config.toml
            env
            logs\

    with the task named 'Bitwarden PAM access connector (<name>)'.

    The binary, the launcher and scripts\ stay shared; the connector cannot write to the
    script directory, so one script can serve every connector. Point a connector's
    script_root elsewhere to give it scripts of its own.

    None of that is configurable. If you want a different layout, a different task
    principal, or Bitwarden Cloud's separate api and identity URLs, install by hand:
    the config file and the task this registers show you every piece.

    Four things here are not arbitrary:

    * It registers a scheduled task, not a Windows service. bwac has no service control
      handler, so the service manager would fail it with error 1053 unless a wrapper such as
      NSSM ran it.

    * A launcher sits between the task and the connector. It loads the ACL-locked env file into
      its own process only, as a machine-level variable lands in a registry key any user can
      read, and captures stderr, which a scheduled task discards.

    * The token is not a parameter; it comes from BWAC_TOKEN or a hidden prompt. A -Token
      parameter would put it in the command line, readable through Get-CimInstance
      Win32_Process, which is also why the connector refuses --token.

    * Windows locks a running image, so an upgrade means stopping every other connector on the
      host first, and the installer says so. A second connector from the same archive leaves
      the installed binary in place, so nothing has to stop.

    Entra ID targets work here, and a CustomScript target runs a .ps1 through a PowerShell host.

    Re-running replaces the binary and the launcher and leaves config.toml and the env
    file alone, so upgrading cannot lose credentials you added.

    Stopping the task kills the connector, since Windows has no SIGTERM. A rotation interrupted
    that way is abandoned without a report, and the server handles the unreported attempt.

    To remove it:

        Unregister-ScheduledTask -TaskName 'Bitwarden PAM access connector' -Confirm:$false
        Remove-Item -Recurse 'C:\Program Files\Bitwarden\bwac'
        Remove-Item -Recurse 'C:\ProgramData\Bitwarden\bwac'

    A named connector comes off the same way, with '(<name>)' on the task name and
    C:\ProgramData\Bitwarden\bwac\<name> in place of that last path. Leave the install
    directory until the last connector on the host is gone.

    Rotation scripts under C:\ProgramData\Bitwarden\bwac\scripts are yours; move them out
    first if you want to keep them.

.PARAMETER ServerUrl
    Your Bitwarden server, for example https://bitwarden.example.com.

.PARAMETER Name
    Which connector on this host is being installed, for a host that runs more than one.
    Lowercase letters, digits, '-' and '_'. Leave it out for the single-connector layout.

.EXAMPLE
    $env:BWAC_TOKEN = '0.access-connector.<id>.<secret>:<key>'
    .\Install-AccessConnector.ps1 https://bitwarden.example.com

.EXAMPLE
    # Prompts for the token, with the input hidden.
    .\Install-AccessConnector.ps1 https://bitwarden.example.com

.EXAMPLE
    # A second connector on the same host, kept separate from the first.
    .\Install-AccessConnector.ps1 https://bitwarden.example.com acme
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

$BinaryName   = 'bwac.exe'
$LauncherName = 'Start-AccessConnector.ps1'
$TaskPrefix   = 'Bitwarden PAM access connector'
$RunAsUser    = 'NT AUTHORITY\NETWORK SERVICE'

$InstallDir   = Join-Path $env:ProgramFiles 'Bitwarden\bwac'
$DataDir      = Join-Path $env:ProgramData 'Bitwarden\bwac'
$ScriptDir    = Join-Path $DataDir 'scripts'

$ExePath      = Join-Path $InstallDir $BinaryName
$LauncherPath = Join-Path $InstallDir $LauncherName

# Names that would land on top of something already sitting beside a named connector's
# directory.
$ReservedNames = @('scripts', 'logs', 'env')

# Set by Resolve-Layout.
$TaskName     = $null
$ConnectorDir = $null
$LogDir       = $null
$ConfigPath   = $null
$EnvPath      = $null
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

# UTF-8 without a BOM: the connector's TOML parser and the launcher's env reader both
# treat a BOM as part of the first key.
function Write-TextFile {
    param([string] $Path, [string[]] $Lines)
    [IO.File]::WriteAllText($Path, ($Lines -join "`r`n") + "`r`n",
        (New-Object Text.UTF8Encoding($false)))
}

# The name becomes part of a scheduled task name, a systemd unit file name on the other
# platforms, and a path, so it is kept to a plain lowercase word.
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
                'directory this connector would get. Pick another.')
        }
    }

    $script:TaskName     = if ($Name) { "$TaskPrefix ($Name)" } else { $TaskPrefix }
    $script:ConnectorDir = if ($Name) { Join-Path $DataDir $Name } else { $DataDir }
    $script:LogDir       = Join-Path $script:ConnectorDir 'logs'
    $script:ConfigPath   = Join-Path $script:ConnectorDir 'config.toml'
    $script:EnvPath      = Join-Path $script:ConnectorDir 'env'
    $script:LogPath    = Join-Path $script:LogDir 'bwac.log'
}

# Windows locks a running image, and Stop-ScheduledTask returns before the process is gone.
# -MultipleInstances IgnoreNew then makes a too-early Start-ScheduledTask a silent no-op, so
# both callers wait for the task to leave Running.
function Stop-AccessConnectorTask {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { return }

    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    foreach ($attempt in 1..50) {
        $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
        if ($state -ne 'Running') { return }
        Start-Sleep -Milliseconds 200
    }
    Fail "'$TaskName' is still running after 10s. Stop it and re-run the installer."
}

function Get-ExitCodeHint {
    param([int] $ExitCode)

    switch ($ExitCode) {
        -1073741515 {  # 0xC0000135 STATUS_DLL_NOT_FOUND
            'A DLL it imports is missing. Install the x64 "Microsoft Visual C++ ' +
            '2015-2022 Redistributable" and run this again.'
        }
        -1073741701 {  # 0xC000007B STATUS_INVALID_IMAGE_FORMAT
            'That binary is for another architecture. Unpack the archive built for ' +
            'x86_64-pc-windows-msvc.'
        }
        default { $null }
    }
}

# Copies the bundled binary into place after the same two checks CI runs, so a binary that
# cannot start here fails now rather than as a task that will not stay running.
function Install-AccessConnectorBinary {
    Write-Step 'Binary'
    $bundled = Join-Path $PSScriptRoot $BinaryName

    if (-not (Test-Path -LiteralPath $bundled)) {
        Fail ("No $BinaryName next to this script. Expected it at`n         $bundled`n" +
            '       Run the script from the unpacked release archive.')
    }

    $probe = & $bundled --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        $message = ("$bundled does not run on this host " +
            ("(exit {0} / 0x{0:X8})." -f $LASTEXITCODE))
        $hint = Get-ExitCodeHint $LASTEXITCODE
        if ($hint) { $message += "`n         $hint" }
        if ($probe) { $message += "`n         It printed: $($probe -join '; ')" }
        Fail $message
    }
    $version = $probe | Select-Object -First 1

    $probe = & $bundled run --help 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail ("$bundled does not accept 'run --help' " +
            ("(exit {0} / 0x{0:X8}); is it really ${BinaryName}?" -f $LASTEXITCODE) +
            $(if ($probe) { "`n         It printed: $($probe -join '; ')" }))
    }

    # Nothing has to stop if the installed binary is already this build, which is the
    # usual case when another connector on this host came from the same archive.
    if ((Test-Path -LiteralPath $ExePath) -and
        (Get-FileHash -LiteralPath $bundled).Hash -eq (Get-FileHash -LiteralPath $ExePath).Hash) {
        Write-Item "$ExePath is already this build ($version); left in place"
        return
    }

    Stop-AccessConnectorTask
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    try {
        Copy-Item -LiteralPath $bundled -Destination $ExePath -Force
    } catch {
        # Windows locks a running image, and every connector on this host runs this one.
        Fail ("Cannot replace $ExePath while another connector on this host is running " +
            "from it. Stop the other tasks, run this again, and start them afterwards:`n" +
            "         Get-ScheduledTask -TaskName '$TaskPrefix*' | Stop-ScheduledTask")
    }
    Write-Item "$ExePath ($version)"
}

# Reads the token from the environment or a prompt and catches the two usual paste mistakes: a
# token cut at the ':', or not an access connector token at all. The connector checks the rest.
function Get-AccessConnectorToken {
    Write-Step 'Access connector token'

    $token = $null
    if ($env:BWAC_TOKEN) {
        $token = $env:BWAC_TOKEN
        Write-Item 'taken from BWAC_TOKEN'
    } else {
        $secure = Read-Host -Prompt '    Paste the access connector token (input hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    $token = ($token -replace '\s', '')
    if (-not $token) { Fail 'The token is empty.' }
    if (-not $token.StartsWith('0.access-connector.')) {
        Fail ("The token does not start '0.access-connector.'. This looks like a different " +
            'kind of Bitwarden key, not an access connector token.')
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

    foreach ($dir in @($InstallDir, $DataDir, $ScriptDir, $ConnectorDir, $LogDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # InstallDir inherits Program Files' ACL: administrators and SYSTEM write, everyone else reads
    # and executes. A named connector's directory inherits this DataDir ACL, read-only for the
    # task principal.
    Set-ExplicitAcl -Path $DataDir -What 'the data directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)R")

    # script_root: the connector reads and executes what is here and cannot add to it, so
    # it cannot install a new script for itself to run.
    Set-ExplicitAcl -Path $ScriptDir -What 'the script directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)RX")

    # The launcher writes the log, so this one directory is writable. It belongs to this
    # connector alone, named or not.
    Set-ExplicitAcl -Path $LogDir -What 'the log directory' -Grants @(
        "$($SidAdministrators):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "*$($sid):(OI)(CI)M")

    Write-Item "$InstallDir, $DataDir"
    return $sid
}

function Write-AccessConnectorConfig {
    Write-Step 'Configuration'
    if (Test-Path -LiteralPath $ConfigPath) {
        Write-Item "$ConfigPath exists; left alone"
        return
    }

    # Paths use TOML literal strings (single quotes), which take no escapes, so
    # Windows backslashes go in as written.
    Write-TextFile -Path $ConfigPath -Lines @(
        '# bwac configuration. The installer writes this once and never touches'
        '# it again; edit it and restart the scheduled task.'
        '#'
        '# Secrets do not belong here. The connector treats a config containing a token as a'
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

function Write-AccessConnectorEnv {
    param([string] $Token, [string] $Sid)
    Write-Step 'Token and target credentials'
    if (Test-Path -LiteralPath $EnvPath) {
        Write-Item "$EnvPath exists; left alone (edit it to change the token)"
        return
    }

    Write-TextFile -Path $EnvPath -Lines @(
        '# Environment for bwac, read by Start-AccessConnector.ps1 and set on'
        '# the connector process only, so nothing here reaches the registry or any other'
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
        "BWAC_TOKEN=$Token"
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
    $template = Join-Path (Join-Path $PSScriptRoot 'templates') 'bwac-launcher.ps1'
    if (-not (Test-Path -LiteralPath $template)) {
        Fail ("No launcher template next to this script. Expected it at`n         $template`n" +
            '         Run the script from the unpacked release archive.')
    }

    # Split so the launcher gets CRLF like every other file this writes.
    Write-TextFile -Path $LauncherPath -Lines (Get-Content -LiteralPath $template)
    Write-Item $LauncherPath
}

function Register-AccessConnectorTask {
    Write-Step 'Scheduled task'

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argument = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" ' +
        '-Exe "{1}" -Config "{2}" -EnvFile "{3}" -LogFile "{4}"') -f
        $LauncherPath, $ExePath, $ConfigPath, $EnvPath, $LogPath

    # ExecutionTimeLimit zero means no limit, which is what a connector needs. The restart
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
        -Description 'Bitwarden PAM access connector.' | Out-Null

    Stop-AccessConnectorTask
    Start-ScheduledTask -TaskName $TaskName
    Write-Item "registered '$TaskName' as $RunAsUser, started, and set to start at boot"
}

try {
    Resolve-Layout -Name $Name
    Install-AccessConnectorBinary
    $token = Get-AccessConnectorToken
    $sid = Initialize-Layout
    Write-AccessConnectorConfig
    Write-AccessConnectorEnv -Token $token -Sid $sid
    Write-Launcher
    Register-AccessConnectorTask

    Write-Host ''
    Write-Host '==> Installed' -ForegroundColor Green
    Write-Host ''
    Write-Host '    Check it came up:'
    Write-Host "      Get-ScheduledTaskInfo -TaskName '$TaskName'"
    Write-Host "      Get-Content -Path '$LogPath' -Tail 20 -Wait"
    Write-Host ''
    Write-Host '    You want "session established". "Access connector credential refused" means the token'
    Write-Host '    needs reissuing; "not eligible" means the access connector record, the licence or the'
    Write-Host '    PAM flag needs attention on the server.'
    Write-Host ''
    Write-Host '    Next, add the credentials for each target system to'
    Write-Host "      $EnvPath"
    Write-Host '    then restart the task. That file explains the naming.'
    Write-Host ''
} catch {
    Write-Host ''
    Write-Host "Install-AccessConnector.ps1: error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
