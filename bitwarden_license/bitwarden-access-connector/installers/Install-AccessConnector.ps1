#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Bitwarden access connector as a scheduled task, following the Windows steps in
    README.md.

.DESCRIPTION
    Run it from the unpacked archive in an elevated PowerShell window. The token comes from
    BWAC_TOKEN or a hidden prompt, so it never appears on a command line.

    Running it again upgrades the binary and the launcher and restarts the task. It leaves an
    existing config.toml or env file as it is.

.PARAMETER ServerUrl
    Your Bitwarden server, for example https://bitwarden.example.com. For Bitwarden's cloud, use
    https://bitwarden.com (US) or https://bitwarden.eu (EU). Only needed the first time.

.PARAMETER Name
    Names the connector, for a host that runs one connector per organization. The connector's
    config, env file and logs go in C:\ProgramData\Bitwarden\bwac\<name>, and its task is named
    'Bitwarden PAM access connector (<name>)'. Use up to 32 lowercase letters, digits, '-' and '_'.

.EXAMPLE
    .\Install-AccessConnector.ps1 https://bitwarden.example.com

.EXAMPLE
    .\Install-AccessConnector.ps1 https://bitwarden.example.com -Name acme
#>
param(
    [Parameter(Position = 0)]
    [string] $ServerUrl,

    [Parameter(Position = 1)]
    [string] $Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskPrefix = 'Bitwarden PAM access connector'
$InstallDir = Join-Path $env:ProgramFiles 'Bitwarden\bwac'
$DataDir    = Join-Path $env:ProgramData 'Bitwarden\bwac'
$ScriptDir  = Join-Path $DataDir 'scripts'
$ExePath    = Join-Path $InstallDir 'bwac.exe'
$Launcher   = Join-Path $InstallDir 'Start-AccessConnector.ps1'

# Account names change with the display language, so the ACLs and task principal start from SIDs.
$SidAdmins         = 'S-1-5-32-544'
$SidSystem         = 'S-1-5-18'
$SidNetworkService = 'S-1-5-20'

$ExitCodeHints = @{
    1 = 'Startup error, such as a bad config file. Fix what the log names.'
    2 = 'The token was refused. Have an admin issue a new one and put it in {0}.'
    3 = "The connector isn't allowed to rotate. Check it isn't revoked, the license is active and PAM is enabled."
    4 = "Couldn't sign in. Check this host can reach your Bitwarden server."
    5 = 'Another bwac is running with the same token, for example one started from a console. Stop it, then start the task again.'
}

function Invoke-Native {
    param([string] $Command, [string[]] $Arguments)
    # Windows PowerShell turns native stderr into a terminating error under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('{0} failed (exit 0x{1:X8}): {2}' -f $Command, $LASTEXITCODE, ($output -join ' '))
    }
    $output
}

function Set-ExplicitAcl {
    param([string] $Path, [string[]] $Grants)
    $arguments = @($Path, '/inheritance:r')
    foreach ($grant in $Grants) { $arguments += '/grant:r', $grant }
    Invoke-Native 'icacls.exe' $arguments | Out-Null
}

function Get-Layout {
    param([string] $Name)
    if ($Name -and ($Name -cnotmatch '^[a-z0-9][a-z0-9_-]{0,31}$')) {
        throw "-Name must be up to 32 lowercase letters, digits, '-' or '_', starting with a letter or digit."
    }
    if ($Name -in 'scripts', 'logs', 'env') {
        throw "-Name can't be '$Name', since the default layout already uses that name."
    }
    $dir = if ($Name) { Join-Path $DataDir $Name } else { $DataDir }
    [pscustomobject] @{
        TaskName = if ($Name) { "$TaskPrefix ($Name)" } else { $TaskPrefix }
        Dir      = $dir
        Config   = Join-Path $dir 'config.toml'
        EnvFile  = Join-Path $dir 'env'
        LogDir   = Join-Path $dir 'logs'
        LogFile  = Join-Path $dir 'logs\bwac.log'
    }
}

function ConvertTo-ServerUrl {
    param([string] $Url)
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $uri) -or $uri.Scheme -notin 'https', 'http') {
        throw "'$Url' isn't a URL. Pass your Bitwarden server's URL, for example https://bitwarden.example.com."
    }
    $uri.AbsoluteUri.TrimEnd('/')
}

function Read-Token {
    $token = $env:BWAC_TOKEN
    if (-not $token) {
        $secure = Read-Host 'Access connector token' -AsSecureString
        $token = [Net.NetworkCredential]::new('', $secure).Password
    }
    $token = $token -replace '\s', ''
    if (-not $token.StartsWith('0.access-connector.')) {
        throw "That isn't an access connector token. It starts with '0.access-connector.'."
    }
    $colon = $token.IndexOf(':')
    if ($colon -lt 0 -or $colon -eq $token.Length - 1) {
        throw "The token is missing the part after the ':'. Copy all of it."
    }
    $token
}

function Stop-ConnectorTask {
    param([string] $TaskName)
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { return }
    Stop-ScheduledTask -TaskName $TaskName
    # Stop-ScheduledTask returns before the task has stopped, and the task ignores a start
    # request until it has.
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') {
        if ((Get-Date) -gt $deadline) { throw "'$TaskName' is still running. Stop it and run this again." }
        Start-Sleep -Milliseconds 250
    }
}

function Install-Binary {
    param([string] $Source, [string] $Version, [string] $TaskName)
    if ((Test-Path -LiteralPath $ExePath) -and
        (Get-FileHash -LiteralPath $Source).Hash -eq (Get-FileHash -LiteralPath $ExePath).Hash) {
        Write-Host "$ExePath is already $Version"
        return
    }
    Stop-ConnectorTask $TaskName
    try {
        Copy-Item -LiteralPath $Source -Destination $ExePath -Force
    } catch {
        throw ("Can't replace $ExePath, probably because another connector on this host is running " +
            "it. Stop them all, run this again, then start them:`n" +
            "  Get-ScheduledTask -TaskName '$TaskPrefix*' | Stop-ScheduledTask")
    }
    Write-Host "Installed $Version to $ExePath"
}

function Register-ConnectorTask {
    param($Layout)
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Exe "{1}" -Config "{2}" -EnvFile "{3}" -LogFile "{4}"' -f
        $Launcher, $ExePath, $Layout.Config, $Layout.EnvFile, $Layout.LogFile
    $user = ([Security.Principal.SecurityIdentifier] $SidNetworkService).Translate([Security.Principal.NTAccount]).Value

    $action    = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $InstallDir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType ServiceAccount -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

    Stop-ConnectorTask $Layout.TaskName
    Register-ScheduledTask -TaskName $Layout.TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

# Polls the log past its first $Skip lines until the connector signs in or exits, or $Seconds pass.
function Wait-Connector {
    param([string] $LogFile, [int] $Skip, [int] $Seconds = 20)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        $lines = @(Get-Content -LiteralPath $LogFile -ErrorAction SilentlyContinue | Select-Object -Skip $Skip)
        if ($lines -match 'session authenticated') { return [pscustomobject] @{ Status = 'authenticated' } }
        $exited = @($lines -match '^--- .* exited with -?\d+ ---$|^--- launcher error')
        if ($exited) {
            $code = if ($exited[-1] -match 'exited with (-?\d+)') { [int] $Matches[1] } else { $null }
            return [pscustomobject] @{ Status = 'exited'; Code = $code; Tail = $lines | Select-Object -Last 10 }
        }
    }
    [pscustomobject] @{ Status = 'timeout' }
}

try {
    $layout = Get-Layout $Name

    $bundledExe = Join-Path $PSScriptRoot 'bwac.exe'
    $template = Join-Path $PSScriptRoot 'templates\bwac-launcher.ps1'
    foreach ($path in $bundledExe, $template) {
        if (-not (Test-Path -LiteralPath $path)) { throw "$path is missing. Run this from the unpacked archive." }
    }
    $version = Invoke-Native $bundledExe '--version' | Select-Object -First 1

    $writeConfig = -not (Test-Path -LiteralPath $layout.Config)
    if ($writeConfig) {
        if (-not $ServerUrl) { throw "Pass your Bitwarden server's URL, for example https://bitwarden.example.com." }
        $url = ConvertTo-ServerUrl $ServerUrl
    } elseif ($ServerUrl) {
        Write-Warning "$($layout.Config) already exists, so -ServerUrl is ignored. Edit the file to change it."
    }
    $writeEnv = -not (Test-Path -LiteralPath $layout.EnvFile)
    if ($writeEnv) { $token = Read-Token }

    foreach ($dir in $InstallDir, $DataDir, $ScriptDir, $layout.Dir, $layout.LogDir) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $owners = "*$($SidAdmins):(OI)(CI)F", "*$($SidSystem):(OI)(CI)F"
    Set-ExplicitAcl $DataDir ($owners + "*$($SidNetworkService):(OI)(CI)R")
    Set-ExplicitAcl $ScriptDir ($owners + "*$($SidNetworkService):(OI)(CI)RX")
    Set-ExplicitAcl $layout.LogDir ($owners + "*$($SidNetworkService):(OI)(CI)M")

    Install-Binary $bundledExe $version $layout.TaskName
    Copy-Item -LiteralPath $template -Destination $Launcher -Force

    # The connector reads a byte order mark as part of the first line. WriteAllLines writes none.
    if ($writeConfig) {
        [IO.File]::WriteAllLines($layout.Config, [string[]] @(
            "script_root = '$ScriptDir'"
            ''
            '[environment]'
            "base = `"$url`""
        ))
        Write-Host "Wrote $($layout.Config)"
    }
    if ($writeEnv) {
        New-Item -ItemType File -Force -Path $layout.EnvFile | Out-Null
        Set-ExplicitAcl $layout.EnvFile "*$($SidAdmins):F", "*$($SidSystem):R", "*$($SidNetworkService):R"
        [IO.File]::WriteAllLines($layout.EnvFile, [string[]] @(
            '# Token and target credentials. See "Target credentials" in README.md.'
            '# Save without a byte order mark, then restart the scheduled task.'
            "BWAC_TOKEN=$token"
            'RUST_LOG=info'
        ))
        Write-Host "Wrote $($layout.EnvFile)"
    }

    Register-ConnectorTask $layout
    $skip = @(Get-Content -LiteralPath $layout.LogFile -ErrorAction SilentlyContinue).Count
    Start-ScheduledTask -TaskName $layout.TaskName
    Write-Host "Started the scheduled task '$($layout.TaskName)'. Waiting for the connector to sign in..."

    $result = Wait-Connector $layout.LogFile $skip
    if ($result.Status -eq 'authenticated') {
        Write-Host 'The connector signed in.' -ForegroundColor Green
    } elseif ($result.Status -eq 'timeout') {
        Write-Warning "The connector hasn't signed in yet. Watch the log: Get-Content '$($layout.LogFile)' -Tail 20 -Wait"
    } else {
        $result.Tail | ForEach-Object { Write-Host "  $_" }
        $hint = if ($null -ne $result.Code -and $ExitCodeHints.ContainsKey($result.Code)) {
            $ExitCodeHints[$result.Code] -f $layout.EnvFile
        } else {
            "Check $($layout.LogFile)."
        }
        Write-Warning "The connector stopped (exit $($result.Code)). $hint"
    }

    Write-Host ''
    Write-Host "Target credentials go in $($layout.EnvFile), and rotation scripts in $ScriptDir."
    Write-Host 'Restart the task after you change either file.'
} catch {
    Write-Host "Install-AccessConnector.ps1: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
