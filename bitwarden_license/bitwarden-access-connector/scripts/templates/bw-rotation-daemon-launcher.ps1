#Requires -Version 5.1
<#
    Launcher for bw-rotation-daemon, written by Install-RotationDaemon.ps1.

    It exists for two reasons.

    The daemon takes its token and every per-target credential from environment
    variables, and most target UUIDs start with a digit. A machine-level environment
    variable would put the token in a registry key any user can read, and PowerShell
    cannot assign $env:85808642_... by name at all. Reading the ACL-restricted env file
    here and calling SetEnvironmentVariable(..., 'Process') avoids both: the values
    exist only in this process and the daemon it starts.

    And the daemon logs to stderr, which a scheduled task discards. This captures it to
    a log file that rolls at 10 MB, since Windows has no logrotate.

    Only stderr is redirected. The daemon writes nothing to stdout, and leaving that
    handle inherited means there is no second pipe to drain and so no way for the daemon
    to block on a full one.

    The daemon's exit code is passed through, so the task's LastTaskResult is the
    daemon's own: 0 clean shutdown, 1 startup error, 2 credential refused, 3 not
    eligible for the rotation endpoints.
#>
param(
    [Parameter(Mandatory = $true)][string] $Exe,
    [Parameter(Mandatory = $true)][string] $Config,
    [Parameter(Mandatory = $true)][string] $EnvFile,
    [Parameter(Mandatory = $true)][string] $LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MaxLogBytes = 10485760
$encoding = New-Object Text.UTF8Encoding($false)
$writer = $null
$written = 0L

function Open-Log {
    param([switch] $Roll)
    if ($script:writer) { $script:writer.Flush(); $script:writer.Dispose(); $script:writer = $null }
    if ($Roll -and (Test-Path -LiteralPath $LogFile)) {
        Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force
    }
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $script:writer = New-Object IO.StreamWriter($LogFile, $true, $script:encoding)
    $script:writer.AutoFlush = $true
    $script:written = (Get-Item -LiteralPath $LogFile).Length
}

function Write-DaemonLog {
    param([string] $Line)
    $script:writer.WriteLine($Line)
    $script:written += $Line.Length + 2
    if ($script:written -gt $script:MaxLogBytes) { Open-Log -Roll }
}

Open-Log
if ($written -gt $MaxLogBytes) { Open-Log -Roll }

$exitCode = 1
try {
    # NAME=VALUE, one per line; '#' comments and blanks skipped. One layer of matching
    # quotes is stripped, the way systemd's EnvironmentFile does it. Continuations are
    # not supported; keep each variable on one line.
    $loaded = 0
    foreach ($line in Get-Content -LiteralPath $EnvFile -Encoding UTF8) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $eq = $trimmed.IndexOf('=')
        if ($eq -lt 1) { continue }
        $name = $trimmed.Substring(0, $eq).Trim()
        $value = $trimmed.Substring($eq + 1)
        if ($value.Length -ge 2 -and
            (($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
             ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        $loaded++
    }

    Write-DaemonLog ('--- {0} starting {1} ({2} variables loaded) ---' -f
        (Get-Date -Format 'o'), $Exe, $loaded)

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ('run --config "{0}"' -f $Config)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Split-Path -Parent $Config

    $proc = New-Object Diagnostics.Process
    $proc.StartInfo = $psi
    [void] $proc.Start()

    while (-not $proc.StandardError.EndOfStream) { Write-DaemonLog $proc.StandardError.ReadLine() }
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode
    Write-DaemonLog ('--- {0} exited with {1} ---' -f (Get-Date -Format 'o'), $exitCode)
} catch {
    if ($writer) { Write-DaemonLog ('--- launcher error: {0} ---' -f $_.Exception.Message) }
    throw
} finally {
    if ($writer) { $writer.Flush(); $writer.Dispose() }
}

exit $exitCode
