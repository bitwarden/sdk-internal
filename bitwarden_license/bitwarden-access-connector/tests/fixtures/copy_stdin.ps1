# Fixture: reads stdin's JSON, extracts "OUT_PATH" from the credentials map, and writes the
# full stdin payload there. Invoked as: copy_stdin.ps1 <operation>
#
# The PowerShell mirror of copy_stdin.sh, so both launchers are held to the same contract.

param([string]$Operation)

$ErrorActionPreference = 'Stop'

$payload = [Console]::In.ReadToEnd()
$parsed = $payload | ConvertFrom-Json

$outPath = $parsed.credentials.OUT_PATH
if ([string]::IsNullOrEmpty($outPath)) {
    [Console]::Error.WriteLine('copy_stdin.ps1: OUT_PATH not found in credentials')
    exit 1
}

[System.IO.File]::WriteAllText($outPath, $payload)
exit 0
