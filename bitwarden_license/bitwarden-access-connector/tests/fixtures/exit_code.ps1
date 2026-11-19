# Fixture: reads stdin's JSON, extracts "EXIT_CODE" from the credentials map, and exits with
# that code. Invoked as: exit_code.ps1 <operation>
#
# The PowerShell mirror of exit_code.sh.

param([string]$Operation)

$ErrorActionPreference = 'Stop'

$payload = [Console]::In.ReadToEnd()
$parsed = $payload | ConvertFrom-Json

$code = $parsed.credentials.EXIT_CODE
if ([string]::IsNullOrEmpty($code)) {
    [Console]::Error.WriteLine('exit_code.ps1: EXIT_CODE not found in credentials')
    exit 1
}

exit ([int]$code)
