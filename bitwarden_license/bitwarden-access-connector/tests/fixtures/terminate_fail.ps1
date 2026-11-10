# Fixture: exits 1 for the terminate operation and 0 for every other one, draining stdin first.
# Invoked as: terminate_fail.ps1 <operation>

param([string]$Operation)

$ErrorActionPreference = 'Stop'

[void][Console]::In.ReadToEnd()

if ($Operation -eq 'terminate') {
    exit 1
}
exit 0
