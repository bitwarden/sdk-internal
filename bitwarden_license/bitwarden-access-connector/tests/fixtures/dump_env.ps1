# Fixture: writes the child's entire environment to OUT_PATH as JSON, so the test can check both
# that credentials are absent and that host essentials survive.

param([string]$Operation)

$ErrorActionPreference = 'Stop'

$payload = [Console]::In.ReadToEnd()
$parsed = $payload | ConvertFrom-Json

$outPath = $parsed.credentials.OUT_PATH
if ([string]::IsNullOrEmpty($outPath)) {
    [Console]::Error.WriteLine('dump_env.ps1: OUT_PATH not found in credentials')
    exit 1
}

$vars = @{}
foreach ($entry in Get-ChildItem Env:) {
    $vars[$entry.Name] = $entry.Value
}

[System.IO.File]::WriteAllText($outPath, ($vars | ConvertTo-Json -Depth 3))
exit 0
