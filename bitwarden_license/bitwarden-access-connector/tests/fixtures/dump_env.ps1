# Fixture: writes the child's entire environment to OUT_PATH as JSON, so the test can assert
# both halves of the allowlist: that credentials are absent, and that the host essentials
# survived. A launcher bug that cleared everything would pass a leak-only check.

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
