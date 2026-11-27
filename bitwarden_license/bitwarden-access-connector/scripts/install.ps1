###########################################################################
# Downloads the Bitwarden Access Connector and installs it as a scheduled task, in one step.
# Run it in an elevated PowerShell window (Run as administrator):
#
#   $env:BWAC_SERVER_URL = 'https://bitwarden.example.com'; irm https://bwac.bitwarden.com/install.ps1 | iex
#
# or, to pass arguments the way Install-AccessConnector.ps1 takes them:
#
#   & ([scriptblock]::Create((irm https://bwac.bitwarden.com/install.ps1))) https://bitwarden.example.com -Name acme
#
# It downloads the bundle, checks it against the release checksums, unpacks it into a temporary
# folder and runs the bundled Install-AccessConnector.ps1. Running it again upgrades the
# connector.
#
# The installer prompts for the access connector token. To install without a prompt, set
# $env:BWAC_TOKEN instead; it never goes on a command line.
#
# Environment variables:
#   BWAC_VERSION     version to install (default: $defaultBwacVersion below)
#   BWAC_SERVER_URL  your Bitwarden server, when not passed as an argument
#   BWAC_NAME        the connector's name, when not passed as -Name
#   BWAC_TOKEN       access connector token, instead of the prompt
#
# Usually run as `irm <url> | iex`, so it uses `throw` instead of `exit` (which would close the
# caller's shell) and keeps its variables inside a script block.
###########################################################################

param(
  [Parameter(Position = 0)]
  [string] $ServerUrl = $env:BWAC_SERVER_URL,

  [Parameter(Position = 1)]
  [string] $Name = $env:BWAC_NAME
)

& {
  $ErrorActionPreference = "Stop"
  # Invoke-WebRequest is much slower with the progress bar on Windows PowerShell 5.1.
  $ProgressPreference = "SilentlyContinue"
  # Windows PowerShell 5.1 may not enable TLS 1.2 by default, which GitHub requires.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  # Updated by the version bump workflow (.github/workflows/version-bump.yml).
  $defaultBwacVersion = "0.1.0"
  $version = if ($env:BWAC_VERSION) { $env:BWAC_VERSION } else { $defaultBwacVersion }
  $releaseUrl = "https://github.com/bitwarden/access-connector/releases/download/v$version"
  $installer = "Install-AccessConnector.ps1"

  $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The installer needs an elevated PowerShell window. Open PowerShell with 'Run as administrator' and run this again."
  }

  # A 32-bit PowerShell on 64-bit Windows reports x86 in PROCESSOR_ARCHITECTURE
  # and the real architecture in PROCESSOR_ARCHITEW6432.
  $processorArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  switch ($processorArch) {
    "AMD64" { $arch = "x86_64" }
    default { throw "Unsupported architecture: $processorArch. The Access Connector is released for 64-bit x86 Windows only." }
  }

  $archive = "bwac-$arch-pc-windows-msvc-$version.zip"
  $checksums = "bwac-sha256-checksums-$version.txt"
  $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmpDir | Out-Null

  try {
    foreach ($file in $archive, $checksums) {
      Write-Output "Downloading $releaseUrl/$file"
      Invoke-WebRequest -UseBasicParsing -Uri "$releaseUrl/$file" -OutFile (Join-Path $tmpDir $file)
    }

    # Lines are "<sha256>  <file name>"; match the file name exactly.
    $expected = Get-Content (Join-Path $tmpDir $checksums) |
      ForEach-Object {
        $fields = -split $_
        if ($fields.Count -eq 2 -and $fields[1] -eq $archive) {
          $fields[0]
        }
      } |
      Select-Object -First 1
    if (-not $expected) {
      throw "$archive is not listed in $checksums."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmpDir $archive)).Hash
    if ($actual -ne $expected) {
      throw "Checksum mismatch for $archive. Expected $expected, got $actual."
    }
    Write-Output "Checksum OK."

    $bundleDir = Join-Path $tmpDir "bundle"
    Expand-Archive -Path (Join-Path $tmpDir $archive) -DestinationPath $bundleDir
    $installerPath = Join-Path $bundleDir $installer
    if (-not (Test-Path -LiteralPath $installerPath)) {
      throw "$archive doesn't contain $installer."
    }

    # A child PowerShell with -ExecutionPolicy Bypass, because the default policy on Windows
    # clients won't run a .ps1 file. It shares this console, so the token prompt still works,
    # and inherits BWAC_TOKEN from this process. Empty arguments are left out, since Windows
    # PowerShell drops them when it passes arguments to a native program.
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installerPath)
    if ($ServerUrl) { $arguments += $ServerUrl }
    if ($Name) { $arguments += "-Name", $Name }

    Write-Output "Installing Bitwarden Access Connector $version"
    & (Get-Process -Id $PID).Path @arguments
    if ($LASTEXITCODE -ne 0) {
      throw "$installer failed (exit $LASTEXITCODE)."
    }
  }
  finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
  }
}
