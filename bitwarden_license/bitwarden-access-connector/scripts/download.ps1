###########################################################################
# Downloads the Bitwarden Access Connector bundle for Windows and unpacks it.
# It doesn't install anything: follow README.md in the unpacked folder.
#
# Environment variables:
#   BWAC_VERSION  version to download (default: $defaultBwacVersion below)
#   BWAC_DIR      folder to unpack into (default: <Desktop>\bitwarden-access-connector-<version>)
#
# Usually run as `iwr <url> | iex`, so it uses `throw` instead of `exit` (which
# would close the caller's shell) and keeps its variables inside a script block.
###########################################################################

& {
  $ErrorActionPreference = "Stop"
  # Invoke-WebRequest is much slower with the progress bar on Windows PowerShell 5.1.
  $ProgressPreference = "SilentlyContinue"
  # Windows PowerShell 5.1 may not enable TLS 1.2 by default, which GitHub requires.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  # Updated by the version bump workflow (.github/workflows/version-bump.yml).
  $defaultBwacVersion = "0.1.0"
  $version = if ($env:BWAC_VERSION) { $env:BWAC_VERSION } else { $defaultBwacVersion }
  # Not the current folder: an elevated PowerShell starts in C:\Windows\system32.
  # Desktop can be empty for accounts without a profile desktop (e.g. Server Core), so fall back to the home folder.
  $parent = [Environment]::GetFolderPath("Desktop")
  if (-not $parent) { $parent = $HOME }
  $dir = if ($env:BWAC_DIR) { $env:BWAC_DIR } else { Join-Path $parent "bitwarden-access-connector-$version" }
  $releaseUrl = "https://github.com/bitwarden/access-connector/releases/download/v$version"

  # A 32-bit PowerShell on 64-bit Windows reports x86 in PROCESSOR_ARCHITECTURE
  # and the real architecture in PROCESSOR_ARCHITEW6432.
  $processorArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  switch ($processorArch) {
    "AMD64" { $arch = "x86_64" }
    default { throw "Unsupported architecture: $processorArch. The Access Connector is released for 64-bit x86 Windows only." }
  }

  if ((Test-Path $dir) -and (Get-ChildItem -Force $dir | Select-Object -First 1)) {
    throw "$dir already exists and isn't empty. Remove it or set BWAC_DIR to another folder."
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
      ForEach-Object { $fields = -split $_; if ($fields.Count -eq 2 -and $fields[1] -eq $archive) { $fields[0] } } |
      Select-Object -First 1
    if (-not $expected) {
      throw "$archive is not listed in $checksums."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmpDir $archive)).Hash
    if ($actual -ne $expected) {
      throw "Checksum mismatch for $archive. Expected $expected, got $actual."
    }
    Write-Output "Checksum OK."

    Expand-Archive -Path (Join-Path $tmpDir $archive) -DestinationPath $dir -Force
  }
  finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
  }

  $dir = (Resolve-Path $dir).Path
  Write-Output ""
  Write-Output "Bitwarden Access Connector $version is in $dir"
  Write-Output "To install it, follow $dir\README.md"
}
