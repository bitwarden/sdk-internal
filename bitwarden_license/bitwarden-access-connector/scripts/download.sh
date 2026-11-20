#!/bin/sh

###########################################################################
# Downloads the Bitwarden Access Connector bundle for Linux and unpacks it.
# It doesn't install anything: follow README.md in the unpacked folder.
#
# Environment variables:
#   BWAC_VERSION  version to download (default: DEFAULT_BWAC_VERSION below)
#   BWAC_DIR      folder to unpack into (default: ./bitwarden-access-connector-<version>)
###########################################################################

set -eu

# Updated by the version bump workflow (.github/workflows/version-bump.yml).
DEFAULT_BWAC_VERSION="0.1.0"
BWAC_VERSION="${BWAC_VERSION:-$DEFAULT_BWAC_VERSION}"
BWAC_DIR="${BWAC_DIR:-$(pwd)/bitwarden-access-connector-${BWAC_VERSION}}"
RELEASE_URL="https://github.com/bitwarden/access-connector/releases/download/v${BWAC_VERSION}"

error() {
  echo "Error: $1" >&2
  exit 1
}

check_required() {
  if ! command -v curl >/dev/null && ! command -v wget >/dev/null; then
    error "curl or wget is required to download the Access Connector."
  fi
  if ! command -v tar >/dev/null; then
    error "tar is required to unpack the Access Connector."
  fi
  if ! command -v sha256sum >/dev/null && ! command -v shasum >/dev/null; then
    error "sha256sum or shasum is required to check the download."
  fi
}

platform_detect() {
  case "$(uname -s)" in
  Linux) PLATFORM="unknown-linux-gnu" ;;
  Darwin) error "The Access Connector isn't released for macOS yet." ;;
  *) error "Unsupported platform: $(uname -s). On Windows, use download.ps1." ;;
  esac
}

arch_detect() {
  case "$(uname -m)" in
  x86_64 | amd64) ARCH="x86_64" ;;
  aarch64 | arm64) ARCH="aarch64" ;;
  *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

checksum() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

downloader() {
  echo "Downloading $1"
  if command -v curl >/dev/null; then
    # HTTPS only, also for the redirect GitHub sends to its download host.
    curl -fsSL --proto '=https' --proto-redir '=https' -o "$2" "$1" || error "Download failed: $1"
  else
    wget -q -O "$2" "$1" || error "Download failed: $1"
  fi
}

main() {
  check_required
  platform_detect
  arch_detect

  if [ -e "$BWAC_DIR" ] && [ -n "$(ls -A "$BWAC_DIR" 2>/dev/null)" ]; then
    error "$BWAC_DIR already exists and isn't empty. Remove it or set BWAC_DIR to another folder."
  fi

  archive="bwac-${ARCH}-${PLATFORM}-${BWAC_VERSION}.tar.gz"
  checksums="bwac-sha256-checksums-${BWAC_VERSION}.txt"

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  downloader "${RELEASE_URL}/${archive}" "${tmp_dir}/${archive}"
  downloader "${RELEASE_URL}/${checksums}" "${tmp_dir}/${checksums}"

  # Lines are "<sha256>  <file name>"; match the file name exactly.
  expected="$(awk -v name="$archive" '$2 == name {print $1}' "${tmp_dir}/${checksums}")"
  [ -n "$expected" ] || error "$archive is not listed in $checksums."
  actual="$(checksum "${tmp_dir}/${archive}")"
  [ "$actual" = "$expected" ] || error "Checksum mismatch for $archive. Expected $expected, got $actual."
  echo "Checksum OK."

  mkdir -p "$BWAC_DIR"
  tar -xzf "${tmp_dir}/${archive}" -C "$BWAC_DIR"

  echo
  echo "Bitwarden Access Connector ${BWAC_VERSION} is in ${BWAC_DIR}"
  echo "To install it, follow ${BWAC_DIR}/README.md"
}

main "$@"
