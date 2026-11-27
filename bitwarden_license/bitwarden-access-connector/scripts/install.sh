#!/bin/sh

###########################################################################
# Downloads the Bitwarden Access Connector and installs it as a service, in one step:
#
#   curl -fsSL https://bwac.bitwarden.com/install | sh -s -- https://bitwarden.example.com
#   curl -fsSL https://bwac.bitwarden.com/install | sh -s -- https://bitwarden.example.com --name acme
#
# It downloads the bundle for this host, checks it against the release checksums, unpacks it
# into a temporary folder and runs the bundled install-access-connector.sh with sudo. Arguments
# after "--" go to that installer; run it with --help to see them. Running it again upgrades the
# connector.
#
# The installer prompts for the access connector token on the terminal. To install without a
# terminal, set BWAC_TOKEN in the environment instead; it never goes on a command line.
#
# Environment variables:
#   BWAC_VERSION  version to install (default: DEFAULT_BWAC_VERSION below)
#   BWAC_TOKEN    access connector token, instead of the prompt
###########################################################################

set -eu

# Updated by the version bump workflow (.github/workflows/version-bump.yml).
DEFAULT_BWAC_VERSION="0.1.0"
BWAC_VERSION="${BWAC_VERSION:-$DEFAULT_BWAC_VERSION}"
RELEASE_URL="https://github.com/bitwarden/access-connector/releases/download/v${BWAC_VERSION}"
INSTALLER="install-access-connector.sh"

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
  if ! command -v bash >/dev/null; then
    error "bash is required to run the installer."
  fi
}

platform_detect() {
  case "$(uname -s)" in
  Linux) PLATFORM="unknown-linux-gnu" ;;
  Darwin) PLATFORM="apple-darwin" ;;
  *) error "Unsupported platform: $(uname -s). On Windows, use install.ps1." ;;
  esac
}

arch_detect() {
  case "$(uname -m)" in
  x86_64 | amd64) ARCH="x86_64" ;;
  aarch64 | arm64) ARCH="aarch64" ;;
  *) error "Unsupported architecture: $(uname -m)" ;;
  esac
  if [ "$PLATFORM" = "apple-darwin" ] && [ "$ARCH" != "aarch64" ]; then
    error "On macOS, the Access Connector is only released for Apple silicon."
  fi
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
    wget -q --https-only -O "$2" "$1" || error "Download failed: $1"
  fi
}

# Runs the bundled installer as root. sudo asks for a password on the terminal by itself.
run_installer() {
  if [ "$(id -u)" -eq 0 ]; then
    set -- bash "$@"
  elif command -v sudo >/dev/null; then
    if [ -n "${BWAC_TOKEN:-}" ]; then
      # sudo drops the environment, and the token mustn't go on a command line.
      set -- sudo --preserve-env=BWAC_TOKEN bash "$@"
    else
      set -- sudo bash "$@"
    fi
  else
    error "The installer needs root. Run this as root, or install sudo."
  fi

  # With "curl | sh" this script's stdin is the download, so give the installer the terminal
  # to prompt for the token on. Without one, it needs BWAC_TOKEN.
  if [ -z "${BWAC_TOKEN:-}" ] && (: </dev/tty) 2>/dev/null; then
    "$@" </dev/tty
  else
    "$@"
  fi
}

main() {
  check_required
  platform_detect
  arch_detect

  archive="bwac-${ARCH}-${PLATFORM}-${BWAC_VERSION}.tar.gz"
  checksums="bwac-sha256-checksums-${BWAC_VERSION}.txt"

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  downloader "${RELEASE_URL}/${archive}" "${tmp_dir}/${archive}"
  downloader "${RELEASE_URL}/${checksums}" "${tmp_dir}/${checksums}"

  # Lines are "<sha256>  <file name>"; match the file name exactly.
  expected="$(awk -v name="$archive" '$2 == name {print $1}' "${tmp_dir}/${checksums}")"
  [ -n "$expected" ] || error "$archive is not listed in $checksums."
  actual="$(checksum "${tmp_dir}/${archive}")"
  [ "$actual" = "$expected" ] || error "Checksum mismatch for $archive. Expected $expected, got $actual."
  echo "Checksum OK."

  bundle_dir="${tmp_dir}/bundle"
  mkdir "$bundle_dir"
  tar -xzf "${tmp_dir}/${archive}" -C "$bundle_dir"
  [ -f "${bundle_dir}/${INSTALLER}" ] || error "$archive doesn't contain $INSTALLER."

  echo "Installing Bitwarden Access Connector ${BWAC_VERSION}"
  run_installer "${bundle_dir}/${INSTALLER}" "$@"
}

# Everything runs from here, so a download cut short by "curl | sh" runs nothing.
main "$@"
