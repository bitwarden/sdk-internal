#!/usr/bin/env bash
#
# Installs bw-rotation-daemon as a system service. One argument, no options.
#
#   sudo -E ./install-rotation-daemon.sh https://bitwarden.example.com
#
#   Linux  -> systemd unit    /etc/systemd/system/bw-rotation-daemon.service
#   macOS  -> launchd daemon  /Library/LaunchDaemons/com.bitwarden.bw-rotation-daemon.plist
#
# The binary is the one sitting next to this script, which is how the release archive
# is laid out. The layout it installs is fixed, and is the one OPERATIONS.md documents:
#
#   /usr/local/bin/bw-rotation-daemon   binary            root  0755
#   /etc/bwrd/config.toml               settings          root  0644  (never secrets)
#   /etc/bwrd/env                       token + creds     root  0400  (Linux only)
#   /opt/bwrd/scripts                   rotation scripts  root  0755  (daemon cannot write)
#   /var/lib/bwrd                       state             bwrd  0700
#   /var/log/bwrd                       daemon log        bwrd  0750  (macOS only)
#
# None of that is configurable. If you want a different layout, a different service
# account, or Bitwarden Cloud's separate api and identity URLs, install by hand: the
# config file and unit file this writes show you every piece.
#
# Two things here are not arbitrary:
#
#   * The token is not an argument. argv is world-readable via `ps` and
#     /proc/<pid>/cmdline, which is why the daemon itself refuses --token. Put it in
#     BWRD_TOKEN, or let the script prompt for it with echo off.
#
#   * On macOS the token and per-target credentials live in the plist's
#     <EnvironmentVariables> dict rather than an env file. launchd has no
#     EnvironmentFile=, and most target UUIDs begin with a digit, which no POSIX shell
#     can export; launchd sets the dict without a shell, so digits are fine there.
#
# Re-running replaces the binary and leaves config.toml, the env file and the plist
# alone, so upgrading cannot lose credentials you added to them.
#
# To remove it, on Linux:
#
#   systemctl disable --now bw-rotation-daemon
#   rm /etc/systemd/system/bw-rotation-daemon.service /usr/local/bin/bw-rotation-daemon
#   rm -rf /etc/bwrd /var/lib/bwrd && userdel bwrd
#
# and on macOS:
#
#   launchctl bootout system/com.bitwarden.bw-rotation-daemon
#   rm /Library/LaunchDaemons/com.bitwarden.bw-rotation-daemon.plist
#   rm -rf /etc/bwrd /var/lib/bwrd /var/log/bwrd /usr/local/bin/bw-rotation-daemon
#   dscl . -delete /Users/_bwrd; dscl . -delete /Groups/_bwrd
#
# Rotation scripts in /opt/bwrd/scripts are yours; nothing above deletes them.

set -euo pipefail

readonly PROGRAM="${0##*/}"
readonly BINARY_NAME="bw-rotation-daemon"
readonly LAUNCHD_LABEL="com.bitwarden.bw-rotation-daemon"
readonly SYSTEMD_UNIT="bw-rotation-daemon.service"

readonly BINARY_PATH="/usr/local/bin/$BINARY_NAME"
readonly CONFIG_DIR="/etc/bwrd"
readonly CONFIG_FILE="$CONFIG_DIR/config.toml"
readonly ENV_FILE="$CONFIG_DIR/env"
readonly SCRIPT_ROOT="/opt/bwrd/scripts"
readonly STATE_DIR="/var/lib/bwrd"
readonly LOG_DIR="/var/log/bwrd"
readonly UNIT_FILE="/etc/systemd/system/$SYSTEMD_UNIT"
readonly PLIST_FILE="/Library/LaunchDaemons/$LAUNCHD_LABEL.plist"

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$SELF_DIR/templates"
readonly SELF_DIR

step() { printf '\n==> %s\n' "$*" >&2; }
info() { printf '    %s\n' "$*" >&2; }
die()  { printf '%s: error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

# Writes stdin to a file atomically, via a temp file in the same directory, so it is
# never briefly world-readable and never half-written. These files hold the token.
write_file() {
    local path="$1" mode="$2" tmp
    tmp="$(umask 077; mktemp "${path}.XXXXXX")"
    cat >"$tmp"
    chown "root:$ROOT_GROUP" "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$path"
}

# Fills in a template from templates/. The substitution is done with shell parameter
# expansion rather than sed because two of these carry the daemon token, and a sed
# replacement would put it in argv where ps can read it. It also sidesteps having to
# escape the delimiter and & in paths and URLs.
render() {
    local template="$TEMPLATE_DIR/$1" line

    [ -f "$template" ] || die "missing template $1.
       Expected it at $template -- run the script from the unpacked release archive."

    while IFS= read -r line || [ -n "$line" ]; do
        line=${line//@BINARY_NAME@/$BINARY_NAME}
        line=${line//@BINARY_PATH@/$BINARY_PATH}
        line=${line//@CONFIG_FILE@/$CONFIG_FILE}
        line=${line//@ENV_FILE@/$ENV_FILE}
        line=${line//@LAUNCHD_LABEL@/$LAUNCHD_LABEL}
        line=${line//@LOG_DIR@/$LOG_DIR}
        line=${line//@PLIST_FILE@/$PLIST_FILE}
        line=${line//@SCRIPT_ROOT@/$SCRIPT_ROOT}
        line=${line//@SERVER_URL@/$SERVER_URL}
        line=${line//@SERVICE_USER@/$SERVICE_USER}
        line=${line//@STATE_DIR@/$STATE_DIR}
        line=${line//@TOKEN@/$TOKEN}
        printf '%s\n' "$line"
    done <"$template"
}

usage() {
    cat <<HELP
Installs bw-rotation-daemon as a system service.

    $PROGRAM <bitwarden-url>

The URL is your Bitwarden server, for example https://bitwarden.example.com. The
daemon token comes from BWRD_TOKEN, or is prompted for with the input hidden:

    BWRD_TOKEN='0.daemon.<id>.<secret>:<key>' sudo -E ./$PROGRAM https://bitwarden.example.com

There are no other options. The comments at the top of this script list the layout
it installs and how to remove it; OPERATIONS.md covers everything else.
HELP
}

detect_platform() {
    case "$(uname -s)" in
        Linux)
            PLATFORM=linux
            ROOT_GROUP=root
            SERVICE_USER=bwrd
            [ -d /run/systemd/system ] \
                || die "this host is not running systemd, so there is no service to install.
       Install by hand; the daemon needs only BWRD_TOKEN and --config."
            ;;
        Darwin)
            PLATFORM=macos
            ROOT_GROUP=wheel
            SERVICE_USER=_bwrd
            ;;
        *)
            die "unsupported platform: $(uname -s). Use Install-RotationDaemon.ps1 on Windows."
            ;;
    esac
}

# Copies the bundled binary into place after checking it runs here. Those are the two
# checks CI runs after building, and they catch an archive for the wrong architecture
# now rather than as a service that will not start.
install_binary() {
    step "Binary"
    local bundled="$SELF_DIR/$BINARY_NAME"

    [ -f "$bundled" ] || die "no $BINARY_NAME next to this script.
       Expected it at $bundled -- run the script from the unpacked release archive."

    chmod +x "$bundled" 2>/dev/null || true
    "$bundled" --version >/dev/null 2>&1 \
        || die "$bundled does not run on this host ($(uname -s)/$(uname -m)).
       Check you unpacked the archive built for this target."
    "$bundled" run --help >/dev/null 2>&1 \
        || die "$bundled does not accept 'run --help'; is it really $BINARY_NAME?"

    install -m 0755 -o root -g "$ROOT_GROUP" "$bundled" "$BINARY_PATH"
    info "$BINARY_PATH ($("$BINARY_PATH" --version))"
}

# Reads the token from the environment or prompts for it, then checks the two things
# that actually go wrong when a token is pasted: it gets cut at the ':', or it is not
# a daemon token at all. The daemon validates the rest properly at startup.
acquire_token() {
    step "Daemon token"

    if [ -n "${BWRD_TOKEN:-}" ]; then
        TOKEN="$BWRD_TOKEN"
        info "taken from BWRD_TOKEN"
    elif [ -t 0 ]; then
        printf '    Paste the daemon token (input hidden): ' >&2
        IFS= read -rs TOKEN
        printf '\n' >&2
    else
        die "no token. Set BWRD_TOKEN, or run interactively so the script can prompt."
    fi

    TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"

    case "$TOKEN" in
        '')         die "the token is empty" ;;
        0.daemon.*) ;;
        *)          die "the token does not start '0.daemon.'. This looks like a different
       kind of Bitwarden key, not a rotation daemon token." ;;
    esac
    case "$TOKEN" in
        *:?*) ;;
        *)    die "the token has nothing after a ':'. It was truncated on copy -- copy the
       whole string, including the encryption key at the end." ;;
    esac
    # The token is embedded in XML on macOS. Real tokens are a UUID, base64 and
    # alphanumerics, so this only fires on a mangled paste.
    case "$TOKEN" in
        *'<'*|*'>'*|*'&'*|*'"'*) die "the token contains an XML metacharacter; it is mangled" ;;
    esac
}

create_service_account() {
    step "Service account: $SERVICE_USER"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        info "already exists"
        return 0
    fi

    if [ "$PLATFORM" = linux ]; then
        local shell_path=/bin/false candidate
        for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
            [ -x "$candidate" ] && { shell_path="$candidate"; break; }
        done
        getent group "$SERVICE_USER" >/dev/null 2>&1 || groupadd --system "$SERVICE_USER"
        useradd --system --gid "$SERVICE_USER" --home-dir "$STATE_DIR" --no-create-home \
            --shell "$shell_path" --comment "Bitwarden PAM rotation daemon" "$SERVICE_USER"
    else
        # macOS has no useradd. Hidden service accounts go straight into the local
        # directory node, in the id range Apple reserves for system daemons.
        local uid="" taken candidate
        taken="$(dscl . -list /Users UniqueID | awk '{print $2}'
                 dscl . -list /Groups PrimaryGroupID | awk '{print $2}')"
        for candidate in $(seq 300 400); do
            printf '%s\n' "$taken" | grep -qx "$candidate" || { uid="$candidate"; break; }
        done
        [ -n "$uid" ] || die "no free uid between 300 and 400 for the service account"

        dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$uid"
        dscl . -create "/Users/$SERVICE_USER" UniqueID "$uid"
        dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$uid"
        dscl . -create "/Users/$SERVICE_USER" RealName "Bitwarden PAM rotation daemon"
        dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
        dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
        dscl . -create "/Users/$SERVICE_USER" IsHidden 1
        dscl . -create "/Users/$SERVICE_USER" Password '*'
    fi
    info "created"
}

create_directories() {
    step "Directories"

    # config.toml is read by the daemon user and holds no secrets; the daemon rejects
    # a config that tries to.
    install -d -m 0755 -o root -g "$ROOT_GROUP" "$CONFIG_DIR"

    # script_root: the daemon reads and executes what is here and cannot write to it,
    # so it cannot install a new script for itself to run.
    install -d -m 0755 -o root -g "$ROOT_GROUP" "$SCRIPT_ROOT"

    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
    if [ "$PLATFORM" = macos ]; then
        install -d -m 0750 -o "$SERVICE_USER" -g "$ROOT_GROUP" "$LOG_DIR"
    fi

    info "$CONFIG_DIR, $SCRIPT_ROOT, $STATE_DIR"
}

write_config() {
    step "Configuration"
    if [ -f "$CONFIG_FILE" ]; then
        info "$CONFIG_FILE exists; left alone"
        return 0
    fi

    render config.toml.in | write_file "$CONFIG_FILE" 0644
    info "$CONFIG_FILE"
}

write_env_file() {
    step "Token and target credentials"
    if [ -f "$ENV_FILE" ]; then
        info "$ENV_FILE exists; left alone (edit it to change the token)"
        return 0
    fi

    render daemon.env.in | write_file "$ENV_FILE" 0400
    info "$ENV_FILE"
}

install_systemd_unit() {
    step "systemd unit"
    render bw-rotation-daemon.service.in | write_file "$UNIT_FILE" 0644

    systemctl daemon-reload
    systemctl enable --now "$SYSTEMD_UNIT"
    info "$UNIT_FILE, enabled and started"
}

install_launchd_plist() {
    step "launchd daemon"
    if [ -f "$PLIST_FILE" ]; then
        info "$PLIST_FILE exists; left alone (edit it to change credentials)"
    else
        render launchd.plist.in | write_file "$PLIST_FILE" 0600
        info "$PLIST_FILE"
    fi

    # bootout first, so a re-install starts the binary we just wrote.
    launchctl bootout "system/$LAUNCHD_LABEL" 2>/dev/null || true
    launchctl bootstrap system "$PLIST_FILE"
    info "loaded and started"
}

summary() {
    local creds status logs
    if [ "$PLATFORM" = linux ]; then
        creds="$ENV_FILE"
        status="systemctl status $SYSTEMD_UNIT"
        logs="journalctl -u $SYSTEMD_UNIT -f"
    else
        creds="$PLIST_FILE"
        status="launchctl print system/$LAUNCHD_LABEL"
        logs="tail -f $LOG_DIR/$BINARY_NAME.log"
    fi

    cat >&2 <<SUMMARY

==> Installed

    Check it came up:
      $status
      $logs

    You want "session established". "Daemon credential refused" means the token needs
    reissuing; "not eligible" means the daemon record, the licence or the PAM flag
    needs attention on the server.

    Next, add the credentials for each target system to
      $creds
    then restart the service. That file explains the naming.

SUMMARY
}

main() {
    case "${1:-}" in
        -h|--help)          usage; exit 0 ;;
        '')                 usage >&2; die "missing the Bitwarden server URL" ;;
        http://*|https://*) SERVER_URL="$1" ;;
        *)                  usage >&2; die "'$1' is not an http(s) URL; this script takes only a URL" ;;
    esac
    [ "$#" -eq 1 ] || die "unexpected extra arguments after '$1'"
    readonly SERVER_URL

    detect_platform
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo -E $PROGRAM $SERVER_URL)"

    install_binary
    acquire_token
    create_service_account
    create_directories
    write_config

    if [ "$PLATFORM" = linux ]; then
        write_env_file
        install_systemd_unit
    else
        install_launchd_plist
    fi

    summary
}

main "$@"
