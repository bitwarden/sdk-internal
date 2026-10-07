#!/usr/bin/env bash
#
# Installs bwac as a system service. Takes a URL and an optional name.
#
#   sudo -E ./install-access-connector.sh https://bitwarden.example.com
#   sudo -E ./install-access-connector.sh https://bitwarden.example.com acme
#
#   Linux  -> systemd unit    /etc/systemd/system/bwac.service
#   macOS  -> launchd daemon  /Library/LaunchDaemons/com.bitwarden.bwac.plist
#
# The binary is the one next to this script, as in the release archive. The layout it installs
# is fixed:
#
#   /usr/local/bin/bwac                 binary            root  0755  (shared)
#   /etc/bwac/config.toml               settings          root  0644  (never secrets)
#   /etc/bwac/env                       token + creds     root  0400  (Linux only)
#   /opt/bwac/scripts                   rotation scripts  root  0755  (shared, connector cannot write)
#   /var/lib/bwac                       state             bwac  0700
#   /var/log/bwac                       connector log     bwac  0750  (macOS only)
#
# A name is only needed to run more than one connector on one host, as a host rotating for
# several organisations must, since a token belongs to one organisation. It moves the
# connector's config, token, state and log one level down:
#
#   /etc/bwac/<name>/config.toml, /etc/bwac/<name>/env, /var/lib/bwac/<name>,
#   /var/log/bwac/<name>, and the service becomes bwac-<name>.service
#   or com.bitwarden.bwac.<name>.
#
# The binary, the service account and /opt/bwac/scripts stay shared; the connector cannot write
# to the script directory, so one script can serve every connector. Point a connector's
# script_root elsewhere to give it scripts of its own.
#
# None of that is configurable. If you want a different layout, a different service
# account, or Bitwarden Cloud's separate api and identity URLs, install by hand: the
# config file and unit file this writes show you every piece.
#
# Two things here are not arbitrary:
#
#   * The token is not an argument. argv is world-readable via `ps` and
#     /proc/<pid>/cmdline, which is why the connector itself refuses --token. Put it in
#     BWAC_TOKEN, or let the script prompt for it with echo off.
#
#   * On macOS the token and per-target credentials live in the plist's
#     <EnvironmentVariables> dict. launchd has no EnvironmentFile=, and sets the dict without
#     a shell, which could not export the digit-led names most target UUIDs produce.
#
# Re-running replaces the binary, shared by every connector on the host, and leaves config.toml,
# the env file, the systemd unit and the plist alone, so your edits survive. Running connectors
# keep the old binary until restarted.
#
# To remove it, on Linux:
#
#   systemctl disable --now bwac
#   rm /etc/systemd/system/bwac.service /usr/local/bin/bwac
#   rm -rf /etc/bwac /var/lib/bwac && userdel bwac
#
# and on macOS:
#
#   launchctl bootout system/com.bitwarden.bwac
#   rm /Library/LaunchDaemons/com.bitwarden.bwac.plist
#   rm -rf /etc/bwac /var/lib/bwac /var/log/bwac /usr/local/bin/bwac
#   dscl . -delete /Users/_bwac; dscl . -delete /Groups/_bwac
#
# A named connector comes off the same way, with -<name> on the unit or .<name> on the
# label, and /etc/bwac/<name>, /var/lib/bwac/<name> and /var/log/bwac/<name> in place of
# the directories above.
#
# Leave the binary, the service account and /opt/bwac/scripts until the last connector on the
# host is gone. Rotation scripts in /opt/bwac/scripts are yours; nothing above deletes them.

set -euo pipefail

readonly PROGRAM="${0##*/}"
readonly BINARY_NAME="bwac"
readonly LABEL_PREFIX="com.bitwarden.bwac"

readonly BINARY_PATH="/usr/local/bin/$BINARY_NAME"
readonly SCRIPT_ROOT="/opt/bwac/scripts"
readonly CONFIG_ROOT="/etc/bwac"
readonly STATE_ROOT="/var/lib/bwac"
readonly LOG_ROOT="/var/log/bwac"

# Names that would land on top of something already sitting beside a named connector's
# directory: the env file here, and the scripts and logs directories on Windows.
readonly RESERVED_NAMES="env logs scripts"

# Set by set_paths.
NAME=""
LAUNCHD_LABEL=""
SYSTEMD_UNIT=""
CONFIG_DIR=""
CONFIG_FILE=""
ENV_FILE=""
STATE_DIR=""
LOG_DIR=""
UNIT_FILE=""
PLIST_FILE=""

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

# Fills in a template from templates/. Uses parameter expansion rather than sed, since two
# templates carry the token and a sed replacement would put it in argv, where ps can read it.
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
Installs bwac as a system service.

    $PROGRAM <bitwarden-url> [name]

The URL is your Bitwarden server, for example https://bitwarden.example.com. The connector
token comes from BWAC_TOKEN, or is prompted for with the input hidden:

    BWAC_TOKEN='0.access-connector.<id>.<secret>:<key>' sudo -E ./$PROGRAM https://bitwarden.example.com

The name is optional, and only needed to run a second connector on this host: it keeps that
connector's config, token, state, log and service separate from the others. Leave it out and
the connector installs to the single-connector layout.

There are no other options. The comments at the top of this script list the layout it
installs and how to remove it; OPERATIONS.md covers everything else.
HELP
}

# The name becomes part of a systemd unit file name, a launchd label and a path on three
# operating systems, so it is kept to a plain lowercase word.
validate_name() {
    local reserved

    case "$1" in
        '')            die "the name is empty; leave it out entirely for a single connector" ;;
        *[!a-z0-9_-]*) die "name '$1' must be lowercase letters, digits, '-' or '_'" ;;
        [!a-z0-9]*)    die "name '$1' must start with a letter or a digit" ;;
    esac
    [ "${#1}" -le 32 ] || die "name '$1' is longer than 32 characters"

    for reserved in $RESERVED_NAMES; do
        [ "$1" != "$reserved" ] || die "'$1' is taken: the layout already uses that name
       next to the directory this connector would get. Pick another."
    done
}

set_paths() {
    NAME="$1"

    if [ -n "$NAME" ]; then
        SYSTEMD_UNIT="$BINARY_NAME-$NAME.service"
        LAUNCHD_LABEL="$LABEL_PREFIX.$NAME"
        CONFIG_DIR="$CONFIG_ROOT/$NAME"
        STATE_DIR="$STATE_ROOT/$NAME"
        LOG_DIR="$LOG_ROOT/$NAME"
    else
        SYSTEMD_UNIT="$BINARY_NAME.service"
        LAUNCHD_LABEL="$LABEL_PREFIX"
        CONFIG_DIR="$CONFIG_ROOT"
        STATE_DIR="$STATE_ROOT"
        LOG_DIR="$LOG_ROOT"
    fi

    CONFIG_FILE="$CONFIG_DIR/config.toml"
    ENV_FILE="$CONFIG_DIR/env"
    UNIT_FILE="/etc/systemd/system/$SYSTEMD_UNIT"
    PLIST_FILE="/Library/LaunchDaemons/$LAUNCHD_LABEL.plist"
}

detect_platform() {
    case "$(uname -s)" in
        Linux)
            PLATFORM=linux
            ROOT_GROUP=root
            SERVICE_USER=bwac
            [ -d /run/systemd/system ] \
                || die "this host is not running systemd, so there is no service to install.
       Install by hand; the connector needs only BWAC_TOKEN and --config."
            ;;
        Darwin)
            PLATFORM=macos
            ROOT_GROUP=wheel
            SERVICE_USER=_bwac
            ;;
        *)
            die "unsupported platform: $(uname -s). Use Install-AccessConnector.ps1 on Windows."
            ;;
    esac
}

# Copies the bundled binary into place after the same two checks CI runs, so an archive for the
# wrong architecture fails here rather than as a service that will not start.
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

# Reads the token from the environment or a prompt and catches the two usual paste mistakes: a
# token cut at the ':', or not an access connector token at all. The connector checks the rest.
acquire_token() {
    step "Access connector token"

    if [ -n "${BWAC_TOKEN:-}" ]; then
        TOKEN="$BWAC_TOKEN"
        info "taken from BWAC_TOKEN"
    elif [ -t 0 ]; then
        printf '    Paste the access connector token (input hidden): ' >&2
        IFS= read -rs TOKEN
        printf '\n' >&2
    else
        die "no token. Set BWAC_TOKEN, or run interactively so the script can prompt."
    fi

    TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"

    case "$TOKEN" in
        '')                   die "the token is empty" ;;
        0.access-connector.*) ;;
        *)                    die "the token does not start '0.access-connector.'. This looks
       like a different kind of Bitwarden key, not an access connector token." ;;
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
        useradd --system --gid "$SERVICE_USER" --home-dir "$STATE_ROOT" --no-create-home \
            --shell "$shell_path" --comment "Bitwarden PAM access connector" "$SERVICE_USER"
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
        dscl . -create "/Users/$SERVICE_USER" RealName "Bitwarden PAM access connector"
        dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
        dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
        dscl . -create "/Users/$SERVICE_USER" IsHidden 1
        dscl . -create "/Users/$SERVICE_USER" Password '*'
    fi
    info "created"
}

create_directories() {
    step "Directories"

    # A named connector's directories sit inside these, which may belong to an unnamed
    # connector. Created only when missing, so that connector's mode and owner stay as they are.
    if [ -n "$NAME" ]; then
        [ -d "$CONFIG_ROOT" ] || install -d -m 0755 -o root -g "$ROOT_GROUP" "$CONFIG_ROOT"
        [ -d "$STATE_ROOT" ] || install -d -m 0755 -o root -g "$ROOT_GROUP" "$STATE_ROOT"
        if [ "$PLATFORM" = macos ] && [ ! -d "$LOG_ROOT" ]; then
            install -d -m 0750 -o "$SERVICE_USER" -g "$ROOT_GROUP" "$LOG_ROOT"
        fi
    fi

    # config.toml is read by the connector user and holds no secrets; the connector rejects
    # a config that tries to.
    install -d -m 0755 -o root -g "$ROOT_GROUP" "$CONFIG_DIR"

    # script_root: the connector reads and executes what is here and cannot write to it,
    # so it cannot install a new script for itself to run. Shared by every connector on
    # the host.
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

    render bwac.env.in | write_file "$ENV_FILE" 0400
    info "$ENV_FILE"
}

install_systemd_unit() {
    step "systemd unit"
    if [ -f "$UNIT_FILE" ]; then
        info "$UNIT_FILE exists; left alone (edit it to change the hardening)"
    else
        render bwac.service.in | write_file "$UNIT_FILE" 0644
        info "$UNIT_FILE"
    fi

    systemctl daemon-reload
    systemctl enable --now "$SYSTEMD_UNIT"
    info "enabled and started"
}

install_launchd_plist() {
    step "launchd daemon"
    if [ -f "$PLIST_FILE" ]; then
        info "$PLIST_FILE exists; left alone (edit it to change credentials)"
    else
        render launchd.plist.in | write_file "$PLIST_FILE" 0600
        info "$PLIST_FILE"
    fi

    # bootout first, so a re-install starts the binary we just wrote. Only this connector's
    # label is touched; any other connector on the host keeps running.
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

    You want "session established". "Access connector credential refused" means the token needs
    reissuing; "not eligible" means the access connector record, the licence or the PAM flag
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
        *)                  usage >&2; die "'$1' is not an http(s) URL; this script takes a URL
       and, for a second connector on this host, a name" ;;
    esac
    [ "$#" -le 2 ] || die "unexpected extra arguments after '$2'"
    readonly SERVER_URL

    if [ "$#" -eq 2 ]; then
        validate_name "$2"
    fi
    set_paths "${2:-}"

    detect_platform
    [ "$(id -u)" -eq 0 ] \
        || die "must run as root (try: sudo -E $PROGRAM $SERVER_URL${NAME:+ $NAME})"

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
