#!/usr/bin/env bash
#
# Installs the Bitwarden access connector as a systemd service on Linux or a launchd daemon on
# macOS, following the steps in README.md. Run it with sudo from the unpacked archive:
#
#   sudo bash install-access-connector.sh https://bitwarden.example.com
#   sudo bash install-access-connector.sh https://bitwarden.example.com --name acme
#
# The token comes from BWAC_TOKEN or a hidden prompt, so it never appears on a command line.
# Running it again upgrades the binary and restarts the service. It leaves an existing config.toml,
# env file, systemd unit or launchd plist as it is.

set -eu
umask 022
export LC_ALL=C

readonly PROGRAM=install-access-connector.sh
HERE=$(cd "$(dirname "$0")" && pwd)
readonly HERE
readonly BINARY=/usr/local/bin/bwac
readonly SCRIPT_ROOT=/opt/bwac/scripts

die() {
    echo "$PROGRAM: $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: sudo bash $PROGRAM [<server-url>] [--name <name>]

<server-url>  Your Bitwarden server, for example https://bitwarden.example.com. For Bitwarden's
              cloud, use https://bitwarden.com (US) or https://bitwarden.eu (EU). Only needed the
              first time.
--name        Names the connector, for a host that runs one connector per organization. Use up
              to 32 lowercase letters, digits, '-' and '_'.

To pass the token in BWAC_TOKEN instead of at the prompt, use sudo --preserve-env=BWAC_TOKEN.
EOF
}

hint() {
    case $1 in
        1) echo 'Startup error, such as a bad config file. Fix what the log names.' ;;
        2) echo "The token was refused. Have an admin issue a new one and put it in $secrets." ;;
        3) echo "The connector isn't allowed to rotate. Check it isn't revoked, the license is active and PAM is enabled." ;;
        4) echo "Couldn't sign in. Check this host can reach your Bitwarden server." ;;
        5) echo 'Another bwac is running with the same token, for example one started from a console. Stop it, then restart this one.' ;;
        *) echo 'Check the log.' ;;
    esac
}

read_token() {
    token=${BWAC_TOKEN:-}
    if [ -z "$token" ]; then
        [ -t 0 ] || die 'Set BWAC_TOKEN, or run this in a terminal so it can prompt for the token.'
        IFS= read -rsp 'Access connector token: ' token
        echo >&2
    fi
    token=${token//[[:space:]]/}
    case $token in
        0.access-connector.*) ;;
        *) die "That isn't an access connector token. It starts with '0.access-connector.'." ;;
    esac
    case $token in
        *:?*) ;;
        *) die "The token is missing the part after the ':'. Copy all of it." ;;
    esac
    # The token goes into XML on macOS, so allow only the characters a token has.
    case $token in
        *[!A-Za-z0-9.:+/=_-]*) die "The token has characters a token doesn't have. Copy it again." ;;
    esac
}

# Fills in a template with bash alone, so the token never reaches a command line.
render() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line//@BINARY_NAME@/bwac}
        line=${line//@BINARY_PATH@/$BINARY}
        line=${line//@CONFIG_FILE@/$config}
        line=${line//@ENV_FILE@/$secrets}
        line=${line//@LAUNCHD_LABEL@/$service}
        line=${line//@LOG_DIR@/$log_dir}
        line=${line//@PLIST_FILE@/$secrets}
        line=${line//@SCRIPT_ROOT@/$SCRIPT_ROOT}
        line=${line//@SERVICE_USER@/$user}
        line=${line//@STATE_DIR@/$state_dir}
        line=${line//@TOKEN@/$token}
        printf '%s\n' "$line"
    done <"$HERE/templates/$1"
}

create_user() {
    if [ "$os" = linux ]; then
        getent group "$user" >/dev/null || groupadd --system "$user"
        useradd --system --gid "$user" --home-dir /var/lib/bwac --no-create-home \
            --shell /usr/sbin/nologin "$user"
        return
    fi
    # macOS has no useradd. Take the first ID from 300 to 400 that no user or group has.
    local taken id=300
    taken=$({ dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $NF}')
    while grep -qx "$id" <<<"$taken"; do id=$((id + 1)); done
    [ "$id" -le 400 ] || die "There's no free ID from 300 to 400 for the $user account."
    dscl . -create "/Groups/$user" PrimaryGroupID "$id"
    dscl . -create "/Users/$user" UniqueID "$id"
    dscl . -create "/Users/$user" PrimaryGroupID "$id"
    dscl . -create "/Users/$user" UserShell /usr/bin/false
    dscl . -create "/Users/$user" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$user" IsHidden 1
    dscl . -create "/Users/$user" Password '*'
}

url='' name='' token=''
while [ $# -gt 0 ]; do
    case $1 in
        --name)
            [ $# -ge 2 ] || die '--name needs a value.'
            name=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*) die "Unknown option $1. See --help." ;;
        *)
            [ -z "$url" ] || die "Unexpected argument $1. See --help."
            url=$1
            shift
            ;;
    esac
done

name_pattern='^[a-z0-9][a-z0-9_-]{0,31}$'
if [ -n "$name" ] && ! [[ $name =~ $name_pattern ]]; then
    die "--name must be up to 32 lowercase letters, digits, '-' or '_', starting with a letter or digit."
fi
case $name in
    scripts | logs | env) die "--name can't be '$name', since the default layout already uses that name." ;;
esac

config_dir=/etc/bwac${name:+/$name}
config=$config_dir/config.toml
state_dir=/var/lib/bwac${name:+/$name}
log_dir=/var/log/bwac${name:+/$name}

case $(uname -s) in
    Linux)
        [ -d /run/systemd/system ] || die "This host doesn't run systemd. Install by hand, as README.md describes."
        os=linux group=root user=bwac
        service=bwac${name:+-$name}
        secrets=$config_dir/env secrets_template=bwac.env.in secrets_mode=0400
        unit=/etc/systemd/system/$service.service
        follow="sudo journalctl -u $service -f"
        restart="sudo systemctl restart $service"
        ;;
    Darwin)
        os=macos group=wheel user=_bwac
        service=com.bitwarden.bwac${name:+.$name}
        secrets=/Library/LaunchDaemons/$service.plist secrets_template=launchd.plist.in secrets_mode=0600
        log=$log_dir/bwac.log
        follow="sudo tail -f $log"
        restart="sudo launchctl bootout system/$service && sudo launchctl bootstrap system $secrets"
        ;;
    *) die 'This script is for Linux and macOS. On Windows, use Install-AccessConnector.ps1.' ;;
esac
[ "$(id -u)" -eq 0 ] || die 'Run this with sudo.'

for file in bwac templates/bwac.env.in templates/bwac.service.in templates/launchd.plist.in; do
    [ -f "$HERE/$file" ] || die "$HERE/$file is missing. Run this from the unpacked archive."
done
bundled=$HERE/bwac
# The release archive is a zip, which doesn't keep the execute bit.
chmod +x "$bundled"
version=$("$bundled" --version) || die "$bundled doesn't run on this host. Check the archive is the one for $(uname -sm)."

write_config=false
if [ ! -f "$config" ]; then
    [ -n "$url" ] || die "Pass your Bitwarden server's URL, for example https://bitwarden.example.com."
    case $url in
        http://?* | https://?*) url=${url%/} ;;
        *) die "'$url' isn't a URL. Pass your Bitwarden server's URL, for example https://bitwarden.example.com." ;;
    esac
    write_config=true
elif [ -n "$url" ]; then
    echo "Warning: $config already exists, so the URL is ignored. Edit the file to change it." >&2
fi
write_secrets=false
if [ ! -f "$secrets" ]; then
    read_token
    write_secrets=true
fi

if ! id -u "$user" >/dev/null 2>&1; then
    create_user
    echo "Created the $user account"
fi
mkdir -p /usr/local/bin
install -d -m 0755 -o root -g "$group" /etc/bwac "$config_dir" "$SCRIPT_ROOT"
install -d -m 0700 -o "$user" -g "$user" /var/lib/bwac "$state_dir"
if [ "$os" = macos ]; then
    install -d -m 0750 -o "$user" -g "$group" /var/log/bwac "$log_dir"
fi

if cmp -s "$bundled" "$BINARY"; then
    echo "$BINARY is already $version"
else
    install -m 0755 -o root -g "$group" "$bundled" "$BINARY"
    echo "Installed $version to $BINARY"
fi

if $write_config; then
    cat >"$config" <<EOF
script_root = "$SCRIPT_ROOT"

[environment]
base = "$url"
EOF
    echo "Wrote $config"
fi
# The env file (Linux) or plist (macOS) holds the token, so only root can read it.
if $write_secrets; then
    (umask 077 && render "$secrets_template" >"$secrets")
    chmod "$secrets_mode" "$secrets"
    echo "Wrote $secrets"
fi
if [ "$os" = linux ] && [ ! -f "$unit" ]; then
    render bwac.service.in >"$unit"
    echo "Wrote $unit"
fi

if [ "$os" = linux ]; then
    systemctl daemon-reload
    systemctl enable --quiet "$service"
    since=$(date +%s)
    systemctl restart "$service"
    logs() { journalctl _SYSTEMD_UNIT="$service.service" --since "@$since" -o cat --no-pager; }
    running() { [ "$(systemctl show -p SubState --value "$service")" = running ]; }
    exit_code() { systemctl show -p ExecMainStatus --value "$service"; }
else
    skip=0
    [ ! -f "$log" ] || skip=$(wc -l <"$log")
    if launchctl print "system/$service" >/dev/null 2>&1; then
        launchctl kickstart -k "system/$service"
    else
        launchctl bootstrap system "$secrets"
    fi
    logs() { tail -n "+$((skip + 1))" "$log" 2>/dev/null; }
    running() { launchctl print "system/$service" | grep -q $'^\tstate = running'; }
    exit_code() { launchctl print "system/$service" | awk -F' = ' '/^\tlast exit code = /{print $2 + 0}'; }
fi
echo "Started $service. Waiting for the connector to sign in..."

# Waits up to 20 seconds for the connector to sign in or exit.
result=timeout
for _ in $(seq 20); do
    sleep 1
    if logs | grep -q 'session authenticated'; then
        result=signed-in
        break
    fi
    if ! running; then
        result=exited
        break
    fi
done

case $result in
    signed-in) echo 'The connector signed in.' ;;
    timeout) echo "Warning: The connector hasn't signed in yet. Watch the log: $follow" >&2 ;;
    exited)
        code=$(exit_code)
        logs | tail -n 10 | sed 's/^/  /'
        echo "Warning: The connector stopped (exit $code). $(hint "$code")" >&2
        ;;
esac

echo
echo "Target credentials go in $secrets, and rotation scripts in $SCRIPT_ROOT."
echo "Restart the connector after you change either: $restart"
