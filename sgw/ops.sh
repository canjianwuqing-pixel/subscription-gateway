#!/usr/bin/env bash
set -euo pipefail
umask 077

SGW_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
RUNTIME=$SGW_DIR/runtime
ENV_FILE=$SGW_DIR/.env
COMPOSE_FILE=$SGW_DIR/docker-compose.yml

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf 'OK: %s\n' "$*"; }
warning() { printf 'WARNING: %s\n' "$*" >&2; }
require_root() { (( EUID == 0 )) || die 'Run as root'; }
install_packages_if_approved() {
    local answer
    read -r -p "Install required system package(s) $* using apt? [y/N] " answer
    [[ $answer == y || $answer == Y ]] || die 'Required dependency not installed'
    apt-get update >/dev/null || die 'apt update failed'
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null || die 'apt install failed'
}
compose() { docker compose --project-directory "$SGW_DIR" -f "$COMPOSE_FILE" "$@"; }
env_value() {
    local key=$1
    [[ -f $ENV_FILE ]] || return 1
    awk -F= -v key="$key" '$1 == key { print substr($0, index($0,"=")+1); exit }' "$ENV_FILE"
}
valid_domain() {
    local value=$1 label
    [[ ${#value} -le 253 && $value =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || return 1
    IFS=. read -r -a labels <<< "$value"
    for label in "${labels[@]}"; do (( ${#label} <= 63 )) || return 1; done
}
valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_secret_path() { [[ $1 =~ ^[A-Za-z0-9_-]{12,128}$ ]]; }
check_os_arch_disk() {
    [[ $(uname -s) == Linux ]] || die 'Only Linux is supported'
    [[ -r /etc/os-release ]] || die 'Cannot identify operating system'
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ $ID == debian || $ID == ubuntu ]] || die 'Only Debian and Ubuntu are supported'
    [[ $(getconf LONG_BIT) == 64 ]] || die '64-bit system required'
    case $(uname -m) in x86_64|aarch64) ;; *) die 'Unsupported CPU architecture';; esac
    local available
    available=$(df -Pk "$SGW_DIR" | awk 'NR==2 {print $4}')
    (( available >= 2097152 )) || die 'At least 2 GiB free disk space is required'
}
check_platform() {
    check_os_arch_disk
    for command in curl openssl getent awk sed stat; do
        command -v "$command" >/dev/null || die "Missing command: $command"
    done
}
ensure_docker() {
    if command -v docker >/dev/null && docker version >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        return 0
    fi
    local response script
    read -r -p 'Docker/Compose not available. Install official Docker now? [y/N] ' response
    [[ $response == y || $response == Y ]] || die 'Docker is required'
    script=$(mktemp)
    curl --proto '=https' --tlsv1.2 -fsSL https://get.docker.com -o "$script" || die 'Docker installer download failed'
    sh "$script" || die 'Docker installation failed'
    rm -f -- "$script"
    docker version >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
        || die 'Docker or Compose validation failed'
}
make_runtime() {
    local path
    for path in "$RUNTIME" "$RUNTIME/ssl" "$RUNTIME/backups"; do
        [[ ! -L $path ]] || die 'Runtime directory must not be a symbolic link'
    done
    mkdir -p "$RUNTIME"/{data,control,generated,logs,ssl/staging,ssl/releases,backups/database}
    for path in "$RUNTIME"/{data,control,generated,logs,ssl,ssl/staging,ssl/releases,backups,backups/database}; do
        [[ -d $path && ! -L $path ]] || die 'Unsafe runtime subdirectory'
    done
    chmod 0750 "$RUNTIME" "$RUNTIME"/{data,control,generated,logs,ssl,ssl/staging,ssl/releases,backups,backups/database}
    chown 82:82 "$RUNTIME/data" "$RUNTIME/control" "$RUNTIME/backups/database"
    chgrp 82 "$RUNTIME/ssl" "$RUNTIME/ssl/releases"
    chmod 0750 "$RUNTIME/data" "$RUNTIME/control" "$RUNTIME/backups/database"
}
certificate_verify() {
    local certificate=$1 key=$2 domain=$3 remaining=${4:-0} cert_public key_public
    [[ $remaining =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    [[ -f $certificate && -f $key && ! -L $certificate && ! -L $key ]] || return 1
    openssl x509 -in "$certificate" -noout >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -checkend "$remaining" -noout >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -checkhost "$domain" -noout >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:' || return 1
    cert_public=$(openssl x509 -in "$certificate" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
    key_public=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum) || return 1
    [[ ${cert_public%% *} == "${key_public%% *}" ]]
}
acme_binary() {
    local binary=/root/.acme.sh/acme.sh temporary
    if [[ -x $binary ]]; then
        chmod -R go-rwx /root/.acme.sh
        printf '%s\n' "$binary"
        return
    fi
    command -v git >/dev/null || install_packages_if_approved git
    temporary=$(mktemp -d)
    git clone --depth 1 https://github.com/acmesh-official/acme.sh.git "$temporary/acme.sh" >/dev/null 2>&1 \
        || die 'Official acme.sh clone failed'
    "$temporary/acme.sh/acme.sh" --install --home /root/.acme.sh >/dev/null 2>&1 \
        || die 'acme.sh installation failed'
    rm -rf -- "$temporary"
    [[ -x $binary ]] || die 'acme.sh executable missing after installation'
    chmod -R go-rwx /root/.acme.sh
    printf '%s\n' "$binary"
}
port_80_free() {
    command -v ss >/dev/null || return 1
    ! ss -H -ltn '( sport = :80 )' | grep -q .
}
http_dns_matches_local() {
    local domain=$1 address
    command -v ip >/dev/null || return 1
    while read -r address; do
        [[ -n $address ]] || continue
        ip -4 -o addr show | grep -Fq " $address/" && return 0
    done < <(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u)
    return 1
}
acquire_certificate() {
    local mode=$1 domain=$2 acme fullchain key token zone
    fullchain=$RUNTIME/ssl/staging/fullchain.pem
    key=$RUNTIME/ssl/staging/privkey.pem
    rm -f -- "$fullchain" "$key"
    if [[ $mode == existing ]]; then
        local supplied_cert supplied_key
        read -r -p 'Existing fullchain.pem absolute path: ' supplied_cert
        read -r -p 'Existing privkey.pem absolute path: ' supplied_key
        [[ $supplied_cert == /* && $supplied_key == /* ]] || die 'Certificate paths must be absolute'
        cp -- "$supplied_cert" "$fullchain" && cp -- "$supplied_key" "$key" \
            || die 'Cannot copy existing certificate'
    elif [[ $mode == http-01 ]]; then
        command -v socat >/dev/null || install_packages_if_approved socat
        command -v ip >/dev/null && command -v ss >/dev/null \
            || install_packages_if_approved iproute2
        port_80_free || die 'Port 80 is occupied; select DNS-01 or existing certificate'
        http_dns_matches_local "$domain" || die 'Domain A record does not match a local IPv4 address'
        acme=$(acme_binary)
        "$acme" --issue --server letsencrypt --standalone -d "$domain" >/dev/null 2>&1 \
            || die 'HTTP-01 issuance failed'
        "$acme" --install-cert -d "$domain" --fullchain-file "$fullchain" --key-file "$key" >/dev/null 2>&1 \
            || die 'Cannot install issued certificate into staging'
        chmod -R go-rwx /root/.acme.sh
    elif [[ $mode == dns-cf ]]; then
        acme=$(acme_binary)
        read -r -s -p 'Cloudflare DNS API Token: ' token; printf '\n'
        token=$(printf '%s' "$token" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -n $token ]] || die 'Cloudflare Token is empty'
        read -r -p 'Cloudflare Zone ID (blank if unnecessary): ' zone
        zone=$(printf '%s' "$zone" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        export CF_Token=$token
        if [[ -n $zone ]]; then export CF_Zone_ID=$zone; fi
        if ! "$acme" --issue --server letsencrypt --dns dns_cf -d "$domain" >/dev/null 2>&1; then
            unset CF_Token CF_Zone_ID token
            die 'Cloudflare DNS-01 issuance failed'
        fi
        unset CF_Token CF_Zone_ID token
        "$acme" --install-cert -d "$domain" --fullchain-file "$fullchain" --key-file "$key" >/dev/null 2>&1 \
            || die 'Cannot install issued certificate into staging'
        chmod -R go-rwx /root/.acme.sh
    else
        die 'Unsupported certificate mode'
    fi
    chmod 0640 "$fullchain"
    chmod 0600 "$key"
    certificate_verify "$fullchain" "$key" "$domain" || die 'Staging certificate validation failed'
}
register_acme_hook() {
    local mode=$1 domain=$2 acme hook
    [[ $mode != existing ]] || return 0
    acme=$(acme_binary)
    hook=$(ensure_deploy_hook)
    "$acme" --install-cert -d "$domain" \
        --fullchain-file "$RUNTIME/ssl/staging/fullchain.pem" \
        --key-file "$RUNTIME/ssl/staging/privkey.pem" \
        --reloadcmd "$hook" >/dev/null 2>&1 || return 1
    chmod -R go-rwx /root/.acme.sh
}
ensure_deploy_hook() {
    local hook=$RUNTIME/ssl/deploy-hook.sh
    [[ ! -L $hook ]] || die 'Unsafe deploy hook path'
    printf '#!/usr/bin/env bash\nexec %q --deploy-staged-certificate\n' "$SGW_DIR/../setup.sh" > "$hook.tmp"
    chown root:root "$hook.tmp"
    chmod 0700 "$hook.tmp"
    sync -f "$hook.tmp"
    mv -f -- "$hook.tmp" "$hook"
    printf '%s\n' "$hook"
}
cert_activate() {
    local domain=$1 defer_reload=${2:-no} old= release target
    certificate_verify "$RUNTIME/ssl/staging/fullchain.pem" "$RUNTIME/ssl/staging/privkey.pem" "$domain" \
        || return 1
    if [[ -L $RUNTIME/ssl/active ]]; then old=$(readlink "$RUNTIME/ssl/active"); fi
    release=releases/$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)
    target=$RUNTIME/ssl/$release
    mkdir -m 0750 "$target"
    chgrp 82 "$target"
    cp -- "$RUNTIME/ssl/staging/fullchain.pem" "$target/fullchain.pem"
    cp -- "$RUNTIME/ssl/staging/privkey.pem" "$target/privkey.pem"
    chmod 0640 "$target/fullchain.pem"
    chgrp 82 "$target/fullchain.pem"
    chmod 0600 "$target/privkey.pem"
    sync -f "$target/fullchain.pem"
    sync -f "$target/privkey.pem"
    if [[ -n $old ]]; then
        ln -s "$old" "$RUNTIME/ssl/backup.next"
        mv -Tf -- "$RUNTIME/ssl/backup.next" "$RUNTIME/ssl/backup"
    fi
    ln -s "$release" "$RUNTIME/ssl/active.next"
    mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
    if [[ $defer_reload != yes && -f $ENV_FILE && -n $(compose ps -q gateway 2>/dev/null) ]]; then
        if ! compose exec -T gateway nginx -t >/dev/null 2>&1 \
            || ! compose exec -T admin nginx -t >/dev/null 2>&1 \
            || ! compose exec -T gateway nginx -s reload >/dev/null 2>&1 \
            || ! compose exec -T admin nginx -s reload >/dev/null 2>&1; then
            if [[ -n $old ]]; then
                ln -s "$old" "$RUNTIME/ssl/active.next"
                mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
                compose exec -T gateway nginx -t >/dev/null 2>&1 || true
                compose exec -T admin nginx -t >/dev/null 2>&1 || true
                compose exec -T gateway nginx -s reload >/dev/null 2>&1 || true
                compose exec -T admin nginx -s reload >/dev/null 2>&1 || true
            fi
            warning 'Certificate activation failed; previous active certificate restored'
            return 1
        fi
    fi
}
wait_health() {
    local service id state attempt
    for service in admin gateway; do
        id=$(compose ps -q "$service")
        [[ -n $id ]] || return 1
        for attempt in {1..60}; do
            state=$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || true)
            [[ $state == healthy ]] && break
            [[ $state == unhealthy ]] && return 1
            sleep 2
        done
        [[ $state == healthy ]] || return 1
    done
}
admin_cli() { compose run --rm --no-deps -T --entrypoint su-exec admin www-data php /app/src/cli.php "$@"; }
