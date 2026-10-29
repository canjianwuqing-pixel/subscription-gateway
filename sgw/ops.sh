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

# Normalize only tracked application PHP, never runtime data or untracked files.
# Archive installations are checked instead; image construction also fixes modes.
prepare_admin_source_permissions() {
    local repository=$1 source_root=$1/sgw/admin/src entry mode path directory
    local -a entries=()
    [[ -d $source_root && ! -L $repository/sgw && ! -L $repository/sgw/admin && ! -L $source_root ]] \
        || die 'Unsafe Admin source directory'
    if git -C "$repository" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$repository" ls-files --error-unmatch -- 'sgw/admin/src/*.php' >/dev/null \
            || die 'Cannot inspect tracked Admin PHP sources before build'
        mapfile -d '' -t entries < <(git -C "$repository" ls-files --stage -z -- 'sgw/admin/src/*.php')
        (( ${#entries[@]} > 0 )) || die 'No tracked Admin PHP sources found before build'
        for entry in "${entries[@]}"; do
            mode=${entry%% *}
            path=$repository/${entry#*$'\t'}
            [[ $mode == 100644 || $mode == 100755 ]] && [[ -f $path && ! -L $path ]] \
                || die "Unsafe tracked Admin PHP source: $path"
            # Validate every parent before chmod, so symlinks cannot escape src.
            directory=${path%/*}
            while [[ $directory == "$source_root" || $directory == "$source_root/"* ]]; do
                [[ -d $directory && ! -L $directory ]] || die "Unsafe Admin source directory: $directory"
                [[ $directory != "$source_root" ]] || break
                directory=${directory%/*}
            done
            directory=${path%/*}
            while [[ $directory == "$source_root" || $directory == "$source_root/"* ]]; do
                chmod 0755 "$directory" || die "Cannot make Admin source directory traversable: $directory"
                [[ $directory != "$source_root" ]] || break
                directory=${directory%/*}
            done
            if [[ $mode == 100755 ]]; then mode=0755; else mode=0644; fi
            chmod "$mode" "$path" || die "Cannot make Admin PHP source readable before build: $path"
        done
    else
        # Do not broaden unknown/untracked file permissions in archive checkouts.
        entry=$(find "$source_root" \( -type l -o \( -type d ! -perm -0005 \) \
            -o \( -type f -name '*.php' ! -perm -0004 \) \) -print -quit) \
            || die 'Cannot inspect Admin source permissions before build'
        [[ -z $entry ]] \
            || die 'Admin PHP sources must be readable and source directories traversable before build'
    fi
}

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
    local response script
    if ! command -v docker >/dev/null; then
        read -r -p 'Docker not installed. Install official Docker now? [y/N] ' response
        [[ $response == y || $response == Y ]] || die 'Docker is required'
        script=$(mktemp)
        if ! curl --proto '=https' --tlsv1.2 -fsSL https://get.docker.com -o "$script"; then
            rm -f -- "$script"
            die 'Docker installer download failed'
        fi
        if ! sh "$script"; then
            rm -f -- "$script"
            die 'Docker installation failed'
        fi
        rm -f -- "$script"
    fi
    if ! docker version >/dev/null 2>&1; then
        if systemd_running; then
            systemctl start docker || die 'Cannot start Docker daemon'
        elif command -v service >/dev/null; then
            service docker start || die 'Cannot start Docker daemon'
        else
            die 'Docker daemon unavailable; start it and run ./setup.sh again'
        fi
        docker version >/dev/null 2>&1 || die 'Docker daemon still unavailable'
    fi
    if ! docker compose version >/dev/null 2>&1; then
        install_packages_if_approved docker-compose-plugin
        docker compose version >/dev/null 2>&1 \
            || die 'Compose plugin unavailable; install docker-compose-plugin from the official Docker apt repository'
    fi
}
systemd_running() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; }
cron_service_active() {
    if systemd_running; then
        systemctl is-active --quiet cron && systemctl is-enabled --quiet cron
    else
        command -v service >/dev/null && service cron status >/dev/null 2>&1 \
            || { command -v pgrep >/dev/null && pgrep -x cron >/dev/null; }
    fi
}
ensure_cron() {
    if ! command -v crontab >/dev/null || ! command -v cron >/dev/null; then
        install_packages_if_approved cron
    fi
    command -v crontab >/dev/null || die 'crontab unavailable; automatic renewal cannot be guaranteed'
    if ! cron_service_active; then
        if systemd_running; then
            systemctl enable --now cron || die 'Cannot enable/start cron for automatic renewal'
        elif command -v service >/dev/null; then
            service cron start || die 'Cannot start cron for automatic renewal'
            if command -v update-rc.d >/dev/null; then update-rc.d cron defaults >/dev/null; fi
        else
            die 'Cannot manage cron on this system; start cron before automatic certificate setup'
        fi
    fi
    cron_service_active || die 'cron is not running/enabled; automatic renewal cannot be guaranteed'
}
ensure_port_tools() {
    command -v ss >/dev/null || install_packages_if_approved iproute2
    command -v ss >/dev/null || die 'ss is required to check host port conflicts'
}
project_owns_port() {
    local port=$1 service=$2 id
    [[ -f $ENV_FILE ]] || return 1
    id=$(compose ps -q "$service" 2>/dev/null) || return 1
    [[ -n $id && $(docker inspect --format '{{.State.Running}}' "$id" 2>/dev/null) == true ]] || return 1
    docker inspect --format '{{range (index .NetworkSettings.Ports "8443/tcp")}}{{println .HostPort}}{{end}}' "$id" \
        2>/dev/null | grep -Fxq "$port"
}
assert_install_ports() {
    local gateway_port=$1 admin_port=$2 port service listeners
    [[ $gateway_port != "$admin_port" ]] || die 'Gateway and Admin host ports must differ'
    for service in gateway admin; do
        port=$gateway_port
        [[ $service != admin ]] || port=$admin_port
        listeners=$(ss -H -ltnp "( sport = :$port )") || die 'Cannot inspect host listening ports'
        if [[ -n $listeners ]] && ! project_owns_port "$port" "$service"; then
            printf '%s\n' "$listeners" >&2
            die "Host port $port ($service) is occupied by another listener; installation stopped"
        fi
    done
}
make_runtime() {
    local path
    for path in "$RUNTIME" "$RUNTIME/ssl" "$RUNTIME/backups"; do
        [[ ! -L $path ]] || die 'Runtime directory must not be a symbolic link'
    done
    mkdir -p "$RUNTIME"/{data,control,generated,logs,domain-certs,ssl/staging,ssl/releases,backups/database}
    for path in "$RUNTIME"/{data,control,generated,logs,domain-certs,ssl,ssl/staging,ssl/releases,backups,backups/database}; do
        [[ -d $path && ! -L $path ]] || die 'Unsafe runtime subdirectory'
    done
    chmod 0750 "$RUNTIME" "$RUNTIME"/{data,control,generated,logs,domain-certs,ssl,ssl/staging,ssl/releases,backups,backups/database}
    chown 82:82 "$RUNTIME/domain-certs"
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
acme_home() { printf '/root/.acme.sh\n'; }
acme_binary() (
    local acme_dir binary temporary=''
    acme_dir=$(acme_home)
    binary=$acme_dir/acme.sh
    ensure_cron >&2
    if [[ -x $binary ]]; then
        chmod -R go-rwx "$acme_dir"
        printf '%s\n' "$binary"
        return
    fi
    command -v git >/dev/null || install_packages_if_approved git >&2
    temporary=$(mktemp -d)
    trap '[[ -z $temporary ]] || rm -rf -- "$temporary"' EXIT
    git clone --depth 1 https://github.com/acmesh-official/acme.sh.git "$temporary/acme.sh" >&2 \
        || die 'Official acme.sh clone failed'
    (cd "$temporary/acme.sh" && ./acme.sh --install --home "$acme_dir") >&2 \
        || die 'acme.sh installation failed from its source directory; see the error above'
    [[ -x $binary ]] || die 'acme.sh executable missing after installation'
    chmod -R go-rwx "$acme_dir"
    printf '%s\n' "$binary"
)
acme_cron_registered() {
    crontab -l 2>/dev/null | awk -v directory="$(acme_home)" '
        /^[[:space:]]*#/ {next}
        index($0,"--cron") && index($0,directory) && index($0,"acme.sh") {found=1}
        END {exit !found}
    '
}
acme_renewal_ready() {
    local domain=$1 binary hook metadata expected
    binary=$(acme_home)/acme.sh
    hook=$RUNTIME/ssl/deploy-hook.sh
    [[ -x $binary && -f $hook && ! -L $hook && -x $hook ]] || return 1
    [[ $(stat -c %u "$hook") == 0 && $(stat -c %a "$hook") == 700 ]] || return 1
    expected=$(printf '#!/usr/bin/env bash\nexec %q --deploy-staged-certificate\n' "$SGW_DIR/../setup.sh")
    [[ $(<"$hook") == "$expected" ]] || return 1
    cron_service_active && acme_cron_registered || return 1
    # --info can include DNS credentials: capture it, select only deployment fields,
    # and never print the complete metadata (or source an ACME configuration file).
    metadata=$("$binary" --info -d "$domain" 2>/dev/null) || return 1
    [[ $(awk -F= '$1=="Le_RealFullChainPath" {print substr($0,index($0,"=")+1)}' <<< "$metadata") == "$RUNTIME/ssl/staging/fullchain.pem" ]] \
        && [[ $(awk -F= '$1=="Le_RealKeyPath" {print substr($0,index($0,"=")+1)}' <<< "$metadata") == "$RUNTIME/ssl/staging/privkey.pem" ]] \
        && [[ $(awk -F= '$1=="Le_ReloadCmd" {print substr($0,index($0,"=")+1)}' <<< "$metadata") == "$hook" ]]
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
        chmod -R go-rwx "$(acme_home)"
    elif [[ $mode == dns-cf ]]; then
        acme=$(acme_binary)
        read -r -p 'Cloudflare DNS API Token: ' token
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
        INSTALL_CF_TOKEN=$token INSTALL_CF_ZONE=$zone
        unset CF_Token CF_Zone_ID token
        "$acme" --install-cert -d "$domain" --fullchain-file "$fullchain" --key-file "$key" >/dev/null 2>&1 \
            || die 'Cannot install issued certificate into staging'
        chmod -R go-rwx "$(acme_home)"
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
    if ! acme_cron_registered; then
        "$acme" --install-cronjob >/dev/null 2>&1 || return 1
    fi
    hook=$(ensure_deploy_hook)
    "$acme" --install-cert -d "$domain" \
        --fullchain-file "$RUNTIME/ssl/staging/fullchain.pem" \
        --key-file "$RUNTIME/ssl/staging/privkey.pem" \
        --reloadcmd "$hook" >/dev/null 2>&1 || return 1
    chmod -R go-rwx "$(acme_home)"
    acme_renewal_ready "$domain"
}
ensure_deploy_hook() {
    local hook=$RUNTIME/ssl/deploy-hook.sh
    [[ ! -L $hook && ! -L $hook.tmp ]] || die 'Unsafe deploy hook path'
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
