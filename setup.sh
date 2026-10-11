#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=sgw/ops.sh
. "$ROOT_DIR/sgw/ops.sh"
# shellcheck source=sgw/install.sh
. "$ROOT_DIR/sgw/install.sh"

choose_mode() {
    local answer
    printf '%s\n' 'Certificate: 1) HTTP-01  2) Cloudflare DNS-01  3) existing files' >&2
    read -r -p 'Select [1/2/3]: ' answer
    case $answer in
        1) printf 'http-01';;
        2) printf 'dns-cf';;
        3) printf 'existing';;
        *) die 'Invalid certificate mode';;
    esac
}
env_replace() {
    local key=$1 value=$2 target=$3 source=${4:-$ENV_FILE}
    [[ $key =~ ^[A-Z_]+$ && $value != *$'\n'* && $value != *$'\r'* ]] || die 'Invalid environment value'
    awk -F= -v key="$key" -v value="$value" '
        $1 == key { print key "=" value; found=1; next }
        { print }
        END { if (!found) print key "=" value }
    ' "$source" > "$target"
    chmod 0600 "$target"
    sync -f "$target"
}
backup_env() {
    local destination=$RUNTIME/backups/env-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)
    cp -p -- "$ENV_FILE" "$destination"
    chmod 0600 "$destination"
    printf '%s\n' "$destination"
}
health_service() {
    local name=$1 id state attempt
    id=$(compose ps -q "$name")
    [[ -n $id ]] || return 1
    for attempt in {1..60}; do
        state=$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || true)
        [[ $state == healthy ]] && return 0
        [[ $state == unhealthy ]] && return 1
        sleep 2
    done
    return 1
}
first_install() {
    require_root
    [[ ! -L $ENV_FILE ]] || die '.env must not be a symbolic link'
    INSTALL_DOMAIN=''
    INSTALL_LOCK_HELD=no
    trap 'installation_cleanup $?' EXIT
    trap 'exit 130' INT TERM HUP
    check_os_arch_disk
    if ! command -v curl >/dev/null || ! command -v openssl >/dev/null \
        || ! dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | grep -q 'install ok installed'; then
        install_packages_if_approved curl openssl ca-certificates
    fi
    check_platform
    local domain port gateway_port username='' mode secret password='' hmac encryption
    local fresh=no completed=no admin_line count certificate_changed=no images_changed=no
    if [[ -f $ENV_FILE ]]; then
        validate_install_environment
        domain=$(env_value GATEWAY_DOMAIN)
        port=$(env_value ADMIN_PORT)
        gateway_port=$(env_value GATEWAY_HTTPS_PORT)
        mode=$(env_value CERT_MODE)
        secret=$(env_value ADMIN_SECRET_PATH)
    else
        [[ ! -e $RUNTIME/data/subscription-gateway.db && ! -e $RUNTIME/install-complete ]] \
            || die 'Existing data without .env; restore .env from backup rather than generate new keys'
        fresh=yes
        read -r -p 'Gateway FQDN: ' domain
        valid_domain "$domain" || die 'Invalid gateway domain'
        read -r -p 'Admin HTTPS port [64444]: ' port
        port=${port:-64444}
        valid_port "$port" && (( port >= 1024 && port != 443 )) || die 'Invalid Admin port'
        gateway_port=443
        read -r -p 'Administrator username [admin]: ' username
        username=${username:-admin}
        [[ $username =~ ^[A-Za-z0-9_.-]{3,64}$ ]] || die 'Invalid administrator username'
        mode=$(choose_mode)
    fi
    INSTALL_DOMAIN=$domain
    ensure_port_tools
    # Check public ports before certificate issuance, Docker installation/build,
    # credentials or database writes. A running container of this project is OK.
    assert_install_ports "$gateway_port" "$port"
    if [[ $mode == http-01 ]] && ! certificate_verify \
        "$RUNTIME/ssl/active/fullchain.pem" "$RUNTIME/ssl/active/privkey.pem" "$domain"; then
        command -v ip >/dev/null || install_packages_if_approved iproute2
        port_80_free || die 'Port 80 is occupied; select DNS-01 or existing certificate'
        http_dns_matches_local "$domain" || die 'Domain A record does not match a local IPv4 address'
    fi
    make_runtime
    [[ ! -L $RUNTIME/install.lock ]] || die 'Unsafe installation lock'
    command -v flock >/dev/null || die 'flock is required'
    exec 8> "$RUNTIME/install.lock"
    flock -n 8 || die 'Another installation is running'
    INSTALL_LOCK_HELD=yes
    [[ ! -e $RUNTIME/install-complete ]] || private_root_file "$RUNTIME/install-complete" \
        || die 'Unsafe install-complete marker'
    if install_completed; then completed=yes; fi
    ensure_docker
    if [[ $completed == yes ]]; then
        if (check_install) >/dev/null 2>&1; then
            info 'Existing installation detected; no credentials, keys, database or certificate changed'
            trap - EXIT INT TERM HUP
            exec 8>&-
            return
        fi
        warning 'Installation exists but health check failed; attempting safe service recovery (see ./setup.sh --check)'
    elif [[ $fresh == no ]]; then
        info 'Incomplete installation detected; resuming with existing credentials, keys and data'
    fi
    if [[ $fresh == yes ]]; then
        [[ ! -f $ENV_FILE ]] || die 'Installation changed while waiting for lock; run ./setup.sh again'
        install_record_write "$RUNTIME/install-state" "ADMIN_USERNAME=$username"
    fi
    if [[ $mode != existing ]]; then ensure_cron; fi
    if ! certificate_verify "$RUNTIME/ssl/active/fullchain.pem" "$RUNTIME/ssl/active/privkey.pem" "$domain"; then
        acquire_certificate "$mode" "$domain"
        cert_activate "$domain" yes || die 'Initial/recovery certificate activation failed'
        certificate_changed=yes
    else
        info 'Valid active certificate reused; no new issuance'
    fi
    if [[ $fresh == yes ]]; then
        secret=$(openssl rand -hex 24)
        hmac=$(openssl rand -base64 32 | tr -d '\n')
        encryption=$(openssl rand -base64 32 | tr -d '\n')
        [[ $hmac != "$encryption" ]] || die 'Generated keys collided'
        [[ ! -L $ENV_FILE.tmp ]] || die 'Unsafe temporary .env'
        cat > "$ENV_FILE.tmp" <<EOF
DATABASE_PATH=/data/subscription-gateway.db
GATEWAY_DOMAIN=$domain
GATEWAY_HTTPS_PORT=443
ADMIN_BIND=0.0.0.0
ADMIN_PORT=$port
CERT_MODE=$mode
APP_UID=82
APP_GID=82
TZ=UTC
TOKEN_EVENT_LOG_PATH=/var/log/subscription-gateway/token-events.log
ACTIVE_CERT_PATH=/ssl/active/fullchain.pem
DNS_RESOLVER=127.0.0.11
TRUSTED_PROXY_IPS=
REAL_IP_HEADER=X-Forwarded-For
ADMIN_SECRET_PATH=$secret
SESSION_NAME=subscription_gateway_session
SESSION_COOKIE_SECURE=true
LOGIN_RATE_DIR=/tmp/subscription-gateway-login-rate
TOKEN_HMAC_KEY=$hmac
TOKEN_ENCRYPTION_KEY=$encryption
EOF
        chmod 0600 "$ENV_FILE.tmp"
        sync -f "$ENV_FILE.tmp"
        mv -f -- "$ENV_FILE.tmp" "$ENV_FILE"
    fi
    validate_install_environment
    compose config >/dev/null || die 'Docker Compose configuration invalid'
    if ! installation_images_ready; then
        compose build || die 'Docker images could not be built'
        images_changed=yes
    fi
    if ! admin_cli installation-check >/dev/null 2>&1; then
        admin_cli migrate >/dev/null || die 'SQLite initialization failed'
    fi
    if [[ $mode == dns-cf && $completed != yes ]]; then
        if [[ -n ${INSTALL_CF_TOKEN:-} && ${INSTALL_CF_ZONE:-} =~ ^[A-Fa-f0-9]{32}$ ]]; then
            if ! printf '%s\n%s\n' "$INSTALL_CF_TOKEN" "$INSTALL_CF_ZONE" | admin_cli cloudflare-bootstrap >/dev/null; then
                warning 'Cloudflare凭据档案未初始化，可稍后在后台添加'
            fi
        else warning 'Cloudflare凭据档案未初始化，可稍后在后台添加'; fi
    fi
    unset INSTALL_CF_TOKEN INSTALL_CF_ZONE
    admin_line=$(admin_cli admin-status) || die 'Cannot read administrator installation state'
    read -r count username <<< "$admin_line"
    if [[ $count == 0 ]]; then
        if [[ -f $RUNTIME/install-state ]]; then
            private_root_file "$RUNTIME/install-state" || die 'Unsafe install-state file'
            username=$(install_record_value "$RUNTIME/install-state" ADMIN_USERNAME)
        else
            read -r -p 'Recovery administrator username [admin]: ' username
            username=${username:-admin}
        fi
        [[ $username =~ ^[A-Za-z0-9_.-]{3,64}$ ]] || die 'Invalid recovery administrator username'
        password=$(openssl rand -hex 24)
        printf '%s' "$password" | admin_cli init-admin "$username" >/dev/null || die 'Administrator initialization failed'
    elif [[ $count != 1 ]]; then
        die 'Expected exactly one administrator; existing database was retained'
    fi
    if [[ $images_changed == yes ]] || ! wait_health; then
        compose up -d || die 'Container startup failed'
    fi
    wait_health || die 'Container healthcheck failed'
    compose exec -T gateway nginx -t || die 'Gateway nginx -t failed'
    compose exec -T admin nginx -t || die 'Admin nginx -t failed'
    if [[ $certificate_changed == yes ]]; then
        compose exec -T gateway nginx -s reload && compose exec -T admin nginx -s reload \
            || die 'Certificate reload failed'
    fi
    if [[ $mode != existing ]] && ! acme_renewal_ready "$domain"; then
        register_acme_hook "$mode" "$domain" || die 'ACME renewal hook registration failed'
    fi
    check_install || die 'Installation integrity checks failed'
    # Never keep plaintext passwords. An incomplete installation with an existing
    # administrator gets a new password only after all readiness checks succeed.
    if [[ $completed != yes && -z $password ]]; then
        password=$(openssl rand -hex 24)
        printf '%s' "$password" | admin_cli reset-admin-password >/dev/null || die 'Recovery password reset failed'
    fi
    local record="FORMAT=1"$'\n'"COMPLETED_AT=$(date -u +%FT%TZ)"$'\n'"CREDENTIALS_DELIVERED="
    # A killed/failed password delivery leaves a pending marker, so the next run
    # recovers the unknown password. No secret is stored in either marker state.
    if [[ -n $password ]]; then install_record_write "$RUNTIME/install-complete" "${record}pending"; fi
    printf 'Admin: https://%s:%s/%s\n' "$domain" "$port" "$secret"
    printf 'Username: %s\n' "$username"
    if [[ -n $password ]]; then
        if [[ $fresh == yes ]]; then printf 'Initial password (shown once): %s\n' "$password"
        else printf 'Recovery administrator password (shown once): %s\n' "$password"; fi
    else
        info 'Services restored; existing administrator password unchanged'
    fi
    install_record_write "$RUNTIME/install-complete" "${record}yes"
    unset password hmac encryption
    trap - EXIT INT TERM HUP
    exec 8>&-
    info 'Installation completed'
}
reset_admin_password() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local password
    password=$(openssl rand -hex 24)
    printf '%s' "$password" | admin_cli reset-admin-password >/dev/null || die 'Password reset failed'
    printf 'New administrator password (shown once): %s\n' "$password"
}
set_admin_secret_path() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local next previous
    read -r -p 'New secret path (blank = generate): ' next
    next=${next:-$(openssl rand -hex 24)}
    valid_secret_path "$next" || die 'Invalid secret path'
    previous=$(backup_env)
    env_replace ADMIN_SECRET_PATH "$next" "$ENV_FILE.next"
    DEPLOY_ENV_FILE=.env.next docker compose --project-directory "$SGW_DIR" -f "$COMPOSE_FILE" \
        --env-file "$ENV_FILE.next" config >/dev/null \
        || { rm -f -- "$ENV_FILE.next"; die 'New Admin config is invalid'; }
    mv -f -- "$ENV_FILE.next" "$ENV_FILE"
    if ! compose up -d --force-recreate --no-deps admin || ! health_service admin; then
        cp -p -- "$previous" "$ENV_FILE"
        compose up -d --force-recreate --no-deps admin >/dev/null 2>&1 || true
        die 'Admin path change failed; previous .env restored'
    fi
    printf 'New Admin URL: https://%s:%s/%s\n' "$(env_value GATEWAY_DOMAIN)" "$(env_value ADMIN_PORT)" "$next"
}
configure_certificate() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local domain mode previous old_cert
    domain=$(env_value GATEWAY_DOMAIN)
    mode=$(choose_mode)
    acquire_certificate "$mode" "$domain"
    previous=$(backup_env)
    old_cert=$(readlink "$RUNTIME/ssl/active")
    cert_activate "$domain" || die 'New certificate failed; old certificate retained'
    env_replace CERT_MODE "$mode" "$ENV_FILE.next"
    mv -f -- "$ENV_FILE.next" "$ENV_FILE"
    if [[ $mode != existing ]] && ! register_acme_hook "$mode" "$domain"; then
        cp -p -- "$previous" "$ENV_FILE"
        ln -s "$old_cert" "$RUNTIME/ssl/active.next"
        mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
        compose exec -T gateway nginx -s reload >/dev/null 2>&1 || true
        compose exec -T admin nginx -s reload >/dev/null 2>&1 || true
        die 'Renewal registration failed; previous certificate restored'
    fi
    info 'Certificate reconfigured'
}
deploy_staged_certificate() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    [[ $(env_value CERT_MODE) != existing ]] || { info 'Manual certificate mode; automatic hook ignored'; return; }
    cert_activate "$(env_value GATEWAY_DOMAIN)" || die 'Renewed certificate rejected; previous certificate retained'
}
renew_certificate() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local mode domain acme
    mode=$(env_value CERT_MODE)
    [[ $mode != existing ]] || die 'Existing-file certificate cannot auto-renew; use --configure-certificate'
    domain=$(env_value GATEWAY_DOMAIN)
    acme=$(acme_binary)
    "$acme" --renew -d "$domain" --force >/dev/null 2>&1 || die 'ACME renewal failed; active certificate unchanged'
    "$acme" --install-cert -d "$domain" --fullchain-file "$RUNTIME/ssl/staging/fullchain.pem" \
        --key-file "$RUNTIME/ssl/staging/privkey.pem" \
        --reloadcmd "$(ensure_deploy_hook)" >/dev/null 2>&1 \
        || die 'Renewed certificate deployment failed; active certificate unchanged'
    info 'Certificate renewed'
}
set_gateway_domain() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local old next mode previous old_cert
    old=$(env_value GATEWAY_DOMAIN)
    read -r -p 'New Gateway FQDN: ' next
    valid_domain "$next" || die 'Invalid new domain'
    [[ $next != "$old" ]] || die 'Domain has not changed'
    mode=$(choose_mode)
    acquire_certificate "$mode" "$next"
    previous=$(backup_env)
    old_cert=$(readlink "$RUNTIME/ssl/active")
    env_replace GATEWAY_DOMAIN "$next" "$ENV_FILE.next"
    env_replace CERT_MODE "$mode" "$ENV_FILE.next2" "$ENV_FILE.next"
    if ! DEPLOY_ENV_FILE=.env.next2 docker compose --project-directory "$SGW_DIR" -f "$COMPOSE_FILE" \
        --env-file "$ENV_FILE.next2" config >/dev/null; then
        rm -f -- "$ENV_FILE.next" "$ENV_FILE.next2"
        die 'New domain Compose configuration is invalid; old domain retained'
    fi
    mv -f -- "$ENV_FILE.next2" "$ENV_FILE"
    rm -f -- "$ENV_FILE.next"
    if ! cert_activate "$next" yes \
        || ! compose up -d --force-recreate admin gateway || ! wait_health \
        || ! compose exec -T gateway nginx -t >/dev/null 2>&1 \
        || ! compose exec -T admin nginx -t >/dev/null 2>&1 \
        || ! admin_cli sync-primary-domain >/dev/null; then
        cp -p -- "$previous" "$ENV_FILE"
        ln -s "$old_cert" "$RUNTIME/ssl/active.next"
        mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
        compose up -d --force-recreate admin gateway >/dev/null 2>&1 || true
        admin_cli sync-primary-domain >/dev/null 2>&1 || true
        die 'Domain change failed; old environment and certificate restored'
    fi
    if [[ $mode != existing ]] && ! register_acme_hook "$mode" "$next"; then
        cp -p -- "$previous" "$ENV_FILE"
        ln -s "$old_cert" "$RUNTIME/ssl/active.next"
        mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
        compose up -d --force-recreate admin gateway >/dev/null 2>&1 || true
        admin_cli sync-primary-domain >/dev/null 2>&1 || true
        die 'Renewal registration failed; old domain and certificate restored'
    fi
    info "Gateway domain changed to $next"
}
check_install() {
    require_root
    local problems=0
    if check_platform; then info 'Platform and free space'; else warning 'Platform check failed'; problems=1; fi
    [[ -f $ENV_FILE ]] || die '.env missing'
    validate_install_environment
    [[ $(stat -c %a "$ENV_FILE") == 600 ]] && info '.env permission 0600' \
        || { warning '.env should be 0600'; problems=1; }
    local domain dir version_line configured active
    domain=$(env_value GATEWAY_DOMAIN)
    valid_domain "$domain" || die 'Invalid gateway domain in .env'
    for dir in data control generated logs domain-certs ssl backups; do
        if [[ -d $RUNTIME/$dir && $(stat -c %a "$RUNTIME/$dir") == 750 ]]; then
            info "runtime/$dir permission 0750"
        else
            warning "runtime/$dir permission or directory invalid"
            problems=1
        fi
    done
    docker version >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && info 'Docker/Compose available' || die 'Docker/Compose unavailable'
    compose config >/dev/null && info 'Compose configuration valid' || die 'Compose configuration invalid'
    if wait_health; then info 'Both containers healthy'; else warning 'A container is not healthy'; problems=1; fi
    certificate_verify "$RUNTIME/ssl/active/fullchain.pem" "$RUNTIME/ssl/active/privkey.pem" "$domain" \
        && info 'Active certificate valid for domain' || { warning 'Active certificate invalid'; problems=1; }
    if [[ -f $RUNTIME/ssl/active/fullchain.pem ]]; then
        openssl x509 -in "$RUNTIME/ssl/active/fullchain.pem" -noout -enddate || true
    fi
    if ! installation_extra_checks; then problems=1; fi
    compose exec -T gateway nginx -t >/dev/null 2>&1 && info 'Gateway nginx -t passed' \
        || { warning 'Gateway nginx -t failed'; problems=1; }
    compose exec -T admin nginx -t >/dev/null 2>&1 && info 'Admin nginx -t passed' \
        || { warning 'Admin nginx -t failed'; problems=1; }
    compose exec -T admin su-exec www-data php /app/src/cli.php integrity >/dev/null 2>&1 \
        && info 'SQLite integrity_check passed' || { warning 'SQLite integrity_check failed'; problems=1; }
    version_line=$(compose exec -T admin su-exec www-data php /app/src/cli.php versions 2>/dev/null) \
        || { warning 'Version check unavailable'; problems=1; version_line=''; }
    if [[ -n $version_line ]]; then
        read -r configured active <<< "$version_line"
        info "config_version=$configured active_version=$active"
        if [[ $configured != "$active" ]]; then warning 'Gateway rules pending'; problems=1; fi
    fi
    getent ahostsv4 "$domain" >/dev/null && info 'Domain resolves' \
        || { warning 'Domain DNS lookup failed'; problems=1; }
    df -h "$SGW_DIR"
    if (( problems == 0 )); then info 'CHECK PASS'; else warning 'CHECK FAIL'; return 1; fi
}
uninstall_installation() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    compose down --remove-orphans
    info 'Project containers stopped and removed; .env, database, certificates, rules and logs retained'
}
purge_installation() {
    require_root
    [[ -f $ENV_FILE ]] || die 'Installation not found'
    local domain confirmation
    domain=$(env_value GATEWAY_DOMAIN)
    read -r -p "Type current gateway domain ($domain) to purge: " confirmation
    [[ $confirmation == "$domain" ]] || die 'Domain confirmation mismatch'
    read -r -p 'Type PURGE to permanently remove project runtime data: ' confirmation
    [[ $confirmation == PURGE ]] || die 'Purge cancelled'
    [[ $RUNTIME == "$SGW_DIR/runtime" && ! -L $RUNTIME && -d $RUNTIME ]] || die 'Unsafe runtime path'
    compose down --remove-orphans
    rm -rf -- "$RUNTIME"
    rm -f -- "$ENV_FILE"
    info 'Project runtime data and .env removed; global Docker and acme.sh data retained'
}

setup_main() {
[[ ! -L $ENV_FILE ]] || die '.env must not be a symbolic link'
case ${1:-} in
    '') first_install;;
    --check) check_install;;
    --reset-admin-password) reset_admin_password;;
    --set-admin-secret-path) set_admin_secret_path;;
    --set-gateway-domain) set_gateway_domain;;
    --configure-certificate) configure_certificate;;
    --renew-certificate) renew_certificate;;
    --deploy-staged-certificate) deploy_staged_certificate;;
    --uninstall) uninstall_installation;;
    --purge) purge_installation;;
    *) die 'Unknown command';;
esac
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then setup_main "$@"; fi
