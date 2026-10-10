#!/usr/bin/env bash
# Installation-only state and diagnostics. Never source deployment/ACME data.

private_root_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u "$1") == 0 && $(stat -c %a "$1") == 600 ]]
}
install_record_write() {
    local path=$1 content=$2
    [[ ! -L $path && ! -L $path.tmp ]] || die 'Unsafe installation state path'
    printf '%s\n' "$content" > "$path.tmp"
    chown root:root "$path.tmp"
    chmod 0600 "$path.tmp"
    sync -f "$path.tmp"
    mv -f -- "$path.tmp" "$path"
}
install_record_value() {
    awk -F= -v key="$2" '$1==key {print substr($0,index($0,"=")+1); exit}' "$1"
}
install_completed() {
    private_root_file "$RUNTIME/install-complete" \
        && [[ $(install_record_value "$RUNTIME/install-complete" FORMAT) == 1 ]] \
        && [[ $(install_record_value "$RUNTIME/install-complete" CREDENTIALS_DELIVERED) == yes ]]
}
validate_install_environment() {
    private_root_file "$ENV_FILE" || die '.env must be a root-owned regular file with permission 0600'
    local key value hmac encryption
    for key in DATABASE_PATH GATEWAY_DOMAIN GATEWAY_HTTPS_PORT ADMIN_BIND ADMIN_PORT CERT_MODE \
        APP_UID APP_GID ADMIN_SECRET_PATH TOKEN_HMAC_KEY TOKEN_ENCRYPTION_KEY; do
        [[ $(awk -F= -v key="$key" '$1==key {n++} END {print n+0}' "$ENV_FILE") == 1 ]] \
            || die "Missing or duplicate .env key: $key"
        value=$(env_value "$key")
        [[ -n $value && $value != *$'\r'* ]] || die "Invalid .env value: $key"
    done
    valid_domain "$(env_value GATEWAY_DOMAIN)" || die 'Invalid GATEWAY_DOMAIN'
    valid_port "$(env_value GATEWAY_HTTPS_PORT)" && valid_port "$(env_value ADMIN_PORT)" || die 'Invalid host port in .env'
    [[ $(env_value CERT_MODE) =~ ^(existing|http-01|dns-cf)$ ]] || die 'Invalid CERT_MODE'
    [[ $(env_value DATABASE_PATH) == /data/subscription-gateway.db \
        && $(env_value APP_UID) == 82 && $(env_value APP_GID) == 82 ]] \
        || die 'Installer requires the standard database path and APP_UID/APP_GID=82; configuration retained'
    [[ $(env_value ADMIN_BIND) =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die 'Invalid ADMIN_BIND'
    valid_secret_path "$(env_value ADMIN_SECRET_PATH)" || die 'Invalid ADMIN_SECRET_PATH'
    hmac=$(env_value TOKEN_HMAC_KEY)
    encryption=$(env_value TOKEN_ENCRYPTION_KEY)
    for value in "$hmac" "$encryption"; do
        [[ $value =~ ^[A-Za-z0-9+/]{43}=$ ]] \
            && [[ $(printf '%s' "$value" | openssl base64 -d -A | wc -c | tr -d ' ') == 32 ]] \
            || die 'Token keys must each encode exactly 32 bytes; existing keys were not changed'
    done
    [[ $hmac != "$encryption" ]] || die 'Token keys must differ; existing keys were not changed'
}
installation_cleanup() {
    local status=$1
    trap - EXIT
    # A process rejected by flock must not delete another installer's files.
    if [[ ${INSTALL_LOCK_HELD:-no} == yes ]]; then
        rm -f -- "$ENV_FILE.tmp"
        if [[ ! -L $RUNTIME ]]; then
            rm -f -- "$RUNTIME/install-state.tmp" "$RUNTIME/install-complete.tmp"
        fi
    fi
    if (( status != 0 )) && [[ ${INSTALL_LOCK_HELD:-no} == yes ]]; then
        if [[ ! -L $RUNTIME && ! -L $RUNTIME/ssl && ! -L $RUNTIME/ssl/staging \
            && -n ${INSTALL_DOMAIN:-} ]] && ! certificate_verify \
            "$RUNTIME/ssl/staging/fullchain.pem" "$RUNTIME/ssl/staging/privkey.pem" "$INSTALL_DOMAIN"; then
            rm -f -- "$RUNTIME/ssl/staging/fullchain.pem" "$RUNTIME/ssl/staging/privkey.pem"
        fi
        if [[ ! -L $RUNTIME && ! -L $RUNTIME/ssl ]]; then
            rm -f -- "$RUNTIME/ssl/deploy-hook.sh.tmp"
        fi
    fi
    if (( status != 0 )); then
        warning 'Installation incomplete. Fix the reported problem and run ./setup.sh again.'
    fi
}
installation_images_ready() {
    docker image inspect subscription-gateway/admin:current subscription-gateway/gateway:current >/dev/null 2>&1 \
        && admin_cli installation-probe >/dev/null 2>&1
}
installation_extra_checks() {
    local problems=0 service id policy binding mode
    if compose exec -T admin su-exec www-data php /app/src/cli.php installation-check; then
        info 'Current schema, tracking structure, administrator and SQLite integrity valid'
    else
        warning 'Installation database/extension checks failed'; problems=1
    fi
    if compose exec -T admin su-exec www-data php /app/src/cli.php transformer-check; then
        info 'PHP curl/yaml and internal 8081 -> Transformer FPM pool available'
    else
        warning 'Internal Transformer/FPM check failed'; problems=1
    fi
    for service in admin gateway; do
        id=$(compose ps -q "$service") || id=''
        if [[ -z $id ]]; then warning "$service container missing"; problems=1; continue; fi
        policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$id") || policy=''
        [[ $policy == unless-stopped ]] && info "$service restart policy unless-stopped" \
            || { warning "$service restart policy invalid"; problems=1; }
        if [[ $service == admin ]]; then
            binding=$(docker inspect --format '{{with index .HostConfig.PortBindings "8081/tcp"}}published{{end}}' "$id") || binding=unknown
            [[ -z $binding ]] && info 'Transformer 8081 has no host PortBindings' \
                || { warning 'Transformer 8081 is host-bound or binding check failed'; problems=1; }
        fi
    done
    mode=$(env_value CERT_MODE)
    if [[ $mode != existing ]]; then
        if command -v crontab >/dev/null && acme_renewal_ready "$(env_value GATEWAY_DOMAIN)"; then
            info 'ACME executable, renewal deployment/hook and active cron verified'
        else
            warning 'Automatic renewal/cron is incomplete'; problems=1
        fi
    else
        info 'Existing certificate mode: cron/ACME/port 80 not required'
    fi
    local upstream
    upstream=$(compose exec -T admin su-exec www-data php /app/src/cli.php upstream-state) || upstream=UNKNOWN
    if [[ $upstream == EMPTY ]]; then info 'Gateway fail-closed: upstream not configured'; fi
    (( problems == 0 ))
}
