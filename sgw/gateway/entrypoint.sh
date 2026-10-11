#!/usr/bin/env bash
set -euo pipefail
umask 027

valid_ipv4() {
    local address=$1 octet
    [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local -a parts
    IFS=. read -r -a parts <<< "$address"
    for octet in "${parts[@]}"; do
        [[ $octet == 0 || $octet != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

valid_proxy_cidr() {
    local value=$1 address prefix
    address=${value%%/*}
    valid_ipv4 "$address" || return 1
    if [[ $value == */* ]]; then
        prefix=${value#*/}
        [[ $prefix =~ ^(0|[1-9]|[12][0-9]|3[0-2])$ ]] || return 1
        [[ $prefix != 0 ]] || return 1
    fi
}

[[ -n ${DNS_RESOLVER:-} ]] || { echo 'DNS_RESOLVER is required' >&2; exit 1; }
[[ ${GATEWAY_DOMAIN:-} =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
    || { echo 'Invalid GATEWAY_DOMAIN' >&2; exit 1; }
[[ ${REAL_IP_HEADER:-X-Forwarded-For} =~ ^[A-Za-z][A-Za-z0-9-]{0,63}$ ]] || {
    echo 'Invalid REAL_IP_HEADER' >&2; exit 1;
}

resolver_words=()
IFS=, read -r -a resolvers <<< "$DNS_RESOLVER"
for address in "${resolvers[@]}"; do
    valid_ipv4 "$address" || { echo 'Invalid DNS_RESOLVER' >&2; exit 1; }
    resolver_words+=("$address")
done
[[ ${#resolver_words[@]} -gt 0 ]] || { echo 'Invalid DNS_RESOLVER' >&2; exit 1; }
resolver_line=$(printf '%s ' "${resolver_words[@]}")
resolver_line=${resolver_line% }

mkdir -p /control /etc/nginx/generated /tmp/subscription-gateway /var/log/nginx
chmod 0750 /etc/nginx/generated /var/log/nginx
chmod 0700 /tmp/subscription-gateway
[[ ${APP_GID:-82} =~ ^[1-9][0-9]{0,5}$ ]] || { echo 'Invalid APP_GID' >&2; exit 1; }
for log_file in /var/log/nginx/access.log /var/log/nginx/token-events.log; do
    [[ ! -L $log_file ]] || { echo 'Unsafe log path' >&2; exit 1; }
    touch "$log_file"
    chgrp "${APP_GID:-82}" "$log_file"
    chmod 0640 "$log_file"
done
chgrp "${APP_GID:-82}" /var/log/nginx

real_ip_tmp=/etc/nginx/generated/real_ip.conf.tmp
: > "$real_ip_tmp"
if [[ -n ${TRUSTED_PROXY_IPS:-} ]]; then
    IFS=, read -r -a trusted <<< "$TRUSTED_PROXY_IPS"
    for network in "${trusted[@]}"; do
        valid_proxy_cidr "$network" || { echo 'Invalid TRUSTED_PROXY_IPS' >&2; exit 1; }
        printf 'set_real_ip_from %s;\n' "$network" >> "$real_ip_tmp"
    done
    printf 'real_ip_header %s;\nreal_ip_recursive on;\n' "${REAL_IP_HEADER:-X-Forwarded-For}" >> "$real_ip_tmp"
fi
chmod 0640 "$real_ip_tmp"
sync -f "$real_ip_tmp"
mv -f "$real_ip_tmp" /etc/nginx/generated/real_ip.conf

sed -e "s/__DNS_RESOLVER__/$resolver_line/" -e "s/__GATEWAY_DOMAIN__/$GATEWAY_DOMAIN/" \
    /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf.tmp
chmod 0640 /etc/nginx/nginx.conf.tmp
sync -f /etc/nginx/nginx.conf.tmp
mv -f /etc/nginx/nginx.conf.tmp /etc/nginx/nginx.conf

rules=/etc/nginx/generated/rules.conf
if [[ -L $rules ]]; then
    echo 'rules.conf must not be a symbolic link' >&2
    exit 1
fi
if [[ ! -f $rules ]]; then
    cat > "$rules.tmp" <<'RULES'
# No active rules; fail closed.
map "" $gateway_ready { default 0; }
map "" $gateway_upstream { default ""; }
map "" $gateway_upstream_host { default ""; }
map "" $tracking_mode { default "off"; }
map "" $gateway_subscription_upstream { default ""; }
map "" $gateway_subscription_host { default ""; }
map "" $gateway_subscription_ssl_name { default ""; }
map "" $tracking_internal_mode { default ""; }
map "" $tracking_internal_client_ip { default ""; }
map "" $tracking_internal_token { default ""; }
map "" $token_valid { default 0; }
map "" $token_query_duplicate { default 0; }
map "" $token_query_unsafe { default 0; }
map "" $token_event_loggable { default 0; }
log_format token_events escape=json '{"time":$msec,"token":"","ip":"$remote_addr","ua":"$http_user_agent","status":$status,"path":"$uri","policy":"$log_decision"}';
map "" $policy_block { default 0; }
map "" $policy_reason { default FAIL_CLOSED; }
map "" $log_decision { default FAIL_CLOSED; }
map "" $rate_key { default ""; }
limit_req_zone $rate_key zone=subscription_rate:10m rate=1r/m;
limit_req zone=subscription_rate nodelay;
limit_req_status 429;
RULES
    chmod 0640 "$rules.tmp"
    sync -f "$rules.tmp"
    mv -f "$rules.tmp" "$rules"
    echo 'No active rules; gateway started in fail-closed mode.' >&2
fi
domains=/control/domains.conf
if [[ -L $domains ]]; then
    # Move only the link itself; never read its target. Keep primary bootable.
    mv -T -- "$domains" "/control/domains.unsafe.$(date +%s).$(od -An -N4 -tx1 /dev/urandom | tr -d ' ').link"
    echo 'Unsafe alias configuration quarantined; recovering primary.' >&2
fi
if [[ ! -f $domains ]]; then
    printf '# No aliases configured.\n' > "$domains"
    chown --reference=/control "$domains"
    chmod 0640 "$domains"
fi
domain_mode=$(stat -c %a "$domains")
if (( (8#$domain_mode & 0027) != 0 )); then
    printf '# Unsafe alias permissions; primary-only recovery.\n' > "$domains"
    chown --reference=/control "$domains"; chmod 0640 "$domains"
fi
if ! nginx -t >/dev/null 2>&1; then
    # Alias corruption must not take down the host-managed primary. Prefer last known good.
    cp -- "$domains" /tmp/subscription-gateway/startup-domains.bad
    if [[ -f $domains.bak && ! -L $domains.bak ]]; then cp -- "$domains.bak" "$domains"; fi
    if ! nginx -t >/dev/null 2>&1; then printf '# Alias startup recovery: primary remains available.\n' > "$domains"; fi
    chown --reference=/control "$domains"; chmod 0640 "$domains"
fi
if ! nginx -t; then
    if [[ -f $rules.bak && ! -L $rules.bak ]]; then
        cp -- "$rules.bak" "$rules.restore"
        chmod 0640 "$rules.restore"
        sync -f "$rules.restore"
        mv -f -- "$rules.restore" "$rules"
        nginx -t || exit 1
        echo 'Invalid active rules restored from the last known backup.' >&2
    else
        exit 1
    fi
fi

nginx -g 'daemon off;' &
nginx_pid=$!
/usr/local/bin/watcher.sh &
watcher_pid=$!
trap 'kill "$nginx_pid" "$watcher_pid" 2>/dev/null || true; wait "$nginx_pid" "$watcher_pid" 2>/dev/null || true; exit 0' TERM INT
if wait -n "$nginx_pid" "$watcher_pid"; then
    status=1
else
    status=$?
fi
kill "$nginx_pid" "$watcher_pid" 2>/dev/null || true
wait "$nginx_pid" "$watcher_pid" 2>/dev/null || true
exit "$status"
