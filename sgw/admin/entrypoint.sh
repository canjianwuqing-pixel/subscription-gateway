#!/bin/sh
set -eu

umask 027

mkdir -p /data /control /domain-certs /run/nginx
chown www-data:www-data /data /control /domain-certs
chmod 0750 /domain-certs
chmod 0750 /data /control /run/nginx

# Substituting only validated DNS/port values prevents Nginx directive injection.
case ${ADMIN_PORT:-64444} in ''|*[!0-9]*) echo 'Invalid Admin port' >&2; exit 1;; esac
php -r 'require "/app/src/cloudflare.php"; domain_fqdn((string)getenv("GATEWAY_DOMAIN"));' || exit 1
domain_regex=$(printf '%s' "$GATEWAY_DOMAIN" | sed 's/\./\\\\./g')
sed -e "s/__GATEWAY_DOMAIN__/$GATEWAY_DOMAIN/g" -e "s/__GATEWAY_DOMAIN_REGEX__/$domain_regex/g" \
    -e "s/__ADMIN_PORT__/${ADMIN_PORT:-64444}/g" /etc/nginx/http.d/default.conf > /etc/nginx/http.d/default.conf.next
mv /etc/nginx/http.d/default.conf.next /etc/nginx/http.d/default.conf

su-exec www-data php -r '
require "/app/src/db.php";
initialize_database(app_db());
if (admin_count(app_db()) === 0) {
    fwrite(STDERR, "No administrator exists. Run the phase-four installer or the explicit password reset command first.\n");
    exit(1);
}
'
chmod 0640 "$DATABASE_PATH"

php-fpm -F &
fpm_pid=$!
nginx -g 'daemon off;' &
nginx_pid=$!
su-exec www-data php /app/src/worker.php &
worker_pid=$!
su-exec www-data php /app/src/certificate_worker.php &
cert_worker_pid=$!
printf '%s\n' "$cert_worker_pid" > /run/certificate-worker.pid
chown root:www-data /run/certificate-worker.pid
chmod 0640 /run/certificate-worker.pid

children="$fpm_pid $nginx_pid $worker_pid $cert_worker_pid"
process_alive() {
    kill -0 "$1" 2>/dev/null || return 1
    IFS= read -r process_stat 2>/dev/null < "/proc/$1/stat" || return 1
    case ${process_stat##*) } in Z*|X*) return 1;; esac
}
stop_children() {
    trap '' TERM INT
    kill $children 2>/dev/null || true
    # Bound shutdown below Docker's normal stop timeout; reap every direct child.
    shutdown_tick=0
    while [ "$shutdown_tick" -lt 5 ]; do
        remaining=no
        for child in $children; do if process_alive "$child"; then remaining=yes; fi; done
        [ "$remaining" = yes ] || break
        sleep 1
        shutdown_tick=$((shutdown_tick + 1))
    done
    for child in $children; do if process_alive "$child"; then kill -KILL "$child" 2>/dev/null || true; fi; done
    for child in $children; do wait "$child" 2>/dev/null || true; done
}
trap 'stop_children; exit 0' TERM INT
# BusyBox ash versions differ in wait -n with multiple PID operands. Explicitly
# inspect each critical child instead of accidentally waiting for all four.
while :; do
    for child in $children; do
        if ! process_alive "$child"; then
            echo 'Critical Admin child exited; restarting container' >&2
            stop_children
            exit 1
        fi
    done
    sleep 1
done
