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

trap 'kill "$fpm_pid" "$nginx_pid" "$worker_pid" "$cert_worker_pid" 2>/dev/null || true; wait "$fpm_pid" "$nginx_pid" "$worker_pid" "$cert_worker_pid" 2>/dev/null || true; exit 0' TERM INT
if wait -n "$fpm_pid" "$nginx_pid" "$worker_pid" "$cert_worker_pid"; then
    exit_status=1
else
    exit_status=$?
fi
kill "$fpm_pid" "$nginx_pid" "$worker_pid" "$cert_worker_pid" 2>/dev/null || true
wait "$fpm_pid" "$nginx_pid" "$worker_pid" "$cert_worker_pid" 2>/dev/null || true
exit "$exit_status"
