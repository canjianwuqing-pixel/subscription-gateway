#!/bin/sh
set -eu

umask 027

mkdir -p /data /control /run/nginx
chown www-data:www-data /data /control
chmod 0750 /data /control /run/nginx

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

trap 'kill "$fpm_pid" "$nginx_pid" "$worker_pid" 2>/dev/null || true; wait "$fpm_pid" "$nginx_pid" "$worker_pid" 2>/dev/null || true; exit 0' TERM INT
if wait -n "$fpm_pid" "$nginx_pid" "$worker_pid"; then
    exit_status=1
else
    exit_status=$?
fi
kill "$fpm_pid" "$nginx_pid" "$worker_pid" 2>/dev/null || true
wait "$fpm_pid" "$nginx_pid" "$worker_pid" 2>/dev/null || true
exit "$exit_status"
