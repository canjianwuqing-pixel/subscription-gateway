#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd "$(dirname "$0")/.." && pwd -P)
sgw=$root/sgw
runtime=$sgw/runtime
env_file=$sgw/.env
temporary=$(mktemp -d)
mock_id=
source_context_restricted=no

compose() { docker compose --project-directory "$sgw" -f "$sgw/docker-compose.yml" "$@"; }
fail() { printf 'CI Docker test failed: %s\n' "$1" >&2; exit 1; }
cleanup() {
    local status=$?
    trap - EXIT
    if (( status != 0 )) && [[ -f $env_file ]]; then
        printf 'CI failure; container status follows (no environment or request logs):\n' >&2
        compose ps >&2 || status=1
    fi
    if [[ -n $mock_id ]]; then
        docker rm -f "$mock_id" >/dev/null || status=1
    fi
    if [[ -f $env_file ]]; then
        compose down -v || status=1
    fi
    if [[ $source_context_restricted == yes ]]; then
        find "$sgw/admin/src" -type d -exec chmod 0755 {} + || status=1
        find "$sgw/admin/src" -type f -name '*.php' -exec chmod 0644 {} + || status=1
    fi
    if [[ $temporary == /tmp/* && -d $temporary && ! -L $temporary ]]; then
        rm -rf -- "$temporary"
    else
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT

for program in docker openssl curl jq python3 sudo sha256sum; do
    command -v "$program" >/dev/null || fail "missing CI tool: $program"
done
[[ $temporary == /tmp/* ]] || fail 'unsafe temporary directory'
[[ ! -e $runtime && ! -e $env_file ]] || fail 'CI requires a clean runtime directory'

docker version
docker compose version

mkdir -p "$runtime"/{data,control,generated,logs,ssl/releases/ci,backups/database}
chmod 0750 "$runtime" "$runtime"/{data,control,generated,logs,ssl,ssl/releases,ssl/releases/ci,backups,backups/database}
sudo chown 82:82 "$runtime/data" "$runtime/control" "$runtime/backups/database"
sudo chgrp 82 "$runtime/logs" "$runtime/ssl" "$runtime/ssl/releases" "$runtime/ssl/releases/ci"

cert=$runtime/ssl/releases/ci/fullchain.pem
key=$runtime/ssl/releases/ci/privkey.pem
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=gateway.test' -addext 'subjectAltName=DNS:gateway.test' \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
sudo chown root:82 "$cert"
sudo chmod 0640 "$cert"
sudo chmod 0600 "$key"
ln -s releases/ci "$runtime/ssl/active"

hmac=$(openssl rand -base64 32 | tr -d '\n')
encryption=$(openssl rand -base64 32 | tr -d '\n')
[[ $hmac != "$encryption" ]] || fail 'random CI keys collided'
admin_password=$(openssl rand -hex 24)
admin_path=$(openssl rand -hex 24)
token=$(openssl rand -hex 16)
cat > "$env_file" <<ENV
DATABASE_PATH=/data/subscription-gateway.db
GATEWAY_DOMAIN=gateway.test
GATEWAY_HTTPS_PORT=18443
ADMIN_BIND=127.0.0.1
ADMIN_PORT=16444
CERT_MODE=existing
APP_UID=82
APP_GID=82
TZ=UTC
TOKEN_EVENT_LOG_PATH=/var/log/subscription-gateway/token-events.log
ACTIVE_CERT_PATH=/ssl/active/fullchain.pem
DNS_RESOLVER=127.0.0.11
TRUSTED_PROXY_IPS=
REAL_IP_HEADER=X-Forwarded-For
ADMIN_SECRET_PATH=$admin_path
SESSION_NAME=subscription_gateway_ci
SESSION_COOKIE_SECURE=true
LOGIN_RATE_DIR=/tmp/subscription-gateway-login-rate
TOKEN_HMAC_KEY=$hmac
TOKEN_ENCRYPTION_KEY=$encryption
ENV
chmod 0600 "$env_file"
unset hmac encryption

compose config --quiet
# Reproduce the old restrictive Git checkout in the real Docker build context.
source_context_restricted=yes
find "$sgw/admin/src" -type f -name '*.php' -exec chmod 0600 {} +
find "$sgw/admin/src" -type d -exec chmod 0700 {} +
[[ $(stat -c %a "$sgw/admin/src/tracking.php") == 600 ]] || fail 'restrictive source fixture was not created'
compose build gateway admin
find "$sgw/admin/src" -type d -exec chmod 0755 {} +
find "$sgw/admin/src" -type f -name '*.php' -exec chmod 0644 {} +
source_context_restricted=no
compose run --rm --no-deps -T --entrypoint su-exec admin www-data php -r '
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator("/app/src", FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== "php") continue;
        if (!$file->isReadable() || $file->isWritable() || ($file->getPerms() & 0777) !== 0644 || $file->getOwner() !== 0) exit(1);
    }
    foreach (["tracking.php", "api.php", "dashboard.php"] as $name) {
        if (!is_readable("/app/src/" . $name)) exit(1);
        echo $name, " root:root 0644 readable, not writable by www-data\n";
    }
    require_once "/app/src/tracking.php";
    require_once "/app/src/api.php";
    require_once "/app/src/subscription_transform.php";
    echo "PASS: restrictive 0600 build context yields readable 0644 PHP and working www-data require chains\n";
' || fail 'Admin image PHP permissions or www-data require chain failed'
compose run --rm --no-deps -T --entrypoint su-exec admin \
    www-data php /app/src/cli.php migrate >/dev/null
printf '%s' "$admin_password" | compose run --rm --no-deps -T --entrypoint su-exec admin \
    www-data php /app/src/cli.php init-admin ci_admin >/dev/null

# Exercise the exact updater helper/CLI backup chain using the newly built image.
(. "$root/sgw/ops.sh"; admin_cli backup /backups/ci-permission.db) >/dev/null \
    || fail 'admin_cli backup failed in the new image'
compose run --rm --no-deps -T --entrypoint su-exec admin www-data php -r '
    $backup = new PDO("sqlite:/backups/ci-permission.db");
    if ($backup->query("PRAGMA integrity_check")->fetchColumn() !== "ok"
        || (int) $backup->query("SELECT COUNT(*) FROM admins")->fetchColumn() !== 1) exit(1);
' || fail 'new-image SQLite safe backup did not contain an intact database'
sudo chmod 0600 "$runtime/backups/database/ci-permission.db"
printf 'PASS: new-image admin_cli backup as www-data and SQLite backup integrity\n'

compose up -d
healthy() {
    local service=$1 id state attempt
    id=$(compose ps -q "$service")
    [[ -n $id ]] || return 1
    for attempt in {1..90}; do
        state=$(docker inspect --format '{{.State.Health.Status}}' "$id")
        [[ $state == healthy ]] && return 0
        [[ $state == unhealthy ]] && return 1
        sleep 2
    done
    return 1
}
healthy gateway || fail 'Gateway did not become healthy'
healthy admin || fail 'Admin did not become healthy'
compose exec -T gateway nginx -t
compose exec -T admin nginx -t
compose exec -T admin su-exec www-data php /app/src/cli.php installation-check
compose exec -T admin su-exec www-data php /app/src/cli.php transformer-check
for service in admin gateway; do
    [[ $(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$(compose ps -q "$service")") == unless-stopped ]] \
        || fail 'container restart policy is not unless-stopped'
done
admin_id=$(compose ps -q admin)
docker inspect "$admin_id" | jq -e '.[0].HostConfig.PortBindings["8081/tcp"] == null' >/dev/null \
    || fail 'internal transformer port is published to the host'

gateway_id=$(compose ps -q gateway)
network=$(docker inspect --format '{{range $name, $network := .NetworkSettings.Networks}}{{$name}}{{end}}' "$gateway_id")
[[ -n $network ]] || fail 'Compose network not found'
mock_id=$(docker run -d --rm --network "$network" --network-alias mock.gateway.test \
    -v "$root/tests/ci_mock_upstream.py:/mock.py:ro" python:3.12-alpine python /mock.py)
for attempt in {1..30}; do
    if docker exec "$mock_id" python -c \
        'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1).status == 200' \
        >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$mock_id" python -c \
    'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1).status == 200' \
    >/dev/null || fail 'Mock upstream did not start'

docker cp "$root/tests/ci_db.php" "$(compose ps -q admin):/tmp/ci_db.php"
db() { compose exec -T admin su-exec www-data php /tmp/ci_db.php "$@" >/dev/null; }
publish() {
    local configured active
    compose exec -T admin su-exec www-data php /app/src/cli.php compile >/dev/null
    read -r configured active <<< "$(compose exec -T admin su-exec www-data php /app/src/cli.php versions)"
    [[ $configured =~ ^[0-9]+$ && $configured == "$active" ]] || fail 'config_version differs from active_version'
    sudo test -s "$runtime/control/candidate.conf" \
        && sudo test -s "$runtime/control/request.json" \
        && sudo test -s "$runtime/control/result.json" \
        && sudo test -s "$runtime/generated/rules.conf" \
        || fail 'rule publication files are incomplete'
    sudo jq -e --argjson version "$configured" '.ok == true and .version == $version' \
        "$runtime/control/result.json" >/dev/null || fail 'rule publication result is not successful'
}
request() {
    local path=$1 ua=${2:-CI_Client/1} code
    request_exit=0
    if code=$(curl --silent --show-error --insecure --noproxy '*' \
        --resolve gateway.test:18443:127.0.0.1 --user-agent "$ua" \
        --output "$temporary/response" --write-out '%{http_code}' \
        "https://gateway.test:18443$path" 2>"$temporary/curl-error"); then
        :
    else
        request_exit=$?
    fi
    request_code=$code
}
expect() {
    local expected=$1 path=$2 ua=${3:-CI_Client/1}
    request "$path" "$ua"
    if [[ $expected == 444 ]]; then
        [[ $request_code == 000 && $request_exit -ne 0 ]] || fail 'expected Nginx connection close (444)'
    else
        [[ $request_exit == 0 && $request_code == "$expected" ]] \
            || fail "expected HTTP $expected, received $request_code (curl exit $request_exit)"
        if [[ $expected == 200 ]]; then
            [[ $(<"$temporary/response") == SGW_CI_MOCK_OK ]] || fail 'Mock upstream response mismatch'
        fi
    fi
}

path=/api/v1/ci/subscribe
expect 444 "$path?token=$token"
db configure http://mock.gateway.test:8080
publish
expect 444 /not-subscribe
expect 400 "$path"
expect 400 "$path?token=invalid"
expect 200 "$path?token=$token"
expect 200 "$path?token=$token&flag=meta"
expect 200 "$path?flag=meta&token=$token"
expect 400 "$path?token=$token&token=$token"
expect 400 "$path?token=$token&flag=meta&token=$token"
ingested=0
for attempt in {1..30}; do
    if db assert-ingested "$token" 2>/dev/null; then
        ingested=1
        break
    fi
    sleep 1
done
[[ $ingested == 1 ]] || fail 'worker did not securely ingest the Token event'

# Real TLS Admin requests exercise the actual session/authentication/API boundary.
admin_cookie=$temporary/admin-cookie
admin_url=https://127.0.0.1:16444/$admin_path
admin_request() {
    admin_code=$(curl --silent --show-error --insecure --noproxy '*' \
        --cookie "$admin_cookie" --cookie-jar "$admin_cookie" \
        --output "$temporary/admin-response" --write-out '%{http_code}' "$admin_url/$1" "${@:2}")
}
for endpoint in api/tokens api/analysis/tokens api/logs api/tokens/1/full api/tokens/1/detail; do
    admin_request "$endpoint"
    [[ $admin_code == 401 ]] || fail 'anonymous Admin Token endpoint was not denied'
    if grep -Fq "$token" "$temporary/admin-response"; then fail 'anonymous API leaked a Token'; fi
done
admin_request api/session
admin_csrf=$(jq -er .csrf_token "$temporary/admin-response")
jq -n --arg password "$admin_password" '{username:"ci_admin",password:$password}' > "$temporary/login.json"
admin_request api/login --request POST --header 'Content-Type: application/json' \
    --header "X-CSRF-Token: $admin_csrf" --data-binary "@$temporary/login.json"
[[ $admin_code == 200 ]] || fail 'Admin login failed'
admin_csrf=$(jq -er .csrf_token "$temporary/admin-response")
admin_request api/tokens
jq -e --arg token "$token" '.tokens | any(.token == $token and .tracking_group_path != null and .token_encrypted == null)' \
    "$temporary/admin-response" >/dev/null || fail 'authenticated Token list lacks full Token or off assignment'
token_id=$(jq -er --arg token "$token" '.tokens[] | select(.token == $token) | .id' "$temporary/admin-response")
admin_request "api/tokens/$token_id/detail"
jq -e --arg token "$token" '.detail.token.token == $token and .detail.token.tracking_group_path != null' \
    "$temporary/admin-response" >/dev/null || fail 'Token detail lacks full Token or group'
admin_request "api/logs?token=$token"
jq -e --arg token "$token" '.result.rows | length > 0 and all(.token == $token and .tracking_group_path != null)' \
    "$temporary/admin-response" >/dev/null || fail 'full Token log search failed'
admin_request "api/logs?token=$(openssl rand -hex 16)"
[[ $admin_code == 200 ]] && jq -e '.result.rows == []' "$temporary/admin-response" >/dev/null \
    || fail 'unknown Token log search did not return empty'
admin_request 'api/logs?token=partial'
[[ $admin_code == 422 ]] || fail 'partial Token search was not rejected'
manual_token=$(openssl rand -hex 16)
jq -n --arg token "$manual_token" '{token:$token,state:"NORMAL"}' > "$temporary/manual-token.json"
admin_request api/tokens --request POST --header 'Content-Type: application/json' \
    --header "X-CSRF-Token: $admin_csrf" --data-binary "@$temporary/manual-token.json"
[[ $admin_code == 200 || $admin_code == 202 ]] || fail 'manual Token API failed'
db assert-assigned "$manual_token"

# Independent second login must be invalidated by auth_version, not just rotation.
primary_cookie=$admin_cookie
admin_cookie=$temporary/other-admin-cookie
admin_request api/session
other_csrf=$(jq -er .csrf_token "$temporary/admin-response")
admin_request api/login --request POST --header 'Content-Type: application/json' \
    --header "X-CSRF-Token: $other_csrf" --data-binary "@$temporary/login.json"
[[ $admin_code == 200 ]] || fail 'second independent Admin login failed'
other_cookie=$admin_cookie
admin_cookie=$primary_cookie
jq -n --arg password "$admin_password" '{current_password:$password,new_password:"123456"}' > "$temporary/password.json"
admin_request api/admin/password --request PATCH --header 'Content-Type: application/json' \
    --header "X-CSRF-Token: $admin_csrf" --data-binary "@$temporary/password.json"
[[ $admin_code == 200 ]] || fail 'six-byte Admin password was not accepted'
admin_request api/tokens
[[ $admin_code == 200 ]] || fail 'password change invalidated the current session'
admin_cookie=$other_cookie
admin_request api/tokens
[[ $admin_code == 401 ]] || fail 'password change did not invalidate another session'
admin_cookie=$primary_cookie
admin_request ''
[[ $admin_code == 200 ]] || fail 'authenticated dashboard could not be rendered'
grep -Fq 'color-scheme:light' "$temporary/admin-response" || fail 'dashboard is not light themed'
if grep -Fq "$token" "$temporary/admin-response" || grep -Fq "$manual_token" "$temporary/admin-response"; then
    fail 'dashboard statically embedded full Tokens'
fi
unset admin_password admin_path manual_token admin_csrf other_csrf
printf 'PASS: authenticated Admin APIs, exact Token logs, off assignments, six-byte password and session invalidation\n'

# Start with no configured mappings: preflight must learn and return original bytes.
db tracking-mode preflight
publish
request "$path?token=$token&format=uri"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'empty-mapping preflight failed'
grep -Fq '@origin.example.invalid:443' "$temporary/response" \
    || fail 'empty-mapping preflight changed the original body'
db assert-learned origin.example.invalid

db tracking-configure "$token" preflight
publish
request "$path?token=$token&format=uri"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'preflight transformer request failed'
grep -Fq '@origin.example.invalid:443' "$temporary/response" \
    || fail 'preflight did not preserve the original subscription body'
request "$path?token=$token&format=unknown"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'preflight unknown-format request failed'
[[ $(<"$temporary/response") == 'not a supported subscription document' ]] \
    || fail 'preflight failure did not preserve the original response'
request "$path?token=$token&format=large"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'preflight oversized response failed'
[[ $(stat -c %s "$temporary/response") == 8388609 ]] \
    || fail 'preflight did not preserve an oversized original response'
compose stop admin >/dev/null
request "$path?token=$token&format=uri"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'preflight did not fall back when Transformer was unavailable'
grep -Fq '@origin.example.invalid:443' "$temporary/response" \
    || fail 'preflight unavailable fallback did not return the original subscription'
compose start admin >/dev/null
healthy admin || fail 'Admin did not recover after Transformer fallback test'

db tracking-mode enforced
publish
tracking_target=$(compose exec -T admin su-exec www-data php /tmp/ci_db.php \
    tracking-target "$token" | tr -d '\r\n')
[[ $tracking_target =~ ^group[123]\.example\.invalid$ ]] || fail 'invalid effective tracking target'
request "$path?token=$token&format=uri"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'enforced URI transform failed'
grep -Fq "@$tracking_target:443" "$temporary/response" || fail 'URI authority host was not transformed'
grep -Fq 'sni=origin.example.invalid' "$temporary/response" || fail 'URI non-authority fields changed'
request "$path?token=$token&format=uri&upstream=http%3A%2F%2Fredirect-target.example.invalid"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'fixed-origin request failed'
grep -Fq "@$tracking_target:443" "$temporary/response" \
    || fail 'a client query parameter affected the fixed upstream behavior'

request "$path?token=$token&format=yaml"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'enforced YAML transform failed'
grep -Eq "^[[:space:]]*server:[[:space:]]*$tracking_target[[:space:]]*$" "$temporary/response" \
    || fail 'YAML server host was not transformed'
grep -Fq 'sni: origin.example.invalid' "$temporary/response" || fail 'YAML SNI changed unexpectedly'

request "$path?token=$token&format=base64"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'enforced Base64 transform failed'
python3 - "$temporary/response" "$tracking_target" <<'PY'
import base64
import pathlib
import sys

payload = pathlib.Path(sys.argv[1]).read_bytes().strip()
payload += b"=" * (-len(payload) % 4)
decoded = base64.b64decode(payload, validate=True).decode()
assert f"@{sys.argv[2]}:443" in decoded
assert "sni=origin.example.invalid" in decoded
PY

request "$path?token=$token&format=unknown"
[[ $request_exit == 0 && $request_code == 502 ]] || fail 'enforced unknown format did not fail closed'
if grep -Fq 'not a supported subscription document' "$temporary/response"; then
    fail 'enforced transform failure leaked the original body'
fi
request "$path?token=$token&format=large"
[[ $request_exit == 0 && $request_code == 502 ]] || fail 'enforced oversized response did not fail closed'
[[ $(stat -c %s "$temporary/response") -lt 8388609 ]] || fail 'enforced oversized response leaked the original body'
request "$path?token=$token&format=unauthorized"
[[ $request_exit == 0 && $request_code == 401 ]] || fail 'upstream non-2xx status was not preserved'
[[ $(<"$temporary/response") == UPSTREAM_UNAUTHORIZED ]] || fail 'upstream non-2xx body was not preserved'
request "$path?token=$token&format=redirect"
[[ $request_exit == 0 && $request_code == 302 ]] || fail 'upstream redirect status was not preserved'
[[ $(<"$temporary/response") == UPSTREAM_REDIRECT ]] || fail 'transformer followed an upstream redirect'
compose stop admin >/dev/null
request "$path?token=$token&format=uri"
[[ $request_exit == 0 && $request_code == 503 ]] || fail 'enforced mode did not fail closed when Transformer was unavailable'
if grep -Fq '@origin.example.invalid:443' "$temporary/response"; then
    fail 'enforced unavailable Transformer fell back to the original subscription'
fi
compose start admin >/dev/null
healthy admin || fail 'Admin did not recover after enforced failure test'

request "$path?token=$token&format=new-source"
[[ $request_exit == 0 && $request_code == 503 ]] || fail 'new unmapped source did not fail closed in enforced mode'
if grep -Fq '@new.example.invalid:443' "$temporary/response"; then fail 'enforced missing mapping leaked original body'; fi
db assert-learned new.example.invalid
db tracking-mode preflight
publish
request "$path?token=$token&format=new-source"
[[ $request_exit == 0 && $request_code == 200 ]] || fail 'new-source preflight failed'
grep -Fq '@new.example.invalid:443' "$temporary/response" || fail 'new-source preflight altered original body'
db tracking-configure "$token" enforced
publish
printf 'PASS: source auto-learning, empty-mapping preflight and enforced missing-target fail-closed\n'

db token "$token" BLOCKED
publish
expect 403 "$path?token=$token&format=uri"
db token "$token" NORMAL
db tracking-mode off
publish

client_ip=$(sudo jq -r 'select(.path == "/api/v1/ci/subscribe" and .status == 200) | .ip' \
    "$runtime/logs/access.log" | tail -n 1)
[[ $client_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'real client IPv4 not found in access log'

db token "$token" BLOCKED
publish
expect 403 "$path?token=$token"
db token "$token" NORMAL
publish

db ip "$client_ip" BLACKLIST
publish
expect 403 "$path?token=$token"
db clear-ip
publish

db ua BLACKLIST
publish
expect 403 "$path?token=$token" CI_Blocked_Client/1
db token "$token" WHITELIST
publish
expect 200 "$path?token=$token" CI_Blocked_Client/1
db token "$token" NORMAL
db ip "$client_ip" WHITELIST
publish
expect 200 "$path?token=$token" CI_Blocked_Client/1
db clear-ip
db clear-ua
publish

db rate on
publish
expect 200 "$path?token=$token"
expect 429 "$path?token=$token"
db rate off
publish

db token "$token" TEMP_BLOCKED
publish
expect 403 "$path?token=$token"
recovered=0
for attempt in {1..45}; do
    request "$path?token=$token"
    if [[ $request_exit == 0 && $request_code == 200 ]]; then
        [[ $(<"$temporary/response") == SGW_CI_MOCK_OK ]] || fail 'recovered response mismatch'
        recovered=1
        break
    fi
    sleep 2
done
[[ $recovered == 1 ]] || fail 'TEMP_BLOCKED was not released by Gateway watcher'

old_hash=$(sudo sha256sum "$runtime/generated/rules.conf" | cut -d ' ' -f 1)
read -r configured active <<< "$(compose exec -T admin su-exec www-data php /app/src/cli.php versions)"
printf 'invalid_ci_nginx_directive;\n' > "$temporary/invalid.conf"
bad_hash=$(sha256sum "$temporary/invalid.conf" | cut -d ' ' -f 1)
bad_id=$(openssl rand -hex 16)
sudo install -o 82 -g 82 -m 0640 "$temporary/invalid.conf" "$runtime/control/candidate.conf"
printf '{"id":"%s","version":%s,"sha256":"%s"}\n' \
    "$bad_id" "$((configured + 1))" "$bad_hash" > "$temporary/request.json"
sudo install -o 82 -g 82 -m 0640 "$temporary/request.json" "$runtime/control/request.json"
rejected=0
for attempt in {1..30}; do
    if sudo test -f "$runtime/control/result.json" && sudo jq -e --arg id "$bad_id" \
        '.id == $id and .ok == false and .error_code == "NGINX_TEST_FAILED"' \
        "$runtime/control/result.json" >/dev/null; then
        rejected=1
        break
    fi
    sleep 1
done
[[ $rejected == 1 ]] || fail 'invalid candidate was not rejected'
[[ $(sudo sha256sum "$runtime/generated/rules.conf" | cut -d ' ' -f 1) == "$old_hash" ]] \
    || fail 'invalid candidate changed active rules'
expect 200 "$path?token=$token"
compose exec -T gateway nginx -t
read -r configured_after active_after <<< "$(compose exec -T admin su-exec www-data php /app/src/cli.php versions)"
[[ $configured_after == "$configured" && $active_after == "$active" ]] \
    || fail 'rejected candidate changed active/config versions'

sleep 1
sudo jq -e 'select(.path == "/not-subscribe" and .status == 444)' \
    "$runtime/logs/access.log" >/dev/null || fail 'non-subscription path was not logged as 444'
if sudo grep -Fq '?token=' "$runtime/logs/access.log" \
    || sudo grep -Fq "$token" "$runtime/logs/access.log" \
    || sudo grep -Fq 'flag=meta' "$runtime/logs/access.log"; then
    fail 'ordinary access log contains Token or Query data'
fi
[[ $(stat -c %a "$env_file") == 600 ]] || fail '.env permission is not 0600'
[[ $(stat -c %a "$key") == 600 ]] || fail 'TLS private key permission is not 0600'
[[ $(stat -c %a "$runtime/logs/token-events.log") == 640 ]] \
    || fail 'Token event log permission is not 0640'
if sudo find "$runtime" \( -type f -o -type d \) -perm /0022 -print -quit | grep -q .; then
    fail 'runtime contains group/world writable files or directories'
fi

printf 'PASS: real Linux Docker, Nginx, mock upstream, rules, expiry, logs and permissions\n'
