#!/usr/bin/env bash
# Sourced after existing CI subscription tests, using their real containers and authenticated Admin helper.
set -euo pipefail
secret=known_Cloudflare_secret_DO_NOT_PERSIST_9876
domain_passed=0
domain_pass() { domain_passed=$((domain_passed+1)); printf 'PASS DOMAIN %02d: %s\n' "$domain_passed" "$1"; }
alias_id=
domain_wait() {
    local id=$1 expected=$2 attempt
    for attempt in {1..90}; do
        admin_request api/domains
        if jq -e --argjson id "$id" --arg state "$expected" 'any(.domains[];.id==$id and .status==$state)' "$temporary/admin-response" >/dev/null; then return; fi
        sleep 1
    done
    fail "alias did not reach $expected"
}
alias_request() {
    local host=$1 path=$2 port=${3:-18443}
    alias_exit=0
    alias_code=$(curl --silent --show-error --insecure --noproxy '*' --resolve "$host:$port:127.0.0.1" \
        --user-agent CI_Client/1 --output "$temporary/alias-response" --write-out '%{http_code}' "https://$host:$port$path" 2>/dev/null) || alias_exit=$?
}
add_alias() {
    local host=$1 zone=$2
    jq -n --arg fqdn "$host" --arg token "$secret" --arg zone "$zone" '{fqdn:$fqdn,token:$token,zone_id:$zone}' > "$temporary/domain.json"
    admin_request api/domains --request POST --header "X-CSRF-Token: $admin_csrf" --data-binary "@$temporary/domain.json"
    [[ $admin_code == 202 ]] || fail 'inline alias add was not asynchronous'
    alias_id=$(jq -er .id "$temporary/admin-response")
    domain_pass 'direct domain/token/zone returns 202/PENDING'
}
sni_fingerprint() {
    openssl s_client -connect 127.0.0.1:18443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
}
printf '%s\n%s\n' "$secret" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | compose run --rm --no-deps -T --entrypoint su-exec admin www-data php /app/src/cli.php cloudflare-bootstrap >/dev/null
domain_pass 'installer bootstrap encrypts CF profile using stdin'
add_alias a.example.net aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
alias_a=$alias_id; domain_wait "$alias_a" ACTIVE
domain_pass 'alias A certificate worker reaches ACTIVE after watcher ACK'
add_alias node.other.org bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
alias_b=$alias_id; domain_wait "$alias_b" ACTIVE
domain_pass 'different-zone alias B gets its independent certificate'
primary_fp=$(sni_fingerprint gateway.test); a_fp=$(sni_fingerprint a.example.net); b_fp=$(sni_fingerprint node.other.org)
[[ $primary_fp != "$a_fp" && $primary_fp != "$b_fp" && $a_fp != "$b_fp" ]] || fail 'SNI certificates were shared'
for pair in 'gateway.test primary' 'a.example.net aliasA' 'node.other.org aliasB'; do domain_pass "real TLS SNI certificate: $pair"; done
path="/api/v1/test/subscribe?token=$token&format=uri"
request "$path"; [[ $request_code == 200 ]] || fail 'primary subscription unavailable'
cp "$temporary/response" "$temporary/primary-subscription"
for host in a.example.net node.other.org; do
    alias_request "$host" "$path"; [[ $alias_code == 200 ]] || fail 'alias subscription unavailable'
    cmp "$temporary/primary-subscription" "$temporary/alias-response" || fail 'alias changed subscription'
    domain_pass 'alias subscription uses identical shared Gateway business chain'
    alias_request "$host" /unknown; [[ $alias_exit == 52 ]] || fail 'alias non-subscription path was not 444'
    domain_pass 'alias unknown path returns 444'
    alias_request "$host" "/$admin_path/" 16444; [[ $alias_exit == 52 ]] || fail 'alias entered Admin port'
    domain_pass 'Admin refuses alias Host even with ignored TLS mismatch'
done
db assert-assigned "$token"
compose exec -T admin su-exec www-data php -r 'require "/app/src/domain_certificates.php"; $q=app_db()->prepare("SELECT COUNT(*) FROM tracking_assignments WHERE token_hash=?");$q->execute([token_hash_value($argv[1])]);if((int)$q->fetchColumn()!==1)exit(1);' "$token"
domain_pass 'same token retains exactly one assignment through all Hosts'
compose exec -T admin su-exec www-data php /app/src/cli.php domain-check
domain_pass 'setup diagnostic checks primary, aliases, certificate permissions and worker'
admin_request api/domains
! grep -Fq "$secret" "$temporary/admin-response" || fail 'GET API exposed CF secret'
! grep -Fq token_encrypted "$temporary/admin-response" || fail 'GET API exposed ciphertext'
domain_pass 'GET domains/profile returns only masked configured-token metadata'
admin_request '';! grep -Fq "$secret" "$temporary/admin-response" || fail 'HTML exposed CF secret'
domain_pass 'Admin HTML contains no CF secret'
profile_id=$(compose exec -T admin su-exec www-data php -r 'require "/app/src/domain_certificates.php"; echo domain_row(app_db(),(int)$argv[1])["credential_id"];' "$alias_a")
admin_request "api/cloudflare/$profile_id" --request PATCH --header "X-CSRF-Token: $admin_csrf" --data '{"token":"","name":"edited profile"}'
[[ $admin_code == 200 ]] || fail 'blank profile edit failed';domain_pass 'blank Token edit preserves credential'
admin_request "api/cloudflare/$profile_id/test" --request POST --header "X-CSRF-Token: $admin_csrf"
jq -e '.tested==true' "$temporary/admin-response" >/dev/null;domain_pass 'real PHP curl test reaches mock CF zone API'
admin_request "api/cloudflare/$profile_id" --request DELETE --header "X-CSRF-Token: $admin_csrf"
[[ $admin_code == 422 ]] || fail 'referenced profile deleted';domain_pass 'profile with active alias cannot be deleted'
for fqdn in a.example.net gateway.test; do
    admin_request api/domains --request POST --header "X-CSRF-Token: $admin_csrf" --data "{\"fqdn\":\"$fqdn\",\"credential_id\":$profile_id}"
    [[ $admin_code == 422 ]] || fail 'duplicate/primary accepted';domain_pass 'duplicate/primary alias rejected'
done
add_alias fail.example.net aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
failed_alias=$alias_id;domain_wait "$failed_alias" ERROR
[[ $(sni_fingerprint a.example.net) == "$a_fp" && $(sni_fingerprint node.other.org) == "$b_fp" ]] || fail 'failed alias changed other certificates'
domain_pass 'failed issuance is isolated and stores ERROR'
compose exec -T admin sh -c 'touch /control/ci-wrong-host'
add_alias wrong-san.example.net aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
wrong_alias=$alias_id;domain_wait "$wrong_alias" ERROR
compose exec -T admin rm /control/ci-wrong-host
domain_pass 'wrong SAN never activates an alias'

# Intercept only the reload command; nginx -t and TLS server remain real. Failure is one-shot, then restore reload works.
docker cp "$root/tests/ci_nginx_fault.sh" "$gateway_id:/tmp/ci_nginx_fault.sh"
compose exec -T gateway sh -c 'mv /usr/sbin/nginx /usr/sbin/nginx.real; cp /tmp/ci_nginx_fault.sh /usr/sbin/nginx; chmod 755 /usr/sbin/nginx'
inject_gateway_failure() { compose exec -T gateway sh -c "touch /tmp/ci-$1-once"; }
inject_gateway_failure test
add_alias rejected.example.net aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
rejected_alias=$alias_id;domain_wait "$rejected_alias" ERROR
domain_pass 'real domain channel test rejection leaves primary/old alias live'
inject_gateway_failure reload
admin_request "api/domains/$rejected_alias/retry" --request POST --header "X-CSRF-Token: $admin_csrf"
domain_wait "$rejected_alias" ERROR
domain_pass 'real domain channel reload failure preserves old domains.conf'
inject_gateway_failure reload
admin_request "api/domains/$alias_a/retry" --request POST --header "X-CSRF-Token: $admin_csrf"
for attempt in {1..30};do
    state=$(compose exec -T admin su-exec www-data php -r 'require "/app/src/domain_certificates.php"; echo domain_row(app_db(),(int)$argv[1])["last_error"];' "$alias_a")
    [[ $state == *续签失败* ]] && break;sleep 1
done
[[ $state == *续签失败* ]] || fail 'renew failure not recorded'
[[ $(sni_fingerprint a.example.net) == "$a_fp" && $(sni_fingerprint node.other.org) == "$b_fp" ]] || fail 'renew rollback changed old cert or other alias'
domain_pass 'renew reload failure restores old certificate and keeps B unchanged'
account_sha=$(sudo sha256sum "$runtime/domain-certs/$alias_a/acme/ca/test-ca/account.key" | cut -d' ' -f1)
admin_request "api/domains/$alias_a/retry" --request POST --header "X-CSRF-Token: $admin_csrf"
for attempt in {1..40};do new_a_fp=$(sni_fingerprint a.example.net);[[ $new_a_fp != "$a_fp" ]] && break;sleep 1;done
[[ $new_a_fp != "$a_fp" ]] || fail 'renew did not rotate cert';domain_wait "$alias_a" ACTIVE
[[ $(sudo sha256sum "$runtime/domain-certs/$alias_a/acme/ca/test-ca/account.key" | cut -d' ' -f1) == "$account_sha" ]] || fail 'ACME account regenerated'
domain_pass 'renew atomically rotates only A and reuses persistent ACME account key'
inject_gateway_failure reload
admin_request "api/domains/$alias_b" --request DELETE --header "X-CSRF-Token: $admin_csrf"
domain_wait "$alias_b" ACTIVE
[[ $(sni_fingerprint node.other.org) == "$b_fp" ]] || fail 'failed removal lost B'
domain_pass 'failed deletion restores ACTIVE and old SNI certificate'
admin_request "api/domains/$alias_b" --request DELETE --header "X-CSRF-Token: $admin_csrf"
for attempt in {1..30};do admin_request api/domains; jq -e --argjson id "$alias_b" 'all(.domains[];.id!=$id)' "$temporary/admin-response" >/dev/null && break;sleep 1;done
jq -e --argjson id "$alias_b" 'all(.domains[];.id!=$id)' "$temporary/admin-response" >/dev/null || fail 'alias delete did not finish'
sudo test ! -d "$runtime/domain-certs/$alias_b" || fail 'alias certificate directory not cleaned'
domain_pass 'successful removal ACK precedes DB/certificate/ACME cleanup'
admin_request api/domains/1 --request DELETE --header "X-CSRF-Token: $admin_csrf"
[[ $admin_code == 422 ]] || fail 'primary deletion accepted';domain_pass 'primary delete explicitly refused'
compose restart gateway >/dev/null;healthy gateway
alias_request a.example.net "$path";[[ $alias_code == 200 ]] || fail 'alias missing after restart'
domain_pass 'Gateway restart restores persisted domains.conf and SNI'
sudo cp "$runtime/control/domains.conf" "$runtime/control/domains.conf.bak"
printf 'invalid alias nginx directive;\n' | sudo tee "$runtime/control/domains.conf" >/dev/null
compose restart gateway >/dev/null;healthy gateway
request "$path";[[ $request_code == 200 ]] || fail 'corrupt domains killed primary'
alias_request a.example.net "$path";[[ $alias_code == 200 ]] || fail 'last known good aliases not recovered'
domain_pass 'corrupt startup domains fall back to last known good without losing primary'
if sudo grep -RFaql -- "$secret" "$runtime/data" "$runtime/control" "$runtime/domain-certs" "$runtime/logs" "$runtime/ssl";then fail 'CF plaintext persisted';fi
domain_pass 'known-secret scan of SQLite/runtime/control/certs/ACME/logs is clean'
compose exec -T admin su-exec www-data php -r '
require "/app/src/domain_certificates.php";
$secret="known_Cloudflare_secret_DO_NOT_PERSIST_9876";
foreach(app_db()->query("SELECT token_encrypted FROM cloudflare_credentials")->fetchAll(PDO::FETCH_COLUMN)as$cipher)if(cloudflare_decrypt($cipher)!==$secret)exit(1);
if(is_writable("/ssl/active/privkey.pem"))exit(1);
';domain_pass 'ciphertext decrypts only in worker memory; primary private key remains RO'
printf 'PASS: %d real Docker multi-domain/worker/SNI/security scenarios (mock CF/ACME; no live LetsEncrypt issuance)\n' "$domain_passed"
unset secret
