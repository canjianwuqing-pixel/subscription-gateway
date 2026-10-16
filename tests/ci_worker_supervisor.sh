#!/usr/bin/env bash
# Sourced by the real Docker suite after existing multi-domain tests.
set -euo pipefail
worker_checks=0
worker_pass() { worker_checks=$((worker_checks+1)); printf 'PASS WORKER %02d: %s\n' "$worker_checks" "$1"; }
worker_secret=SGW_TEST_CF_SECRET_NEVER_LOG_987654321
admin_id=$(compose ps -q admin)
health_code() {
    compose exec -T admin php -r '$c=curl_init("http://127.0.0.1:8080/healthz");curl_setopt($c,CURLOPT_RETURNTRANSFER,true);curl_exec($c);echo curl_getinfo($c,CURLINFO_RESPONSE_CODE);'
}
await_admin_restart() {
    local before=$1 host_pid=$2 attempt count current_pid state
    for attempt in {1..70}; do
        count=$(docker inspect --format '{{.RestartCount}}' "$admin_id")
        current_pid=$(docker inspect --format '{{.State.Pid}}' "$admin_id")
        state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$admin_id")
        if (( count > before )) && [[ $current_pid != 0 && $current_pid != "$host_pid" && $state == healthy ]]; then return; fi
        sleep 1
    done
    fail 'Admin did not automatically restart and become healthy'
}
run_setup_check() {
    local output=$1 owner status=0
    owner=$(stat -c '%u:%g' "$env_file")
    sudo chown 0:0 "$env_file"
    sudo bash "$root/setup.sh" --check > "$output" 2>&1 || status=$?
    sudo chown "$owner" "$env_file"
    return "$status"
}

# Record actual ash behavior instead of assuming Bash wait semantics.
compose exec -T admin sh -c 'busybox | head -1; sleep 2 & a=$!; sleep 0.1 & b=$!; start=$(date +%s); wait -n "$a" "$b"; echo "legacy multi-PID wait -n elapsed=$(( $(date +%s) - start ))s"; wait "$a" 2>/dev/null || true'
worker_pass 'Alpine /bin/sh legacy wait behavior probed in the actual Admin image'

docker cp "$root/tests/ci_worker_fault.php" "$admin_id:/tmp/ci_worker_fault.php"
compose exec -T admin chmod 0644 /tmp/ci_worker_fault.php
compose exec -T admin su-exec www-data touch /control/certificate-maintenance
sleep 3
printf '%s' "$worker_secret" | compose exec -T admin su-exec www-data php /tmp/ci_worker_fault.php queue > "$temporary/worker-queue.json"
worker_a=$(jq -er .a "$temporary/worker-queue.json");worker_b=$(jq -er .b "$temporary/worker-queue.json")
docker exec -d "$admin_id" su-exec www-data php /tmp/ci_worker_fault.php hold
restarts_before=$(docker inspect --format '{{.RestartCount}}' "$admin_id")
compose exec -T admin rm /control/certificate-maintenance
for attempt in {1..25}; do
    docker logs "$admin_id" > "$temporary/worker-docker.log" 2>&1
    if grep -q 'Certificate job failure state pending: ISSUE_FAILED' "$temporary/worker-docker.log" && grep -q 'Certificate worker iteration failed: SQLITE_BUSY_OR_LOCKED' "$temporary/worker-docker.log"; then break; fi
    sleep 1
done
grep -q 'Certificate job failure state pending: ISSUE_FAILED' "$temporary/worker-docker.log" || fail 'locked recovery lost the original safe issue-failure category'
grep -q 'Certificate worker iteration failed: SQLITE_BUSY_OR_LOCKED' "$temporary/worker-docker.log" || fail 'actual certificate worker did not catch the real recovery lock'
compose exec -T admin su-exec www-data php /tmp/ci_worker_fault.php states "$worker_a" "$worker_b" > "$temporary/worker-states.json"
jq -e '.a=="RUNNING" and .b=="PENDING"' "$temporary/worker-states.json" >/dev/null || fail 'locked fixture did not reproduce RUNNING/PENDING queue'
[[ $(health_code) == 200 ]] || fail 'live busy worker was incorrectly declared dead'
[[ $(docker inspect --format '{{.RestartCount}}' "$admin_id") == "$restarts_before" ]] || fail 'transient DB lock restarted Admin instead of surviving'
worker_pass 'real ACME failure/recovery SQLite lock is caught; worker remains alive and health is 200'
compose exec -T admin su-exec www-data touch /control/ci-release-sqlite
domain_wait "$worker_a" ACTIVE;domain_job_done "$worker_a"
domain_wait "$worker_b" ACTIVE;domain_job_done "$worker_b"
worker_pass 'RUNNING alias A recovers after unlock, then PENDING alias B completes ACTIVE/DONE'
if compose exec -T admin su-exec www-data php /app/src/certificate_worker.php; then fail 'second certificate worker acquired the singleton lock'; fi
worker_pass 'singleton OS flock refuses a second certificate worker'

# CI-only local resolver fixture; never alter Cloudflare A/AAAA records.
printf '127.0.0.1 gateway.test\n' | sudo tee -a /etc/hosts >/dev/null
restarts_before=$(docker inspect --format '{{.RestartCount}}' "$admin_id")
host_pid_before=$(docker inspect --format '{{.State.Pid}}' "$admin_id")
cert_pid=$(compose exec -T admin cat /run/certificate-worker.pid)
compose exec -T admin kill -STOP 1
compose exec -T admin kill -KILL "$cert_pid"
dead_health=$(health_code)
dead_check=0
if run_setup_check "$temporary/setup-worker-dead.log"; then dead_check=1; fi
compose exec -T admin kill -CONT 1
[[ $dead_health == 503 && $dead_check == 0 ]] || fail 'dead/zombie certificate worker was not rejected by health and setup --check'
worker_pass 'dead/zombie certificate worker gives health 503 and actual setup --check fails'
await_admin_restart "$restarts_before" "$host_pid_before"
compose exec -T admin su-exec www-data php /app/src/cli.php domain-check
worker_pass 'certificate worker death makes PID1 exit and Docker automatically restarts a healthy worker'

for process in token-worker php-fpm nginx; do
    restarts_before=$(docker inspect --format '{{.RestartCount}}' "$admin_id")
    host_pid_before=$(docker inspect --format '{{.State.Pid}}' "$admin_id")
    case $process in
        token-worker) victim=$(compose exec -T admin pgrep -f '^php /app/src/worker.php$');;
        php-fpm) victim=$(compose exec -T admin pgrep -o -f '^php-fpm: master process');;
        nginx) victim=$(compose exec -T admin pgrep -o -f '^nginx: master process');;
    esac
    [[ $victim =~ ^[0-9]+$ ]] || fail 'critical process fixture PID not unique'
    compose exec -T admin kill -TERM "$victim"
    await_admin_restart "$restarts_before" "$host_pid_before"
    worker_pass "$process death triggers an automatic container restart and healthy recovery"
done

before_lines=$(docker logs "$admin_id" 2>&1 | wc -l)
restarts_before=$(docker inspect --format '{{.RestartCount}}' "$admin_id")
compose stop admin >/dev/null
[[ $(docker inspect --format '{{.State.ExitCode}}' "$admin_id") == 0 ]] || fail 'normal Admin stop did not exit zero'
sleep 2
[[ $(docker inspect --format '{{.State.Running}}' "$admin_id") == false && $(docker inspect --format '{{.RestartCount}}' "$admin_id") == "$restarts_before" ]] || fail 'manual stop caused a restart loop'
docker logs "$admin_id" > "$temporary/worker-stopped.log" 2>&1
if tail -n "+$((before_lines+1))" "$temporary/worker-stopped.log" | grep -q 'Critical Admin child exited'; then fail 'normal stop was reported as a critical crash';fi
compose start admin >/dev/null;healthy admin
compose restart admin >/dev/null;healthy admin
worker_pass 'normal stop exits zero without restart loop; start/restart recover normally'
if ! run_setup_check "$temporary/setup-worker-ready.log"; then tail -15 "$temporary/setup-worker-ready.log" >&2; fail 'actual setup --check failed after worker recovery';fi
grep -q 'DOMAINS_OK.*worker=ready' "$temporary/setup-worker-ready.log" || fail 'setup --check hid the domain/worker diagnostic'
worker_pass 'actual setup --check passes again with DOMAINS_OK worker=ready'
docker logs "$admin_id" > "$temporary/worker-docker.log" 2>&1
if grep -Fq "$worker_secret" "$temporary/worker-docker.log" || sudo grep -RFaql -- "$worker_secret" "$runtime/data" "$runtime/control" "$runtime/domain-certs" "$runtime/logs" "$runtime/ssl";then fail 'worker recovery persisted/logged the complete fake CF secret';fi
worker_pass 'fake CF secret absent from Docker logs, SQLite/runtime/control/certificates/persistent ACME state'
printf 'PASS: %d real Docker worker/contention/supervisor/health/stop/security scenarios\n' "$worker_checks"
unset worker_secret
