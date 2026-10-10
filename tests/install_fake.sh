#!/usr/bin/env bash
# Executes the real first_install/check/uninstall/purge functions in child shells.
# Only external operations (Docker, ACME, packages, ports, database) are mocked.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)

if [[ ${1:-} == --driver ]]; then
    state=$2 action=$3
    export TEST_STATE=$state
    . "$root/setup.sh"
    SGW_DIR=$state/sgw RUNTIME=$state/sgw/runtime ENV_FILE=$state/sgw/.env
    COMPOSE_FILE=$SGW_DIR/docker-compose.yml
    export PATH="$state/bin:$PATH"
    log() { printf '%s\n' "$*" >> "$state/calls"; }
    inject() { [[ ! -f $state/fail || $(<"$state/fail") != "$1" ]]; }
    require_root() { :; }
    check_os_arch_disk() { :; }
    check_platform() { :; }
    acme_home() { printf '%s/acme\n' "$state"; }
    # NTFS does not implement Linux ownership/modes. Linux CI uses the real
    # permission checks and make_runtime (and runs this test as root).
    if [[ $(uname -s) != Linux ]]; then
        private_root_file() { [[ -f $1 && ! -L $1 ]]; }
        chown() { :; }
        chgrp() { :; }
        flock() { :; }
        stat() {
            if [[ ${2:-} == %a && -d ${3:-} ]]; then printf '750\n'
            elif [[ ${2:-} == %u ]]; then printf '0\n'
            elif [[ ${2:-} == %a && ${3:-} == */deploy-hook.sh ]]; then printf '700\n'
            else builtin command stat "$@"; fi
        }
    fi
    case $action in
        ops-*)
            # Deterministic service tests; all service commands remain mocks.
            systemd_running() { [[ -f $state/systemd ]]; }
            pgrep() { [[ -f $state/cron-running ]]; }
            ;; # Retain the real dependency/bootstrap/port implementations.
        *)
            ensure_port_tools() { :; }
            ensure_docker() { log docker-ready; }
            assert_install_ports() {
                log "ports $1 $2"
                [[ ! -f $state/conflict ]] || die "Host port $(<"$state/conflict") occupied"
            }
            ensure_cron() { log cron; inject cron || die 'cron unavailable'; }
            acquire_certificate() {
                log "certificate $1"
                [[ $1 != http-01 || ! -f $state/port80 ]] || die 'Port 80 occupied'
                cp "$state/cert.pem" "$RUNTIME/ssl/staging/fullchain.pem"
                cp "$state/key.pem" "$RUNTIME/ssl/staging/privkey.pem"
            }
            cert_activate() {
                log activate
                mkdir -p "$RUNTIME/ssl/active"
                cp "$RUNTIME/ssl/staging/"*.pem "$RUNTIME/ssl/active/"
            }
            acme_renewal_ready() { [[ -f $state/renewal ]]; }
            register_acme_hook() { log hook; inject hook || return 1; touch "$state/renewal"; }
            compose() {
                log "compose $*"
                case $1 in
                    config) inject config;;
                    build) inject build || return 1; touch "$state/images";;
                    up) inject up || return 1; touch "$state/running";;
                    down) rm -f "$state/running";;
                    ps) [[ ! -f $state/running ]] || printf '%s-id\n' "${3:-admin}";;
                    exec)
                        case ${*: -1} in
                            installation-check) admin_cli installation-check;;
                            transformer-check) inject transformer && inject extensions;;
                            integrity) inject integrity;;
                            versions) if inject versions; then printf '1 1\n'; else printf '2 1\n'; fi;;
                            upstream-state) printf 'EMPTY\n';;
                            *) inject nginx;;
                        esac;;
                esac
            }
            admin_cli() {
                log "cli $*"
                case $1 in
                    installation-probe) [[ -f $state/images ]];;
                    installation-check)
                        [[ -f $state/schema && $(<"$state/schema") == 4 && -f $state/admin ]] \
                            && inject schema && inject extensions && inject tracking;;
                    migrate)
                        inject migrate || return 1
                        printf '4\n' > "$state/schema"
                        [[ -f $RUNTIME/data/subscription-gateway.db ]] || printf 'retained tokens/ip/ua/logs/tracking\n' > "$RUNTIME/data/subscription-gateway.db";;
                    admin-status)
                        if [[ -f $state/admin ]]; then printf '1 %s\n' "$(<"$state/admin")"; else printf '0\n'; fi;;
                    init-admin)
                        inject init || return 1
                        printf '%s\n' "$2" > "$state/admin"
                        sha256sum | cut -d ' ' -f 1 > "$state/password-hash";;
                    reset-admin-password) sha256sum | cut -d ' ' -f 1 > "$state/password-hash";;
                esac
            }
            wait_health() { [[ -f $state/running ]] && inject health; }
            ;;
    esac
    case $action in
        install) first_install;;
        check) check_install;;
        uninstall) uninstall_installation;;
        purge) purge_installation;;
        ops-acme) acme_binary;;
        ops-cron) ensure_cron;;
        ops-docker) ensure_docker;;
        ops-ports) assert_install_ports 443 64444;;
        ops-http) make_runtime; acquire_certificate http-01 gateway.test;;
        ops-existing) make_runtime; acquire_certificate existing gateway.test; register_acme_hook existing gateway.test;;
        ops-renewal) make_runtime; ensure_deploy_hook >/dev/null; acme_renewal_ready gateway.test;;
        ops-cleanup)
            INSTALL_DOMAIN=gateway.test INSTALL_LOCK_HELD=no
            [[ ! -f $state/lock-held ]] || INSTALL_LOCK_HELD=yes
            installation_cleanup 1;;
        *) exit 1;;
    esac
    exit
fi

test_root=$(mktemp -d)
[[ $test_root == /tmp/* && -d $test_root && ! -L $test_root ]] || exit 1
cleanup() {
    local status=$?
    if (( status != 0 )); then
        printf 'Installer test failed in %s\n' "${state:-initialization}" >&2
        if [[ -f ${state:-}/output ]]; then
            sed '/password (shown once):/d' "$state/output" >&2
        fi
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT
passed=0
pass() { passed=$((passed+1)); printf 'PASS %02d: %s\n' "$passed" "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
expect() { "$@" || fail "assertion: $*"; }
new_state() {
    state=$test_root/$1
    mkdir -p "$state/bin" "$state/sgw"
    cp "$test_root/cert.pem" "$state/cert.pem"
    cp "$test_root/key.pem" "$state/key.pem"
    cp "$test_root/mock" "$state/bin/mock"
    for name in docker curl git apt-get service systemctl crontab cron dpkg-query ss ip socat getent update-rc.d; do
        cp "$test_root/mock" "$state/bin/$name"
    done
    chmod 0755 "$state/bin/"*
    touch "$state/docker-present" "$state/daemon" "$state/compose" "$state/cron-present"
    touch "$state/calls"
}
run() {
    # The child is not in an if/! function context: Bash errexit remains active.
    bash "$0" --driver "$state" "$1" > "$state/output" 2>&1
}
install() { printf 'gateway.test\n\noperator\n%s\n' "${1:-3}" | run install; }
expect_failed() {
    if "$@"; then fail 'expected installation to fail'; fi
    expect test ! -f "$state/sgw/runtime/install-complete"
    expect grep -q 'Installation incomplete' "$state/output"
    if grep -q 'Installation completed\|password (shown once)' "$state/output"; then fail 'failure announced success/credentials'; fi
}
password_matches_output() {
    local displayed
    displayed=$(sed -n 's/^.*password (shown once): //p' "$state/output")
    [[ ${#displayed} == 48 ]] || fail 'missing delivered random password'
    [[ $(printf '%s' "$displayed" | sha256sum | cut -d ' ' -f 1) == "$(<"$state/password-hash")" ]] \
        || fail 'displayed password cannot authenticate'
    if grep -RFq -- "$displayed" "$state/sgw"; then fail 'plaintext password persisted'; fi
}

MSYS2_ARG_CONV_EXCL=/CN= openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=gateway.test' -addext 'subjectAltName=DNS:gateway.test' \
    -keyout "$test_root/key.pem" -out "$test_root/cert.pem" >/dev/null 2>&1

cat > "$test_root/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
s=$TEST_STATE name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$s/calls"
case $name in
    dpkg-query) printf 'install ok installed\n';;
    docker)
        case $1 in
            version) [[ -f $s/daemon ]];;
            compose)
                [[ -f $s/compose ]] || exit 1
                if [[ $* == *' ps -q '* && -f $s/owned-port ]]; then echo project-id; fi;;
            image) [[ -f $s/images ]];;
            inspect)
                case $3 in
                    *RestartPolicy*) if [[ -f $s/fail && $(<"$s/fail") == restart ]]; then echo no; else echo unless-stopped; fi;;
                    *PortBindings*) [[ ! -f $s/fail || $(<"$s/fail") != binding ]] || echo published;;
                    *State.Running*) echo true;;
                    *NetworkSettings.Ports*) [[ ! -f $s/owned-port ]] || cat "$s/owned-port";;
                esac;;
        esac;;
    apt-get) [[ $1 != install ]] || touch "$s/cron-present" "$s/compose";;
    service)
        case "$1 $2" in
            'cron status') [[ -f $s/cron-running ]];;
            'cron start') [[ ! -f $s/cron-fail ]] && touch "$s/cron-running";;
            'docker start') touch "$s/daemon";;
        esac;;
    systemctl)
        case $1 in
            is-active|is-enabled) [[ -f $s/cron-running ]];;
            enable) [[ ! -f $s/cron-fail ]] && touch "$s/cron-running";;
            start) touch "$s/daemon";;
        esac;;
    crontab) [[ $1 != -l ]] || printf '%s/acme/acme.sh --cron --home %s/acme\n' "$s" "$s";;
    cron|socat|update-rc.d) :;;
    ss)
        if [[ -f $s/conflict && ${*: -1} == *":$(<"$s/conflict") )" ]]; then echo 'LISTEN external-process'; fi
        if [[ -f $s/port80 && ${*: -1} == *':80 )' ]]; then echo 'LISTEN port80'; fi;;
    ip) printf 'inet 192.0.2.10/24\n';;
    getent) printf '192.0.2.10 STREAM\n';;
    curl) echo 'ERROR: real network forbidden in installer tests' >&2; exit 1;;
    git)
        [[ $1 == clone ]] || exit 1
        destination=${*: -1}
        printf '%s\n' "$destination" > "$s/clone-path"
        mkdir -p "$destination"
        cat > "$destination/acme.sh" <<'ACME'
#!/usr/bin/env bash
set -euo pipefail
[[ -f ./acme.sh ]] || { echo 'wrong bootstrap cwd' >&2; exit 1; }
[[ ! -f $TEST_STATE/clone-fail ]] || { echo 'synthetic bootstrap error' >&2; exit 1; }
mkdir -p "$3"
cp ./acme.sh "$3/acme.sh"
chmod 0700 "$3/acme.sh"
printf '%s\n' "$PWD" > "$TEST_STATE/bootstrap-cwd"
ACME
        chmod 0755 "$destination/acme.sh";;
esac
MOCK

if [[ ${1:-} != --ops-only ]]; then
new_state fresh
install
password_matches_output
expect grep -q 'CREDENTIALS_DELIVERED=yes' "$state/sgw/runtime/install-complete"
if [[ $(uname -s) == Linux ]]; then
    expect test "$(stat -c %u "$state/sgw/runtime/install-complete")" == 0
    expect test "$(stat -c %a "$state/sgw/runtime/install-complete")" == 600
fi
pass 'real first_install completes and stores a root-only nonsecret marker'
expect test "$(<"$state/schema")" == 4
pass 'fresh migration reaches schema v4 (real SQLite also tested in PHP/Docker)'
expect grep -q 'Gateway fail-closed: upstream not configured' "$state/output"
pass 'empty upstream is accepted as fail-closed'
expect grep -q 'Existing certificate mode: cron/ACME/port 80 not required' "$state/output"
if grep -q '^cron\|^hook' "$state/calls"; then fail 'existing requires cron/hook'; fi
pass 'existing mode does not require cron/ACME/80/hook'

env_hash=$(sha256sum "$state/sgw/.env") db_hash=$(sha256sum "$state/sgw/runtime/data/subscription-gateway.db")
password_hash=$(<"$state/password-hash")
: > "$state/calls"
run install
expect grep -q 'Existing installation detected' "$state/output"
expect test "$env_hash" == "$(sha256sum "$state/sgw/.env")"
expect test "$password_hash" == "$(<"$state/password-hash")"
if grep -q '^cli reset\|^cli init\|^certificate\|^compose build' "$state/calls"; then fail 'completed reinstall mutated secrets'; fi
pass 'completed rerun preserves password, secret path, keys and active certificate'
expect test "$db_hash" == "$(sha256sum "$state/sgw/runtime/data/subscription-gateway.db")"
pass 'completed rerun preserves tokens/rules/logs/tracking database'
run uninstall
expect test ! -f "$state/running"
run install
expect test -f "$state/running"
expect test "$password_hash" == "$(<"$state/password-hash")"
pass 'uninstall then setup restores services without changing the password'
printf 'gateway.test\nPURGE\n' | run purge
expect test ! -f "$state/sgw/.env"
expect test ! -e "$state/sgw/runtime"
rm -f "$state/admin" "$state/schema" # mock database is removed with runtime
install
password_matches_output
pass 'purge removes completion state and next setup performs fresh installation'

for stage in build migrate init up health hook; do
    new_state "failure-$stage"
    printf '%s\n' "$stage" > "$state/fail"
    mode=3; [[ $stage != hook ]] || mode=1
    expect_failed install "$mode"
    expect test -f "$state/sgw/.env"
    env_hash=$(sha256sum "$state/sgw/.env")
    if [[ -f $state/sgw/runtime/data/subscription-gateway.db ]]; then
        db_hash=$(sha256sum "$state/sgw/runtime/data/subscription-gateway.db")
    else db_hash=''; fi
    old_password=''; [[ ! -f $state/password-hash ]] || old_password=$(<"$state/password-hash")
    pass ".env/$stage failure is incomplete, preserves durable state and hides password"
    rm "$state/fail"
    : > "$state/calls"
    run install
    expect test "$env_hash" == "$(sha256sum "$state/sgw/.env")"
    if [[ -n $db_hash ]]; then expect test "$db_hash" == "$(sha256sum "$state/sgw/runtime/data/subscription-gateway.db")"; fi
    if grep -q '^certificate' "$state/calls"; then fail 'resume reissued valid active certificate'; fi
    password_matches_output
    if [[ -n $old_password ]]; then
        expect grep -q 'Recovery administrator password (shown once)' "$state/output"
        expect test "$old_password" != "$(<"$state/password-hash")"
    fi
    if [[ $stage == hook ]] && grep -q '^compose build\|^compose up\|^cli migrate\|^cli init' "$state/calls"; then
        fail 'hook resume repeated already healthy stages'
    fi
    pass "$stage failure resumes successfully; existing unknown password is recovered only at completion"
done

new_state late-recovery-failure
printf 'up\n' > "$state/fail"
expect_failed install
old_password=$(<"$state/password-hash")
printf 'transformer\n' > "$state/fail"
expect_failed run install
expect test "$old_password" == "$(<"$state/password-hash")"
pass 'unknown password is not reset while final Transformer readiness still fails'
rm "$state/fail"
run install
password_matches_output
pass 'late recovery failure can be retried and delivers the final usable password'
printf 'FORMAT=1\nCREDENTIALS_DELIVERED=pending\n' > "$state/sgw/runtime/install-complete"
old_password=$(<"$state/password-hash")
run install
expect test "$old_password" != "$(<"$state/password-hash")"
password_matches_output
pass 'interrupted credential delivery marker recovers instead of pretending complete'

for port in 443 64444; do
    new_state "conflict-$port"
    printf '%s\n' "$port" > "$state/conflict"
    expect_failed install
    expect test ! -f "$state/sgw/.env"
    if grep -q '^certificate\|^compose build\|^cli\|^docker-ready' "$state/calls"; then fail 'port conflict too late'; fi
    pass "public port $port conflict rejected before certificate/Docker/data side effects"
done
new_state http80
touch "$state/port80"
expect_failed install 1
pass 'HTTP-01 rejects occupied port 80'

new_state diagnostics
install 1
for stage in schema extensions transformer binding restart tracking versions; do
    printf '%s\n' "$stage" > "$state/fail"
    if run check; then fail "--check ignored $stage failure"; fi
    rm "$state/fail"
    run check
    pass "--check detects and recovers $stage failure"
done
rm "$state/renewal"
if run check; then fail '--check ignored missing auto-renewal'; fi
touch "$state/renewal"
run check
pass '--check requires automatic renewal configuration'
fi

# Tests of actual dependency/bootstrap and port functions. Override command
# lookup only for the missing-command branch, without removing basic utilities.
# A wrapper sourced through BASH_ENV is inherited by child shells, not production.
cat > "$test_root/lookup" <<'LOOKUP'
command() {
    if [[ ${1:-} == -v ]]; then
        case ${2:-} in
            crontab|cron) [[ -f $TEST_STATE/cron-present ]] || return 1;;
            docker) [[ -f $TEST_STATE/docker-present ]] || return 1;;
        esac
    fi
    builtin command "$@"
}
LOOKUP
export BASH_ENV=$test_root/lookup
new_state bootstrap
run ops-acme
expect test -x "$state/acme/acme.sh"
expect test "$(<"$state/bootstrap-cwd")" == "$(<"$state/clone-path")"
expect test ! -d "$(<"$state/clone-path")"
pass 'ACME bootstrap uses source cwd and cleans its temporary clone'
printf 'preserve account\n' > "$state/acme/account.conf"
: > "$state/calls"
run ops-acme
expect test "$(<"$state/acme/account.conf")" == 'preserve account'
if grep -q '^git clone' "$state/calls"; then fail 'ACME was reinstalled'; fi
pass 'executable ACME reused without overwriting account/renewal configuration'
new_state bootstrap-failure
touch "$state/clone-fail"
if run ops-acme; then fail 'bootstrap error ignored'; fi
expect grep -q 'synthetic bootstrap error' "$state/output"
expect test ! -d "$(<"$state/clone-path")"
pass 'ACME bootstrap failure shows its cause and cleans clone'
new_state missing-cron
rm "$state/cron-present"
printf 'y\n' | run ops-cron
expect grep -q '^apt-get install -y cron' "$state/calls"
expect test -f "$state/cron-running"
pass 'missing cron uses prompted dependency installation and verifies running service'
new_state cron-refused
rm "$state/cron-present"
if printf 'n\n' | run ops-cron; then fail 'missing cron refusal ignored'; fi
pass 'automatic mode cannot continue after refusing cron dependency'
new_state cron-failed
touch "$state/cron-fail"
if run ops-cron; then fail 'unstartable cron ignored'; fi
pass 'unstartable cron rejects unsafe automatic renewal'
new_state systemd-cron
touch "$state/systemd"
run ops-cron
expect grep -q '^systemctl enable --now cron' "$state/calls"
pass 'systemd cron is enabled and started, then both states are verified'
new_state docker-ready
run ops-docker
if grep -q '^curl\|^apt-get\|^service\|^systemctl' "$state/calls"; then fail 'healthy Docker changed'; fi
pass 'healthy Docker/Compose is untouched'
rm "$state/daemon"
run ops-docker
expect test -f "$state/daemon"
if grep -q '^curl' "$state/calls"; then fail 'daemon stopped triggered get.docker.com'; fi
pass 'Docker daemon stopped is started without reinstallation'
rm "$state/compose"
printf 'y\n' | run ops-docker
expect grep -q '^apt-get install -y docker-compose-plugin' "$state/calls"
pass 'missing Compose prompts for plugin instead of reinstalling Docker'
rm "$state/docker-present"
if printf 'n\n' | run ops-docker; then fail 'Docker refusal ignored'; fi
pass 'absent Docker prompts and honors refusal (no live download)'

new_state actual-port-check
printf '443\n' > "$state/conflict"
if run ops-ports; then fail 'actual port check ignored conflict'; fi
expect grep -q external-process "$state/output"
pass 'actual ss port check safely reports the occupying listener'
printf 'GATEWAY_DOMAIN=gateway.test\n' > "$state/sgw/.env"
printf '443\n' > "$state/owned-port"
run ops-ports
pass 'actual port check accepts this project running container during resume'
printf '8081\n' > "$state/conflict"
rm "$state/owned-port"
run ops-ports
pass 'internal 8080/8081/8443 are not incorrectly checked as host published ports'
new_state actual-http80
touch "$state/port80"
if run ops-http; then fail 'actual HTTP-01 port check ignored conflict'; fi
if grep -q '^git\|^curl' "$state/calls"; then fail 'HTTP conflict checked after ACME'; fi
pass 'actual HTTP-01 checks port 80 before ACME bootstrap'
new_state actual-existing
rm "$state/cron-present"
touch "$state/port80"
printf '%s\n%s\n' "$state/cert.pem" "$state/key.pem" | run ops-existing
if grep -q '^git\|^crontab\|^apt-get\|^ss ' "$state/calls"; then fail 'existing invoked auto certificate dependencies'; fi
pass 'actual existing certificate acquisition validates files without cron/ACME/80'
new_state actual-renewal
mkdir "$state/acme"
touch "$state/cron-running"
cat > "$state/acme/acme.sh" <<'ACME_INFO'
#!/usr/bin/env bash
printf 'Le_RealFullChainPath=%s/sgw/runtime/ssl/staging/fullchain.pem\n' "$TEST_STATE"
printf 'Le_RealKeyPath=%s/sgw/runtime/ssl/staging/privkey.pem\n' "$TEST_STATE"
if [[ ! -f $TEST_STATE/bad-hook ]]; then
    printf 'Le_ReloadCmd=%s/sgw/runtime/ssl/deploy-hook.sh\n' "$TEST_STATE"
fi
printf 'SAVED_CF_Token=synthetic-private-credential\n'
ACME_INFO
chmod 0700 "$state/acme/acme.sh"
run ops-renewal
if grep -q synthetic-private-credential "$state/output"; then fail 'ACME metadata leaked'; fi
touch "$state/bad-hook"
if run ops-renewal; then fail 'missing real renewal reload command ignored'; fi
pass 'actual renewal readiness validates metadata/hook without leaking DNS credentials'
new_state cleanup-lock
mkdir -p "$state/sgw/runtime/ssl/staging"
touch "$state/sgw/.env.tmp" "$state/sgw/runtime/install-state.tmp"
printf 'invalid\n' > "$state/sgw/runtime/ssl/staging/fullchain.pem"
printf 'invalid\n' > "$state/sgw/runtime/ssl/staging/privkey.pem"
run ops-cleanup
expect test -f "$state/sgw/.env.tmp"
expect test -f "$state/sgw/runtime/install-state.tmp"
pass 'failed concurrent install without the lock cannot remove another installer temporary files'
touch "$state/lock-held" "$state/sgw/.env"
run ops-cleanup
expect test ! -f "$state/sgw/.env.tmp"
expect test ! -f "$state/sgw/runtime/install-state.tmp"
expect test ! -f "$state/sgw/runtime/ssl/staging/fullchain.pem"
expect test -f "$state/sgw/.env"
pass 'lock-owning failure cleans temporary/invalid staging but preserves durable environment'

printf 'PASS: %d installer scenarios (no real ACME, package installation or Docker download)\n' "$passed"
