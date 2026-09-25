#!/usr/bin/env bash
set -euo pipefail

for command in jq sha256sum sync stat timeout; do
    command -v "$command" >/dev/null || { echo "NOT RUN: missing $command"; exit 77; }
done

test_root=$(mktemp -d)
[[ -d $test_root && $test_root == /tmp/* ]] || { echo 'Unsafe test directory'; exit 1; }
watcher_pid=
cleanup() {
    if [[ -n $watcher_pid ]]; then
        kill "$watcher_pid" 2>/dev/null || true
        wait "$watcher_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

mkdir -p "$test_root/control" "$test_root/generated" "$test_root/staging" "$test_root/fake"
chmod 0750 "$test_root/control" "$test_root/generated"
chmod 0700 "$test_root/staging"
printf 'OLD_RULES\n' > "$test_root/generated/rules.conf"
chmod 0640 "$test_root/generated/rules.conf"
printf 'http {\n    include %s/generated/rules.conf;\n}\n' "$test_root" > "$test_root/nginx.conf"

cat > "$test_root/fake/nginx" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == -t ]]; then
    [[ ! -f $FAKE_NGINX_STATE/fail_test ]]
elif [[ ${1:-} == -s && ${2:-} == reload ]]; then
    if [[ -f $FAKE_NGINX_STATE/fail_reload_once ]]; then
        rm -- "$FAKE_NGINX_STATE/fail_reload_once"
        exit 1
    fi
else
    exit 2
fi
FAKE
chmod 0755 "$test_root/fake/nginx"

# Git Bash cannot represent POSIX 0640 ownership/modes on NTFS. These two
# test-only adapters keep the watcher protocol testable; Linux uses real tools.
if [[ $(uname -s) == MINGW* ]]; then
    cat > "$test_root/fake/stat" <<'FAKE_STAT'
#!/usr/bin/env bash
if [[ ${1:-} == -c && ${2:-} == %a ]]; then
    printf '640\n'
else
    /usr/bin/stat "$@"
fi
FAKE_STAT
    cat > "$test_root/fake/chown" <<'FAKE_CHOWN'
#!/usr/bin/env bash
exit 0
FAKE_CHOWN
    chmod 0755 "$test_root/fake/stat" "$test_root/fake/chown"
    export PATH="$test_root/fake:$PATH"
fi

export CONTROL_DIR="$test_root/control"
export GENERATED_DIR="$test_root/generated"
export STAGING_DIR="$test_root/staging"
export NGINX_CONFIG="$test_root/nginx.conf"
export NGINX_BIN="$test_root/fake/nginx"
export FAKE_NGINX_STATE="$test_root/fake"

bash "$(dirname "$0")/../sgw/gateway/watcher.sh" > "$test_root/watcher.stderr" 2>&1 &
watcher_pid=$!

submit() {
    local id=$1 version=$2 text=$3 wrong_hash=${4:-no} sha
    printf '%s\n' "$text" > "$CONTROL_DIR/candidate.conf.tmp"
    chmod 0640 "$CONTROL_DIR/candidate.conf.tmp"
    mv -f "$CONTROL_DIR/candidate.conf.tmp" "$CONTROL_DIR/candidate.conf"
    sha=$(sha256sum "$CONTROL_DIR/candidate.conf")
    sha=${sha%% *}
    [[ $wrong_hash == no ]] || sha=$(printf '0%.0s' {1..64})
    jq -n --arg id "$id" --argjson version "$version" --arg sha256 "$sha" \
        '{id:$id,version:$version,sha256:$sha256}' > "$CONTROL_DIR/request.json.tmp"
    chmod 0640 "$CONTROL_DIR/request.json.tmp"
    mv -f "$CONTROL_DIR/request.json.tmp" "$CONTROL_DIR/request.json"
    local attempt
    for attempt in {1..80}; do
        if [[ -f $CONTROL_DIR/result.json ]] \
            && jq -e --arg id "$id" '.id==$id' "$CONTROL_DIR/result.json" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "Watcher result timeout for $id" >&2
    tail -20 "$test_root/watcher.stderr" >&2
    exit 1
}

touch "$FAKE_NGINX_STATE/fail_test"
submit 11111111111111111111111111111111 1 NEW_RULES
jq -e '.ok==false and .error_code=="NGINX_TEST_FAILED"' "$CONTROL_DIR/result.json" >/dev/null
[[ $(cat "$GENERATED_DIR/rules.conf") == OLD_RULES ]]
rm -- "$FAKE_NGINX_STATE/fail_test"

touch "$FAKE_NGINX_STATE/fail_reload_once"
submit 22222222222222222222222222222222 2 NEXT_RULES
jq -e '.ok==false and .error_code=="RELOAD_FAILED"' "$CONTROL_DIR/result.json" >/dev/null
[[ $(cat "$GENERATED_DIR/rules.conf") == OLD_RULES ]]
[[ $(cat "$GENERATED_DIR/rules.conf.bak") == OLD_RULES ]]

submit 33333333333333333333333333333333 3 GOOD_RULES
jq -e '.ok==true and .version==3' "$CONTROL_DIR/result.json" >/dev/null
[[ $(cat "$GENERATED_DIR/rules.conf") == GOOD_RULES ]]
[[ $(cat "$CONTROL_DIR/active_version") == 3 ]]

submit 44444444444444444444444444444444 4 TEST_SECRET_TOKEN yes
jq -e '.ok==false and .error_code=="HASH_MISMATCH"' "$CONTROL_DIR/result.json" >/dev/null
[[ $(cat "$GENERATED_DIR/rules.conf") == GOOD_RULES ]]
! grep -Fq TEST_SECRET_TOKEN "$CONTROL_DIR/result.json"

echo 'PASS: 5 fake watcher scenarios (not an Nginx integration test)'
