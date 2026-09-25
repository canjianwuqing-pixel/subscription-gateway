#!/usr/bin/env bash
set -euo pipefail
umask 027

control=${CONTROL_DIR:-/control}
generated=${GENERATED_DIR:-/etc/nginx/generated}
staging=${STAGING_DIR:-/tmp/subscription-gateway}
nginx_config=${NGINX_CONFIG:-/etc/nginx/nginx.conf}
nginx_bin=${NGINX_BIN:-nginx}
request=$control/request.json
candidate=$control/candidate.conf
result=$control/result.json
rules=$generated/rules.conf

restricted_file() {
    local path=$1 mode
    [[ -f $path && ! -L $path ]] || return 1
    mode=$(stat -c %a "$path") || return 1
    [[ $mode =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 0027) == 0 ))
}

write_control_file() {
    local target=$1 source=$2 temporary
    temporary="$target.tmp"
    [[ ! -L $temporary ]] || return 1
    cp -- "$source" "$temporary" || return 1
    chmod 0640 "$temporary" || return 1
    chown --reference="$control" "$temporary" || return 1
    sync -f "$temporary" || return 1
    mv -f -- "$temporary" "$target" || return 1
}

write_result() {
    local ok=$1 code=$2 id=$3 version=$4 sha=$5 payload="$staging/result.payload.json"
    jq -n --arg id "$id" --argjson version "$version" --arg sha256 "$sha" \
        --argjson ok "$ok" --arg error_code "$code" \
        '{id:$id,version:$version,sha256:$sha256,ok:$ok,error_code:$error_code}' > "$payload" || return 1
    write_control_file "$result" "$payload"
}

fail_request() {
    write_result false "$1" "$request_id" "$request_version" "$request_sha"
}

restore_previous_rules() {
    cp -- "$rules.bak" "$rules.restore" && chmod 0640 "$rules.restore" \
        && sync -f "$rules.restore" && mv -f -- "$rules.restore" "$rules" \
        && "$nginx_bin" -t >/dev/null 2>&1 \
        && "$nginx_bin" -s reload >/dev/null 2>&1
}

process_request() {
    local request_id request_version request_sha size actual test_config backup_tmp new_rules
    restricted_file "$request" || return 0
    size=$(stat -c %s "$request") || return 0
    (( size > 0 && size <= 512 )) || return 0
    jq -e 'type=="object" and (.id|type)=="string" and (.id|test("^[0-9a-f]{32}$"))
        and (.version|type)=="number" and (.version>=1) and (.version == (.version|floor))
        and (.sha256|type)=="string" and (.sha256|test("^[0-9a-f]{64}$"))' "$request" >/dev/null 2>&1 || return 0
    request_id=$(jq -r '.id' "$request")
    request_version=$(jq -r '.version' "$request")
    request_sha=$(jq -r '.sha256' "$request")
    if [[ -f $result && ! -L $result ]] && jq -e --arg id "$request_id" \
        --argjson version "$request_version" --arg sha "$request_sha" \
        '.id==$id and .version==$version and .sha256==$sha' "$result" >/dev/null 2>&1; then
        return 0
    fi

    restricted_file "$candidate" || { fail_request INVALID_CANDIDATE; return; }
    size=$(stat -c %s "$candidate") || { fail_request INVALID_CANDIDATE; return; }
    (( size > 0 && size <= 1048576 )) || { fail_request INVALID_CANDIDATE; return; }
    actual=$(sha256sum "$candidate") || { fail_request INVALID_CANDIDATE; return; }
    [[ ${actual%% *} == "$request_sha" ]] || { fail_request HASH_MISMATCH; return; }

    cp -- "$candidate" "$staging/rules.candidate.conf" || { fail_request STAGING_FAILED; return; }
    chmod 0600 "$staging/rules.candidate.conf" || { fail_request STAGING_FAILED; return; }
    sync -f "$staging/rules.candidate.conf" || { fail_request STAGING_FAILED; return; }
    actual=$(sha256sum "$staging/rules.candidate.conf") || { fail_request STAGING_FAILED; return; }
    [[ ${actual%% *} == "$request_sha" ]] || { fail_request HASH_MISMATCH; return; }
    test_config=$staging/nginx-test.conf
    local replaced=0 line
    : > "$test_config"
    while IFS= read -r line; do
        if [[ $line == "    include $generated/rules.conf;" ]]; then
            printf '    include %s/rules.candidate.conf;\n' "$staging" >> "$test_config"
            replaced=1
        else
            printf '%s\n' "$line" >> "$test_config"
        fi
    done < "$nginx_config"
    if (( replaced != 1 )); then
        fail_request STAGING_FAILED
        return
    fi
    if ! "$nginx_bin" -t -c "$test_config" >/dev/null 2>&1; then
        fail_request NGINX_TEST_FAILED
        return
    fi

    backup_tmp=$rules.bak.tmp
    new_rules=$rules.new
    if ! cp -- "$rules" "$backup_tmp" || ! chmod 0640 "$backup_tmp" \
        || ! sync -f "$backup_tmp" || ! mv -f -- "$backup_tmp" "$rules.bak"; then
        fail_request BACKUP_FAILED
        return
    fi
    if ! cp -- "$staging/rules.candidate.conf" "$new_rules" || ! chmod 0640 "$new_rules" \
        || ! sync -f "$new_rules" || ! mv -f -- "$new_rules" "$rules"; then
        if restore_previous_rules; then
            fail_request INSTALL_FAILED
        else
            fail_request RESTORE_FAILED
        fi
        return
    fi
    if ! "$nginx_bin" -s reload >/dev/null 2>&1; then
        if ! restore_previous_rules; then
            fail_request RESTORE_FAILED
            return
        fi
        fail_request RELOAD_FAILED
        return
    fi

    printf '%s\n' "$request_version" > "$staging/active_version"
    write_control_file "$control/active_version" "$staging/active_version" || return 1
    write_result true OK "$request_id" "$request_version" "$request_sha"
}

mkdir -p "$staging"
chmod 0700 "$staging"
while true; do
    process_request || exit 1
    sleep 1
done
