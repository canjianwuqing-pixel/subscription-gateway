#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $(uname -s) == Linux ]] || { echo 'NOT RUN: update permission tests require Linux modes'; exit 77; }
(( EUID == 0 )) || { echo 'Run update permission tests with sudo'; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd -P)
test_root=$(mktemp -d)
[[ $test_root == /tmp/* && -d $test_root && ! -L $test_root ]] || exit 1
trap 'rm -rf -- "$test_root"' EXIT
passed=0
fail() { printf 'Update permission test failed: %s\n' "$*" >&2; exit 1; }
expect() { "$@" || fail "$*"; passed=$((passed + 1)); }
export REAL_GIT_BIN
REAL_GIT_BIN=$(command -v git)
mkdir -p "$test_root/bin" "$test_root/upstream/sgw/admin/src/nested"
export UPDATE_TEST_STATE=$test_root/state UPDATE_TEST_REPO=$test_root/checkout
mkdir "$UPDATE_TEST_STATE"

# Fake only containers; Git pull, checkout, umask, chmod and update.sh are real.
cat > "$test_root/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
    if [[ $argument == pull ]]; then
        printf 'pull\n' >> "$UPDATE_TEST_STATE/calls"
        umask > "$UPDATE_TEST_STATE/pull-umask"
        [[ ! -f $UPDATE_TEST_STATE/fail-pull ]] || exit 42
    fi
done
exec "$REAL_GIT_BIN" "$@"
SH
cat > "$test_root/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
state=$UPDATE_TEST_STATE
repo=$UPDATE_TEST_REPO
if [[ $1 == inspect ]]; then
    if [[ $* == *Health.Status* ]]; then
        printf 'health\n' >> "$state/calls"
        printf 'healthy\n'
    else
        printf 'old-image-%s\n' "${!#}"
    fi
    exit 0
fi
if [[ $1 == tag ]]; then printf 'tag %s %s\n' "$2" "$3" >> "$state/calls"; exit 0; fi
[[ $1 == compose ]] || exit 1
shift
while [[ ${1:-} == --* || ${1:-} == -f ]]; do shift 2; done
command=$1
shift
if [[ $command == run ]]; then
    while [[ ${1:-} != /app/src/cli.php && $# -gt 0 ]]; do shift; done
    [[ $# -gt 0 ]] || exit 1
    shift
    command=$1
    shift
fi
printf '%s\n' "$command" >> "$state/calls"
case $command in
    ps) printf 'old-container-%s\n' "${!#}";;
    backup) cp "$repo/sgw/runtime/data/subscription-gateway.db" "$repo/sgw/runtime/backups/database/${1##*/}";;
    build)
        umask > "$state/build-umask"
        printf 'sensitive-after-pull\n' > "$state/sensitive-after-pull"
        [[ ! -f $state/fail-build ]] || exit 43
        ;;
    down) printf 'sensitive-during-rollback\n' > "$state/sensitive-during-rollback";;
    migrate) printf 'new-database\n' > "$repo/sgw/runtime/data/subscription-gateway.db";;
    versions) printf '1 1\n';;
    config|up|stop|compile|exec) :;;
    *) exit 1;;
esac
SH
chmod 0755 "$test_root/bin/git" "$test_root/bin/docker"

upstream=$test_root/upstream
cp "$root/update.sh" "$upstream/update.sh"
cp "$root/sgw/ops.sh" "$upstream/sgw/ops.sh"
printf '<?php // initial\n' > "$upstream/sgw/admin/src/tracking.php"
printf '<?php // unchanged, later restricted\n' > "$upstream/sgw/admin/src/unchanged.php"
printf '#!/bin/sh\nexit 0\n' > "$upstream/sgw/admin/entrypoint.sh"
chmod 0755 "$upstream/sgw/admin/entrypoint.sh"
printf 'sgw/runtime/\nsgw/.env\n' > "$upstream/.gitignore"
git -C "$upstream" init -q -b main
git -C "$upstream" config user.email permissions@example.invalid
git -C "$upstream" config user.name 'Permissions Test'
git -C "$upstream" add .
git -C "$upstream" commit -qm initial
(umask 022; git clone -q "$upstream" "$UPDATE_TEST_REPO")
git -C "$UPDATE_TEST_REPO" config user.email permissions@example.invalid
git -C "$UPDATE_TEST_REPO" config user.name 'Permissions Test'

runtime=$UPDATE_TEST_REPO/sgw/runtime
mkdir -p "$runtime"/{data,backups/database,generated,control,domain-certs/2/releases/00000000000000000000000000000001,ssl/releases/old}
printf '# old domains\n' > "$runtime/control/domains.conf"
chmod 0640 "$runtime/control/domains.conf"
printf 'alias-private-key\n' > "$runtime/domain-certs/2/releases/00000000000000000000000000000001/privkey.pem"
chmod 0640 "$runtime/domain-certs/2/releases/00000000000000000000000000000001/privkey.pem"
ln -s releases/00000000000000000000000000000001 "$runtime/domain-certs/2/active"
chmod 0750 "$runtime" "$runtime/data" "$runtime/backups" "$runtime/backups/database" "$runtime/generated" "$runtime/ssl"
printf 'test-env\n' > "$UPDATE_TEST_REPO/sgw/.env"
printf 'old-database\n' > "$runtime/data/subscription-gateway.db"
printf 'old-rules\n' > "$runtime/generated/rules.conf"
printf 'test-private-key\n' > "$runtime/ssl/releases/old/privkey.pem"
chmod 0600 "$UPDATE_TEST_REPO/sgw/.env" "$runtime/ssl/releases/old/privkey.pem"
chmod 0640 "$runtime/data/subscription-gateway.db" "$runtime/generated/rules.conf"
ln -s releases/old "$runtime/ssl/active"

printf '<?php // replaced upstream\n' > "$upstream/sgw/admin/src/tracking.php"
printf '<?php // added upstream\n' > "$upstream/sgw/admin/src/api.php"
printf '<?php // added nested upstream\n' > "$upstream/sgw/admin/src/nested/new.php"
git -C "$upstream" add .
git -C "$upstream" commit -qm 'new and replaced PHP'
new_commit=$(git -C "$upstream" rev-parse HEAD)
chmod 0600 "$UPDATE_TEST_REPO/sgw/admin/src/unchanged.php"
export PATH="$test_root/bin:$PATH"
expect bash "$UPDATE_TEST_REPO/update.sh" --pull
expect test "$(git -C "$UPDATE_TEST_REPO" rev-parse HEAD)" == "$new_commit"
expect test "$(<"$UPDATE_TEST_STATE/pull-umask")" == 0022
expect test "$(<"$UPDATE_TEST_STATE/build-umask")" == 0077
expect test "$(umask)" == 0077
expect test "$(stat -c %a "$UPDATE_TEST_STATE/sensitive-after-pull")" == 600
for source in tracking.php api.php nested/new.php unchanged.php; do
    expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/src/$source")" == 644
done
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/src/nested")" == 755
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/entrypoint.sh")" == 755
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/.env")" == 600
expect test "$(stat -c %a "$runtime/ssl/releases/old/privkey.pem")" == 600
expect test "$(stat -c %a "$runtime/data/subscription-gateway.db")" == 640
expect test "$(stat -c %a "$runtime/data")" == 750
expect test "$(readlink "$runtime/ssl/active")" == releases/old
expect test "$(<"$runtime/generated/rules.conf")" == old-rules
mapfile -t snapshots < <(find "$runtime/backups" -maxdepth 1 -type d -name 'update-*')
expect test "${#snapshots[@]}" == 1
expect test "$(stat -c %a "${snapshots[0]}/database.db")" == 600
expect test "$(<"${snapshots[0]}/database.db")" == old-database
expect awk '$0=="backup"{b=NR} $0=="pull"{p=NR} $0=="build"{d=NR} $0=="migrate"{m=NR} $0=="compile"{c=NR} END{exit !(b<p && p<d && d<m && m<c)}' "$UPDATE_TEST_STATE/calls"

# No --pull also repairs tracked 0600 files/directories without touching unknown PHP.
printf '<?php // untracked private fixture\n' > "$UPDATE_TEST_REPO/sgw/admin/src/private.php"
chmod 0600 "$UPDATE_TEST_REPO/sgw/admin/src/tracking.php" "$UPDATE_TEST_REPO/sgw/admin/src/private.php"
chmod 0700 "$UPDATE_TEST_REPO/sgw/admin/src/nested"
expect bash "$UPDATE_TEST_REPO/update.sh"
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/src/tracking.php")" == 644
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/src/nested")" == 755
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/admin/src/private.php")" == 600
rm -- "$UPDATE_TEST_REPO/sgw/admin/src/private.php"

# Pull succeeded, then build failed: actual updater restores commit/images/data.
printf '<?php // next replacement\n' > "$upstream/sgw/admin/src/tracking.php"
git -C "$upstream" add .
git -C "$upstream" commit -qm 'next update for rollback'
printf 'rollback-database\n' > "$runtime/data/subscription-gateway.db"
touch "$UPDATE_TEST_STATE/fail-build"
before_failed_migrations=$(grep -c '^migrate$' "$UPDATE_TEST_STATE/calls")
if bash "$UPDATE_TEST_REPO/update.sh" --pull; then fail 'build failure did not stop update'; fi
passed=$((passed + 1))
expect test "$(git -C "$UPDATE_TEST_REPO" rev-parse HEAD)" == "$new_commit"
expect test "$(<"$runtime/data/subscription-gateway.db")" == rollback-database
expect test "$(stat -c %a "$runtime/data/subscription-gateway.db")" == 640
expect test "$(<"$UPDATE_TEST_REPO/sgw/.env")" == test-env
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/.env")" == 600
expect test "$(readlink "$runtime/ssl/active")" == releases/old
expect test "$(<"$runtime/generated/rules.conf")" == old-rules
expect grep -q '^tag old-image-old-container-admin subscription-gateway/admin:current$' "$UPDATE_TEST_STATE/calls"
expect grep -q '^tag old-image-old-container-gateway subscription-gateway/gateway:current$' "$UPDATE_TEST_STATE/calls"
expect test "$(stat -c %a "$UPDATE_TEST_STATE/sensitive-during-rollback")" == 600
expect test "$(grep -c '^migrate$' "$UPDATE_TEST_STATE/calls")" == "$before_failed_migrations"
rm -- "$UPDATE_TEST_STATE/fail-build"

# Failed pull cannot leak its 022 into rollback or subsequent sensitive creation.
touch "$UPDATE_TEST_STATE/fail-pull"
if bash "$UPDATE_TEST_REPO/update.sh" --pull; then fail 'pull failure did not stop update'; fi
passed=$((passed + 1))
expect test "$(git -C "$UPDATE_TEST_REPO" rev-parse HEAD)" == "$new_commit"
expect test "$(<"$UPDATE_TEST_STATE/pull-umask")" == 0022
expect test "$(stat -c %a "$UPDATE_TEST_STATE/sensitive-during-rollback")" == 600
expect test "$(umask)" == 0077
rm -- "$UPDATE_TEST_STATE/fail-pull"

# Guard against escaping src through a symlink; sensitive targets remain 0600.
. "$root/sgw/ops.sh"
rm -- "$UPDATE_TEST_REPO/sgw/admin/src/tracking.php"
ln -s "$UPDATE_TEST_REPO/sgw/.env" "$UPDATE_TEST_REPO/sgw/admin/src/tracking.php"
if (prepare_admin_source_permissions "$UPDATE_TEST_REPO"); then fail 'source symlink was accepted'; fi
passed=$((passed + 1))
expect test "$(stat -c %a "$UPDATE_TEST_REPO/sgw/.env")" == 600
rm -- "$UPDATE_TEST_REPO/sgw/admin/src/tracking.php"
git -C "$UPDATE_TEST_REPO" restore sgw/admin/src/tracking.php
mv -- "$UPDATE_TEST_REPO/sgw/admin/src/nested" "$test_root/nested-original"
mkdir "$test_root/private-directory"
printf 'private-target\n' > "$test_root/private-directory/new.php"
ln -s "$test_root/private-directory" "$UPDATE_TEST_REPO/sgw/admin/src/nested"
if (prepare_admin_source_permissions "$UPDATE_TEST_REPO"); then fail 'source parent symlink was accepted'; fi
passed=$((passed + 1))
expect test "$(stat -c %a "$test_root/private-directory/new.php")" == 600
expect test "$(stat -c %a "$test_root/private-directory")" == 700

# Non-Git archives retain their existing semantics: explicit validation, no broad chmod.
archive=$test_root/archive
mkdir -p "$archive/sgw/admin/src"
printf '<?php // archive fixture\n' > "$archive/sgw/admin/src/main.php"
if (prepare_admin_source_permissions "$archive"); then fail 'unreadable archive source was accepted'; fi
passed=$((passed + 1))
expect test "$(stat -c %a "$archive/sgw/admin/src/main.php")" == 600
chmod 0755 "$archive/sgw/admin/src"
chmod 0644 "$archive/sgw/admin/src/main.php"
expect prepare_admin_source_permissions "$archive"
expect grep -Fq '# old domains' "$runtime/control/domains.conf"
expect test "$(readlink "$runtime/domain-certs/2/active")" == releases/00000000000000000000000000000001
expect test "$(stat -c %a "$runtime/domain-certs/2/releases/00000000000000000000000000000001/privkey.pem")" == 640
expect test ! -f "$runtime/control/certificate-maintenance"
mapfile -t domain_snapshots < <(find "$runtime/backups" -name domain-cert-targets -type f)
expect test "${#domain_snapshots[@]}" -gt 0
expect grep -Fq '2 releases/00000000000000000000000000000001' "${domain_snapshots[0]}"
printf 'PASS: %s update permission checks (real Git pull under 077, isolated 022, scoped repair and rollback)\n' "$passed"
