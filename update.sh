#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT_DIR=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=sgw/ops.sh
. "$ROOT_DIR/sgw/ops.sh"

require_root
[[ ${1:-} == '' || ${1:-} == --pull ]] || die 'Usage: ./update.sh [--pull]'
pull_mode=${1:-}
[[ -f $ENV_FILE && -d $RUNTIME/data ]] || die 'Installation not found'
[[ ! -L $ENV_FILE ]] || die '.env must not be a symbolic link'
[[ ! -L $RUNTIME && ! -L $RUNTIME/backups && ! -L $RUNTIME/data ]] || die 'Unsafe runtime path'
command -v flock >/dev/null || die 'flock is required'
exec 9> "$RUNTIME/update.lock"
flock -n 9 || die 'Another update is already running'
old_commit=$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)
if [[ ${1:-} == --pull ]]; then
    [[ -n $old_commit ]] || die 'Git repository required for --pull'
    [[ -n $(git -C "$ROOT_DIR" remote) ]] || die 'No Git remote configured'
    [[ -z $(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal) ]] \
        || die 'Working tree must be clean before --pull'
fi
stamp=$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)
backup=$RUNTIME/backups/update-$stamp
mkdir -m 0700 "$backup"
cp -p -- "$ENV_FILE" "$backup/.env"
[[ ! -f $RUNTIME/generated/rules.conf ]] || cp -p -- "$RUNTIME/generated/rules.conf" "$backup/rules.conf"
[[ ! -L $RUNTIME/ssl/active ]] || readlink "$RUNTIME/ssl/active" > "$backup/cert-target"
old_gateway=$(compose ps -q gateway)
old_admin=$(compose ps -q admin)
[[ -n $old_gateway && -n $old_admin ]] || die 'Both services must be running before update'
gateway_image=$(docker inspect --format '{{.Image}}' "$old_gateway")
admin_image=$(docker inspect --format '{{.Image}}' "$old_admin")
[[ ! -L $RUNTIME/control && ! -L $RUNTIME/domain-certs ]] || die 'Unsafe domain runtime path'
mkdir -p "$RUNTIME/control"
[[ ! -L $RUNTIME/control/certificate-maintenance ]] || die 'Unsafe maintenance marker'
printf 'updating\n' > "$RUNTIME/control/certificate-maintenance"
chmod 0640 "$RUNTIME/control/certificate-maintenance"
trap 'backup_status=$?; if (( backup_status != 0 )); then rm -f -- "$RUNTIME/control/certificate-maintenance"; compose up -d admin >/dev/null 2>&1 || true; fi' EXIT
compose stop admin >/dev/null
[[ ! -L $RUNTIME/control && ! -L $RUNTIME/domain-certs ]] || die 'Unsafe domain runtime path'
mkdir -p "$RUNTIME/control" "$RUNTIME/domain-certs"
chown 82:82 "$RUNTIME/control" "$RUNTIME/domain-certs"
chmod 0750 "$RUNTIME/control" "$RUNTIME/domain-certs"
for file in domains.conf domains.conf.bak; do
    [[ ! -L $RUNTIME/control/$file ]] || die 'Unsafe domain configuration'
    [[ ! -f $RUNTIME/control/$file ]] || cp -p -- "$RUNTIME/control/$file" "$backup/$file"
done
: > "$backup/domain-cert-targets"
for domain_directory in "$RUNTIME/domain-certs/"[0-9]*; do
    [[ -d $domain_directory && ! -L $domain_directory ]] || continue
    domain_id=${domain_directory##*/}
    [[ $domain_id =~ ^[1-9][0-9]*$ ]] || die 'Invalid certificate domain ID'
    if [[ -L $domain_directory/active ]]; then
        target=$(readlink "$domain_directory/active")
        [[ $target =~ ^releases/[0-9a-f]{32}$ && ! -L $domain_directory/releases && ! -L $domain_directory/$target ]] || die 'Unsafe alias certificate target'
        printf '%s %s\n' "$domain_id" "$target" >> "$backup/domain-cert-targets"
    fi
done
printf '%s\n' "$gateway_image" > "$backup/gateway-image-id"
printf '%s\n' "$admin_image" > "$backup/admin-image-id"
admin_cli backup "/backups/update-$stamp.db" >/dev/null || die 'SQLite safe backup failed'
mv -f -- "$RUNTIME/backups/database/update-$stamp.db" "$backup/database.db"
chown root:root "$backup/database.db"
chmod 0600 "$backup/database.db"
trap - EXIT

rollback() {
    set +e
    warning 'Update failed; restoring previous application state'
    if ! compose down --remove-orphans >/dev/null 2>&1; then
        warning 'Containers could not be stopped; database was not overwritten'
        return 1
    fi
    cp -p -- "$backup/.env" "$ENV_FILE"
    cp -p -- "$backup/database.db" "$RUNTIME/data/subscription-gateway.db"
    rm -f -- "$RUNTIME/data/subscription-gateway.db-wal" "$RUNTIME/data/subscription-gateway.db-shm"
    chown 82:82 "$RUNTIME/data/subscription-gateway.db"
    chmod 0640 "$RUNTIME/data/subscription-gateway.db"
    if [[ -f $backup/rules.conf ]]; then cp -p -- "$backup/rules.conf" "$RUNTIME/generated/rules.conf"; fi
    for file in domains.conf domains.conf.bak; do
        if [[ -f $backup/$file ]]; then cp -p -- "$backup/$file" "$RUNTIME/control/$file";
        else rm -f -- "$RUNTIME/control/$file"; fi
    done
    rm -f -- "$RUNTIME/control/domain-request.json" "$RUNTIME/control/domain-result.json" "$RUNTIME/control/domain-candidate.conf"
    while read -r domain_id target; do
        [[ $domain_id =~ ^[1-9][0-9]*$ && $target =~ ^releases/[0-9a-f]{32}$ ]] || continue
        domain_directory=$RUNTIME/domain-certs/$domain_id
        [[ -d $domain_directory/$target && ! -L $domain_directory && ! -L $domain_directory/releases && ! -L $domain_directory/$target && ! -L $domain_directory/active.next ]] || continue
        ln -s "$target" "$domain_directory/active.next"
        mv -Tf -- "$domain_directory/active.next" "$domain_directory/active"
    done < "$backup/domain-cert-targets"
    if [[ -f $backup/cert-target ]]; then
        ln -s "$(<"$backup/cert-target")" "$RUNTIME/ssl/active.next"
        mv -Tf -- "$RUNTIME/ssl/active.next" "$RUNTIME/ssl/active"
    fi
    docker tag "$gateway_image" subscription-gateway/gateway:current || true
    docker tag "$admin_image" subscription-gateway/admin:current || true
    if [[ $pull_mode == --pull && -n $old_commit ]]; then
        git -C "$ROOT_DIR" switch --detach "$old_commit" >/dev/null 2>&1 || true
    fi
    rm -f -- "$RUNTIME/control/certificate-maintenance"
    compose up -d >/dev/null 2>&1 || true
    warning 'Rollback attempted; run ./setup.sh --check before accepting traffic'
}
trap 'update_status=$?; trap - ERR; rollback; exit "$update_status"' ERR

if [[ ${1:-} == --pull ]]; then
    (
        # Handle failures once in the private-umask parent, not inside this shell.
        trap - ERR
        umask 022
        git -C "$ROOT_DIR" pull --ff-only
    )
fi
(trap - ERR; prepare_admin_source_permissions "$ROOT_DIR")
compose config >/dev/null
compose build
admin_cli migrate >/dev/null
compose up -d --force-recreate admin gateway
wait_health
admin_cli compile >/dev/null
versions=$(admin_cli versions)
read -r configured active <<< "$versions"
[[ $configured == "$active" ]] || {
    [[ $(admin_cli upstream-state) == EMPTY ]]
}
compose exec -T gateway nginx -t >/dev/null
compose exec -T admin nginx -t >/dev/null
trap - ERR
rm -f -- "$RUNTIME/control/certificate-maintenance"
info "Update complete; backup kept at $backup"

# Keep the latest five update snapshots; never prune unrelated backup files.
mapfile -t old_backups < <(find "$RUNTIME/backups" -mindepth 1 -maxdepth 1 -type d -name 'update-*' | sort)
if (( ${#old_backups[@]} > 5 )); then
    for ((index=0; index<${#old_backups[@]}-5; index++)); do
        target=${old_backups[index]}
        [[ $target == "$RUNTIME/backups/update-"* && ! -L $target ]] || continue
        rm -rf -- "$target"
    done
fi
