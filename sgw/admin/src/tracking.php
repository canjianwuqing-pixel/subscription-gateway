<?php

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

const TRACKING_MODES = ['off', 'preflight', 'enforced'];
const TRACKING_GROUP_STATUSES = ['DRAFT', 'ACTIVE', 'ARCHIVED'];
const TRACKING_EVENT_OUTCOMES = [
    'SUCCESS',
    'PARTIAL_SUCCESS',
    'NO_USABLE_NODES',
    'UNKNOWN_FORMAT',
    'MAPPING_INCOMPLETE',
    'PARSE_FAILED',
    'RESPONSE_TOO_LARGE',
    'VALIDATION_FAILED',
    'UPSTREAM_ERROR',
    'INTERNAL_ERROR',
];

function tracking_mode(PDO $pdo): string
{
    $mode = (string) setting_get($pdo, 'tracking_mode', 'off');
    if (!in_array($mode, TRACKING_MODES, true)) {
        throw new RuntimeException('Invalid tracking mode in SQLite');
    }
    return $mode;
}

function normalize_tracking_host(string $value): string
{
    if (preg_match('/[\x00-\x1F\x7F]/', $value)) throw new InvalidArgumentException('Entry host is invalid');
    $value = trim($value);
    if ($value === '' || strlen($value) > 253 || preg_match('/[\x00-\x20\x7F]/', $value)) {
        throw new InvalidArgumentException('Entry host is invalid');
    }
    if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
        $packed = inet_pton($value);
        $normalized = $packed === false ? false : inet_ntop($packed);
        if (!is_string($normalized)) {
            throw new InvalidArgumentException('Entry IP address is invalid');
        }
        return strtolower($normalized);
    }
    $value = strtolower(rtrim($value, '.'));
    if ($value === '' || str_contains($value, ':') || str_contains($value, '/')
        || str_contains($value, '?') || str_contains($value, '#')
        || str_contains($value, '@') || str_contains($value, '\\')
        || filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
    ) {
        throw new InvalidArgumentException('Entry host must be a DNS hostname or IP address');
    }
    return $value;
}

/** @return array<string, mixed> */
function tracking_group(PDO $pdo, int $id): array
{
    $statement = $pdo->prepare(
        'SELECT id, parent_id, child_no, path, status, split_at, created_at, updated_at '
        . 'FROM tracking_groups WHERE id = :id'
    );
    $statement->execute([':id' => $id]);
    $row = $statement->fetch();
    if (!is_array($row)) {
        throw new DomainException('Tracking group not found');
    }
    $row['id'] = (int) $row['id'];
    $row['parent_id'] = $row['parent_id'] === null ? null : (int) $row['parent_id'];
    $row['child_no'] = (int) $row['child_no'];
    $row['split_at'] = $row['split_at'] === null ? null : (int) $row['split_at'];
    $row['created_at'] = (int) $row['created_at'];
    $row['updated_at'] = (int) $row['updated_at'];
    return $row;
}

/** @return list<array<string, mixed>> */
function tracking_children(PDO $pdo, int $parentId, string $status = 'ACTIVE'): array
{
    if (!in_array($status, TRACKING_GROUP_STATUSES, true)) {
        throw new InvalidArgumentException('Invalid tracking group status');
    }
    $statement = $pdo->prepare(
        'SELECT id, parent_id, child_no, path, status, split_at, created_at, updated_at '
        . 'FROM tracking_groups WHERE parent_id = :parent_id AND status = :status ORDER BY child_no'
    );
    $statement->execute([':parent_id' => $parentId, ':status' => $status]);
    return $statement->fetchAll();
}

function tracking_group_is_active_leaf(PDO $pdo, int $id): bool
{
    $statement = $pdo->prepare(<<<'SQL'
SELECT COUNT(*)
FROM tracking_groups g
WHERE g.id = :id AND g.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'ACTIVE'
  )
SQL);
    $statement->execute([':id' => $id]);
    return (int) $statement->fetchColumn() === 1;
}

function tracking_descend_to_leaf(PDO $pdo, string $tokenHash, int $startGroupId): int
{
    $current = $startGroupId;
    $visited = [];
    while (true) {
        if (isset($visited[$current])) {
            throw new RuntimeException('Tracking group tree contains a cycle');
        }
        $visited[$current] = true;
        $group = tracking_group($pdo, $current);
        if ($group['status'] !== 'ACTIVE') {
            throw new RuntimeException('Tracking assignment references an inactive group');
        }
        $children = tracking_children($pdo, $current);
        if ($children === []) {
            return $current;
        }
        $childCount = count($children);
        if ($childCount < 2 || $childCount > 20
            || array_map(static fn (array $row): int => (int) $row['child_no'], $children) !== range(1, $childCount)) {
            throw new RuntimeException('Active tracking split is incomplete');
        }
        $childNo = tracking_child_number($tokenHash, $current, $childCount);
        $current = (int) $children[$childNo - 1]['id'];
    }
}

function tracking_assignment_for_hash(PDO $pdo, string $tokenHash): int
{
    if (!preg_match('/^[0-9a-f]{64}$/D', $tokenHash)) {
        throw new InvalidArgumentException('Invalid Token hash');
    }
    return write_transaction($pdo, static function () use ($pdo, $tokenHash): int {
        $query = $pdo->prepare('SELECT group_id FROM tracking_assignments WHERE token_hash = :token_hash');
        $query->execute([':token_hash' => $tokenHash]);
        $stored = $query->fetchColumn();
        if ($stored === false) {
            $root = (int) $pdo->query("SELECT id FROM tracking_groups WHERE parent_id IS NULL AND status = 'ACTIVE'")->fetchColumn();
            if ($root < 1) {
                throw new RuntimeException('Tracking root group is unavailable');
            }
            $leaf = tracking_descend_to_leaf($pdo, $tokenHash, $root);
            $now = time();
            $insert = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_assignments
    (token_hash, group_id, algorithm_version, assigned_at, updated_at)
VALUES (:token_hash, :group_id, :algorithm_version, :assigned_at, :updated_at)
SQL);
            $insert->execute([':token_hash' => $tokenHash, ':group_id' => $leaf,
                ':algorithm_version' => TRACKING_ALGORITHM_VERSION, ':assigned_at' => $now, ':updated_at' => $now]);
            return $leaf;
        }
        try {
            $leaf = tracking_descend_to_leaf($pdo, $tokenHash, (int) $stored);
        } catch (DomainException) {
            // Missing groups can be repaired; corrupt ACTIVE topology must fail,
            // never silently choose another branch and reshuffle the assignment.
            $root = (int) $pdo->query("SELECT id FROM tracking_groups WHERE parent_id IS NULL AND status = 'ACTIVE'")->fetchColumn();
            $leaf = tracking_descend_to_leaf($pdo, $tokenHash, $root);
        }
        if ($leaf !== (int) $stored) {
            $update = $pdo->prepare(
                'UPDATE tracking_assignments SET group_id = :group_id, algorithm_version = :version, '
                . 'updated_at = :updated_at WHERE token_hash = :token_hash'
            );
            $update->execute([':group_id' => $leaf, ':version' => TRACKING_ALGORITHM_VERSION,
                ':updated_at' => time(), ':token_hash' => $tokenHash]);
        }
        return $leaf;
    });
}

function tracking_backfill_token_assignments(PDO $pdo): void
{
    // Repair pre-existing v3 Tokens that were ingested while tracking was off.
    // Only hashes are read; no full-library Token decryption or reassignment.
    $hashes = $pdo->query('SELECT t.token_hash FROM tokens t LEFT JOIN tracking_assignments a '
        . 'ON a.token_hash=t.token_hash WHERE a.token_hash IS NULL')->fetchAll(PDO::FETCH_COLUMN);
    if ($hashes === []) return;
    write_transaction($pdo, static function () use ($pdo, $hashes): void {
        foreach ($hashes as $hash) tracking_assignment_for_hash($pdo, (string) $hash);
    });
}

/** @return list<array{id:int,source_host:string,target_host:?string}> */
function tracking_group_mappings(PDO $pdo, int $groupId): array
{
    $statement = $pdo->prepare(
        'SELECT id, source_host, target_host FROM tracking_entry_mappings '
        . 'WHERE group_id = :group_id ORDER BY source_host'
    );
    $statement->execute([':group_id' => $groupId]);
    $rows = [];
    foreach ($statement as $row) {
        $rows[] = ['id' => (int) $row['id'], 'source_host' => (string) $row['source_host'],
            'target_host' => $row['target_host'] === null ? null : (string) $row['target_host']];
    }
    return $rows;
}

/** Ensure mapping slots without overwriting targets, including retained parents. */
function tracking_ensure_source_mappings(PDO $pdo, array $hosts): void
{
    $insert = $pdo->prepare('INSERT INTO tracking_entry_mappings '
        . '(group_id,source_host,target_host,created_at,updated_at) VALUES (:group,:source,NULL,:now,:now) '
        . 'ON CONFLICT(group_id,source_host) DO NOTHING');
    $now = time();
    $ids = $pdo->query("SELECT g.id FROM tracking_groups g LEFT JOIN tracking_groups p ON p.id=g.parent_id "
        . "WHERE g.parent_id IS NOT NULL AND (g.status='ACTIVE' OR (g.status='DRAFT' AND p.status='ACTIVE'))")
        ->fetchAll(PDO::FETCH_COLUMN);
    foreach ($ids as $id) {
        foreach ($hosts as $source) {
            $insert->execute([':group' => $id, ':source' => $source, ':now' => $now]);
        }
    }
}

function tracking_source(PDO $pdo, string $host): array
{
    $query = $pdo->prepare('SELECT * FROM tracking_sources WHERE source_host=:host');
    $query->execute([':host' => normalize_tracking_host($host)]);
    $row = $query->fetch();
    if (!is_array($row)) throw new DomainException('原入口不存在');
    return $row;
}

function tracking_assert_source_capacity(PDO $pdo): void
{
    if ((int) $pdo->query('SELECT COUNT(*) FROM tracking_sources')->fetchColumn() >= 1000) {
        throw new DomainException('原入口Catalog最多保留1000个入口（含历史及已删除入口）');
    }
}

/** A complete, successfully parsed upstream snapshot, not an additive hint.
 * Caller must never invoke this for partial reads, HEAD, or failed responses.
 * @param list<string> $hosts
 */
function tracking_sync_source_hosts(PDO $pdo, array $hosts, ?int $observedAt = null): void
{
    $sources = [];
    foreach ($hosts as $host) $sources[normalize_tracking_host($host)] = true;
    if (count($sources) > 1000) throw new InvalidArgumentException('原入口超过1000个，无法同步');
    if ($sources === []) throw new InvalidArgumentException('完整订阅快照必须包含真实节点入口');
    write_transaction($pdo, static function () use ($pdo, $sources, $observedAt): void {
        $now = $observedAt ?? time();
        $snapshot = $pdo->prepare('INSERT INTO tracking_source_snapshots (source_count,created_at) VALUES (:count,:now)');
        $snapshot->execute([':count' => count($sources), ':now' => $now]);
        $snapshotId = (int) $pdo->lastInsertId();
        $insert = $pdo->prepare("INSERT INTO tracking_sources (source_host,origin,ever_seen,state,first_seen_at,last_seen_at,first_snapshot_id,last_snapshot_id,created_at,updated_at) "
            . "VALUES (:host,'AUTO',1,'CURRENT',:now,:now,:snapshot,:snapshot,:now,:now)");
        $seen = $pdo->prepare("UPDATE tracking_sources SET ever_seen=1,state=CASE WHEN state='DELETED' THEN state ELSE 'CURRENT' END,"
            . 'first_seen_at=COALESCE(first_seen_at,:now),first_snapshot_id=COALESCE(first_snapshot_id,:snapshot),last_seen_at=:now,missing_count=0,last_snapshot_id=:snapshot,updated_at=:now WHERE source_host=:host');
        $query = $pdo->prepare('SELECT COUNT(*) FROM tracking_sources WHERE source_host=:host');
        foreach (array_keys($sources) as $source) {
            $query->execute([':host' => $source]);
            if ((int) $query->fetchColumn() === 0) {
                tracking_assert_source_capacity($pdo);
                $insert->execute([':host' => $source, ':now' => $now, ':snapshot' => $snapshotId]);
            } else $seen->execute([':host' => $source, ':now' => $now, ':snapshot' => $snapshotId]);
        }
        $missing = $pdo->prepare("UPDATE tracking_sources SET missing_count=missing_count+1,updated_at=:now,"
            . "state=CASE WHEN missing_count+1>=3 AND :now-last_seen_at>=600 THEN 'INACTIVE' ELSE 'SUSPECT' END "
            . "WHERE ever_seen=1 AND state!='DELETED' AND (last_snapshot_id IS NULL OR last_snapshot_id!=:snapshot)");
        $missing->execute([':now' => $now, ':snapshot' => $snapshotId]);
        tracking_ensure_source_mappings($pdo, array_keys($sources));
    });
}

function tracking_add_source(PDO $pdo, string $host): array
{
    $host = normalize_tracking_host($host);
    return write_transaction($pdo, static function () use ($pdo, $host): array {
        $query = $pdo->prepare('SELECT state FROM tracking_sources WHERE source_host=:host');
        $query->execute([':host' => $host]);
        $state = $query->fetchColumn();
        if ($state === 'DELETED') return tracking_restore_source($pdo, $host);
        if ($state !== false) throw new DomainException('原入口已存在，请编辑现有入口');
        tracking_assert_source_capacity($pdo);
        $insert = $pdo->prepare("INSERT INTO tracking_sources (source_host,origin,state,created_at,updated_at) VALUES (:host,'MANUAL','UNSEEN',:now,:now)");
        $insert->execute([':host' => $host, ':now' => time()]);
        tracking_ensure_source_mappings($pdo, [$host]);
        return tracking_source($pdo, $host);
    });
}

function tracking_delete_source(PDO $pdo, string $host): void
{
    write_transaction($pdo, static function () use ($pdo, $host): void {
        $source = tracking_source($pdo, $host);
        $update = $pdo->prepare("UPDATE tracking_sources SET state='DELETED',deleted_at=:now,updated_at=:now WHERE source_host=:host");
        $update->execute([':host' => $source['source_host'], ':now' => time()]);
        // Keep targets for an explicit restore; no enforced readiness veto on
        // deleting an in-use host. Runtime will filter it, even if it was last.
    });
}

function tracking_restore_source(PDO $pdo, string $host): array
{
    return write_transaction($pdo, static function () use ($pdo, $host): array {
        $source = tracking_source($pdo, $host);
        $latest = (int) $pdo->query('SELECT COALESCE(MAX(id),0) FROM tracking_source_snapshots')->fetchColumn();
        $state = (int) $source['last_snapshot_id'] === $latest && $latest > 0 ? 'CURRENT' : ((int) $source['ever_seen'] ? 'SUSPECT' : 'UNSEEN');
        $update = $pdo->prepare('UPDATE tracking_sources SET state=:state,deleted_at=NULL,missing_count=0,updated_at=:now WHERE source_host=:host');
        $update->execute([':state' => $state, ':host' => $source['source_host'], ':now' => time()]);
        tracking_ensure_source_mappings($pdo, [$source['source_host']]);
        return tracking_source($pdo, $host);
    });
}

function tracking_rename_source(PDO $pdo, string $old, string $new): array
{
    $new = normalize_tracking_host($new);
    return write_transaction($pdo, static function () use ($pdo, $old, $new): array {
        $source = tracking_source($pdo, $old);
        $old = $source['source_host'];
        if ($old === $new) return $source;
        if ($source['state'] === 'DELETED') throw new DomainException('请先恢复已删除入口再修改');
        $query = $pdo->prepare('SELECT (SELECT COUNT(*) FROM tracking_sources WHERE source_host=:host) '
            . '+ (SELECT COUNT(*) FROM tracking_entry_mappings WHERE source_host=:host)');
        $query->execute([':host' => $new]);
        if ((int) $query->fetchColumn() !== 0) throw new DomainException('请先处理重复入口映射，不能覆盖已有target');
        tracking_add_source($pdo, $new);
        // Copy targets, retaining old rows behind the tombstone for audit and
        // explicit restoration. Archived groups are never rewritten.
        $update = $pdo->prepare('INSERT INTO tracking_entry_mappings (group_id,source_host,target_host,created_at,updated_at) '
            . 'SELECT m.group_id,:new,m.target_host,:now,:now FROM tracking_entry_mappings m JOIN tracking_groups g ON g.id=m.group_id '
            . "WHERE m.source_host=:old AND g.status!='ARCHIVED' "
            . 'ON CONFLICT(group_id,source_host) DO UPDATE SET target_host=excluded.target_host,updated_at=excluded.updated_at');
        $update->execute([':new' => $new, ':old' => $old, ':now' => time()]);
        tracking_ensure_source_mappings($pdo, [$new]);
        tracking_delete_source($pdo, $old);
        return tracking_source($pdo, $new);
    });
}

function tracking_list_sources(PDO $pdo): array
{
    return $pdo->query('SELECT s.*,CASE WHEN s.last_snapshot_id=(SELECT MAX(id) FROM tracking_source_snapshots) THEN 1 ELSE 0 END AS in_latest '
        . 'FROM tracking_sources s ORDER BY source_host')->fetchAll();
}

function tracking_source_stats(PDO $pdo): array
{
    $counts = ['current' => 0, 'new' => 0, 'unmapped' => 0, 'suspect' => 0, 'inactive' => 0, 'manual_unseen' => 0, 'deleted' => 0];
    $leaves = tracking_active_leaves($pdo);
    $latest = (int) $pdo->query('SELECT COALESCE(MAX(id),0) FROM tracking_source_snapshots')->fetchColumn();
    $available = array_map(static fn ($leaf) => tracking_available_mapping($pdo, (int) $leaf['id'], true), $leaves);
    foreach (tracking_list_sources($pdo) as $source) {
        if ($source['state'] === 'CURRENT' && (int) $source['in_latest']) {
            $counts['current']++;
            if ((int) $source['first_snapshot_id'] === $latest) $counts['new']++;
            foreach ($available as $mapping) {
                if (!array_key_exists($source['source_host'], $mapping)) {
                    $counts['unmapped']++; break;
                }
            }
        } elseif ($source['state'] === 'SUSPECT') $counts['suspect']++;
        elseif ($source['state'] === 'INACTIVE') $counts['inactive']++;
        elseif ($source['state'] === 'DELETED') $counts['deleted']++;
        elseif ($source['origin'] === 'MANUAL') $counts['manual_unseen']++;
    }
    return $counts;
}

/** Admin form edits targets only; discovered sources cannot be removed or added.
 * @param list<array{source_host:mixed,target_host:mixed}> $rows
 */
function tracking_save_group_targets(PDO $pdo, int $groupId, array $rows): void
{
    write_transaction($pdo, static function () use ($pdo, $groupId, $rows): void {
        $known = array_column(tracking_group_mappings($pdo, $groupId), 'source_host');
        $provided = [];
        foreach ($rows as $row) {
            if (!is_array($row)) throw new InvalidArgumentException('入口映射格式不正确');
            $provided[] = normalize_tracking_host((string) ($row['source_host'] ?? ''));
        }
        sort($known, SORT_STRING);
        sort($provided, SORT_STRING);
        if ($known === [] || $known !== $provided) {
            throw new DomainException('原入口列表已变化，请刷新后重新填写目标入口');
        }
        tracking_save_group_mappings($pdo, $groupId, $rows);
    });
}

/** @return array<string, string> */
function tracking_effective_mapping(PDO $pdo, int $groupId): array
{
    if (!tracking_group_is_active_leaf($pdo, $groupId)) {
        throw new RuntimeException('Tracking assignment is not an active leaf');
    }
    return tracking_available_mapping($pdo, $groupId);
}

/** Current-only for readiness; runtime also accepts valid historical/manual
 * hosts actually present in this request, but NEVER a tombstoned source. */
function tracking_available_mapping(PDO $pdo, int $groupId, bool $currentOnly = false): array
{
    $query = $pdo->prepare('SELECT m.source_host,m.target_host FROM tracking_entry_mappings m JOIN tracking_sources s ON s.source_host=m.source_host '
        . "WHERE m.group_id=:id AND s.state!='DELETED' AND m.target_host IS NOT NULL AND TRIM(m.target_host)!=''"
        . ($currentOnly ? " AND s.state='CURRENT' AND s.last_snapshot_id=(SELECT MAX(id) FROM tracking_source_snapshots)" : ''));
    $query->execute([':id' => $groupId]);
    $mapping = [];
    foreach ($query as $row) $mapping[normalize_tracking_host($row['source_host'])] = normalize_tracking_host($row['target_host']);
    return $mapping;
}

/** @param list<array{source_host:mixed,target_host:mixed}> $rows */
function tracking_save_group_mappings(PDO $pdo, int $groupId, array $rows): void
{
    write_transaction($pdo, static function () use ($pdo, $groupId, $rows): void {
        $group = tracking_group($pdo, $groupId);
        if ($group['path'] === 'root' || $group['status'] === 'ARCHIVED') {
            throw new DomainException('This tracking group cannot have mappings');
        }
        // An ACTIVE split parent's retained mapping may be prepared for undo;
        // its children remain the effective mappings until the undo commits.
        if (count($rows) > 1000) {
            throw new InvalidArgumentException('Too many entry mappings');
        }
        $normalized = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                throw new InvalidArgumentException('Invalid entry mapping');
            }
            $source = normalize_tracking_host((string) ($row['source_host'] ?? ''));
            $targetInput = trim((string) ($row['target_host'] ?? ''));
            $target = $targetInput === '' ? null : normalize_tracking_host($targetInput);
            if (array_key_exists($source, $normalized)) {
                throw new InvalidArgumentException('Duplicate source host in tracking mapping');
            }
            $normalized[$source] = $target;
        }
        $delete = $pdo->prepare('DELETE FROM tracking_entry_mappings WHERE group_id = :group_id');
        $delete->execute([':group_id' => $groupId]);
        $insert = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_entry_mappings
    (group_id, source_host, target_host, created_at, updated_at)
VALUES (:group_id, :source_host, :target_host, :created_at, :updated_at)
SQL);
        $now = time();
        foreach ($normalized as $source => $target) {
            $insert->execute([':group_id' => $groupId, ':source_host' => $source,
                ':target_host' => $target, ':created_at' => $now, ':updated_at' => $now]);
        }
        $update = $pdo->prepare('UPDATE tracking_groups SET updated_at = :updated_at WHERE id = :id');
        $update->execute([':updated_at' => $now, ':id' => $groupId]);
        if (tracking_mode($pdo) === 'enforced') {
            tracking_validate_enforced_ready($pdo);
        }
    });
}

/** @return list<array<string, mixed>> */
function tracking_create_split(PDO $pdo, int $parentId, int $childCount = 2): array
{
    validate_tracking_child_count($childCount);
    return write_transaction($pdo, static function () use ($pdo, $parentId, $childCount): array {
        $parent = tracking_group($pdo, $parentId);
        if ($parent['path'] === 'root' || !tracking_group_is_active_leaf($pdo, $parentId)) {
            throw new DomainException('Only an active leaf group can be split');
        }
        $existing = $pdo->prepare("SELECT COUNT(*) FROM tracking_groups WHERE parent_id = :parent_id AND status != 'ARCHIVED'");
        $existing->execute([':parent_id' => $parentId]);
        if ((int) $existing->fetchColumn() !== 0) {
            throw new DomainException('Tracking group already has a split');
        }
        $now = time();
        $insert = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_groups
    (parent_id, child_no, path, status, created_at, updated_at)
VALUES (:parent_id, :child_no, :path, 'DRAFT', :created_at, :updated_at)
SQL);
        $mappingInsert = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_entry_mappings
    (group_id, source_host, target_host, created_at, updated_at)
VALUES (:group_id, :source_host, NULL, :created_at, :updated_at)
SQL);
        $sources = array_column(tracking_group_mappings($pdo, $parentId), 'source_host');
        if ($sources === []) {
            throw new DomainException('Configure the active parent mapping before creating a split');
        }
        tracking_retire_archived_paths($pdo, $parentId);
        $children = [];
        for ($childNo = 1; $childNo <= $childCount; $childNo++) {
            $path = $parent['path'] . '.' . $childNo;
            $insert->execute([':parent_id' => $parentId, ':child_no' => $childNo, ':path' => $path,
                ':created_at' => $now, ':updated_at' => $now]);
            $id = (int) $pdo->lastInsertId();
            foreach ($sources as $source) {
                $mappingInsert->execute([':group_id' => $id, ':source_host' => $source,
                    ':created_at' => $now, ':updated_at' => $now]);
            }
            $children[] = tracking_group($pdo, $id);
        }
        return $children;
    });
}

function validate_tracking_child_count(mixed $count): int
{
    if ($count !== 2) {
        throw new InvalidArgumentException('新拆分固定为2个子组');
    }
    return $count;
}

/** Reject unsafe pending trees before deleting or renumbering any row. */
function tracking_assert_draft_removable(PDO $pdo, array $group): void
{
    if ($group['parent_id'] === null || tracking_group($pdo, (int) $group['parent_id'])['path'] === 'root') {
        throw new DomainException('根级主组永远不能删除');
    }
    if ($group['status'] !== 'DRAFT') {
        throw new DomainException('仅允许删除待配置子组，已启用或归档组不可删除');
    }
    $statement = $pdo->prepare('SELECT '
        . '(SELECT COUNT(*) FROM tracking_assignments WHERE group_id = :id) + '
        . '(SELECT COUNT(*) FROM tracking_groups WHERE parent_id = :id)');
    $statement->execute([':id' => (int) $group['id']]);
    if ((int) $statement->fetchColumn() !== 0) {
        throw new DomainException('带有Token分配或子组的待配置组不可删除');
    }
}

/** @return list<array<string, mixed>> */
function tracking_pending_split(PDO $pdo, int $parentId): array
{
    $parent = tracking_group($pdo, $parentId);
    if ($parent['path'] === 'root' || !tracking_group_is_active_leaf($pdo, $parentId)) {
        throw new DomainException('仅允许取消ACTIVE叶子组下的待配置拆分');
    }
    $children = tracking_children($pdo, $parentId, 'DRAFT');
    $statement = $pdo->prepare("SELECT COUNT(*) FROM tracking_groups WHERE parent_id = :id "
        . "AND (status != 'ARCHIVED' OR path NOT LIKE '@archived/%')");
    $statement->execute([':id' => $parentId]);
    if ($children === [] || (int) $statement->fetchColumn() !== count($children)) {
        throw new DomainException('仅允许删除待配置拆分，已激活拆分数量不可改变');
    }
    foreach ($children as $child) tracking_assert_draft_removable($pdo, $child);
    return $children;
}

function tracking_delete_draft_group(PDO $pdo, int $groupId): void
{
    write_transaction($pdo, static function () use ($pdo, $groupId): void {
        $group = tracking_group($pdo, $groupId);
        tracking_assert_draft_removable($pdo, $group);
        $parentId = (int) $group['parent_id'];
        $children = tracking_pending_split($pdo, $parentId);
        $delete = $pdo->prepare("DELETE FROM tracking_groups WHERE id = :id AND status = 'DRAFT'");
        $delete->execute([':id' => $groupId]);
        $remaining = array_values(array_filter($children, static fn ($child) => (int) $child['id'] !== $groupId));
        $parent = tracking_group($pdo, $parentId);
        // Two phases avoid UNIQUE(parent_id,child_no) and UNIQUE(path) collisions.
        $maximum = $pdo->prepare('SELECT MAX(child_no) FROM tracking_groups WHERE parent_id = :id');
        $maximum->execute([':id' => $parentId]);
        $offset = (int) $maximum->fetchColumn() + 20;
        $update = $pdo->prepare('UPDATE tracking_groups SET child_no = :no, path = :path, updated_at = :now WHERE id = :id');
        $now = time();
        foreach ([$offset, 0] as $base) {
            foreach ($remaining as $index => $child) {
                $number = $base + $index + 1;
                $update->execute([':no' => $number, ':path' => $parent['path'] . '.' . $number,
                    ':now' => $now, ':id' => (int) $child['id']]);
            }
        }
    });
}

function tracking_cancel_split(PDO $pdo, int $parentId): void
{
    write_transaction($pdo, static function () use ($pdo, $parentId): void {
        tracking_pending_split($pdo, $parentId);
        $delete = $pdo->prepare("DELETE FROM tracking_groups WHERE parent_id = :id AND status = 'DRAFT'");
        $delete->execute([':id' => $parentId]);
    });
}

/** @return list<array<string, mixed>> */
function tracking_validate_split(PDO $pdo, int $parentId): array
{
    $parent = tracking_group($pdo, $parentId);
    if ($parent['path'] === 'root' || $parent['status'] !== 'ACTIVE' || !tracking_group_is_active_leaf($pdo, $parentId)) {
        throw new DomainException('Split parent must still be an active leaf');
    }
    $children = tracking_pending_split($pdo, $parentId);
    $childCount = count($children);
    if ($childCount !== 2
        || array_map(static fn (array $row): int => (int) $row['child_no'], $children) !== [1, 2]) {
        throw new DomainException('二分拆分必须完整保留2个连续编号的待配置子组，请取消拆分后重新创建');
    }
    $expectedSources = array_column(tracking_group_mappings($pdo, $parentId), 'source_host');
    sort($expectedSources, SORT_STRING);
    if ($expectedSources === []) {
        throw new DomainException('Split parent has no entry mappings');
    }
    foreach ($children as &$child) {
        $mappings = tracking_group_mappings($pdo, (int) $child['id']);
        if ($mappings === []) {
            throw new DomainException('Every draft child requires entry mappings');
        }
        $sources = [];
        foreach ($mappings as $mapping) {
            $source = normalize_tracking_host($mapping['source_host']);
            if ($mapping['target_host'] !== null && trim($mapping['target_host']) !== '') normalize_tracking_host($mapping['target_host']);
            $sources[] = $source;
        }
        sort($sources, SORT_STRING);
        if ($expectedSources !== $sources) {
            throw new DomainException('Draft children must cover the parent source hosts');
        }
        if (tracking_available_mapping($pdo, (int) $child['id'], true) === []) {
            throw new DomainException('每个待配置子组至少需要1个当前可用目标入口');
        }
        $child['mappings'] = $mappings;
    }
    unset($child);
    return $children;
}

function tracking_activate_split(PDO $pdo, int $parentId): int
{
    return write_transaction($pdo, static function () use ($pdo, $parentId): int {
        $children = tracking_validate_split($pdo, $parentId);
        $now = time();
        $activate = $pdo->prepare(
            "UPDATE tracking_groups SET status = 'ACTIVE', updated_at = :updated_at WHERE id = :id AND status = 'DRAFT'"
        );
        $byNumber = [];
        foreach ($children as $child) {
            $activate->execute([':updated_at' => $now, ':id' => (int) $child['id']]);
            if ($activate->rowCount() !== 1) {
                throw new RuntimeException('Draft tracking child changed during activation');
            }
            $byNumber[(int) $child['child_no']] = (int) $child['id'];
        }
        if (tracking_mode($pdo) === 'enforced') {
            tracking_validate_enforced_ready($pdo);
        }
        $assignments = $pdo->prepare(
            'SELECT token_hash FROM tracking_assignments WHERE group_id = :group_id ORDER BY token_hash'
        );
        $assignments->execute([':group_id' => $parentId]);
        $update = $pdo->prepare(
            'UPDATE tracking_assignments SET group_id = :group_id, algorithm_version = :version, '
            . 'updated_at = :updated_at WHERE token_hash = :token_hash AND group_id = :parent_id'
        );
        $moved = 0;
        foreach ($assignments as $assignment) {
            $tokenHash = (string) $assignment['token_hash'];
            $childNo = tracking_child_number($tokenHash, $parentId, count($children));
            $update->execute([':group_id' => $byNumber[$childNo], ':version' => TRACKING_ALGORITHM_VERSION,
                ':updated_at' => $now, ':token_hash' => $tokenHash, ':parent_id' => $parentId]);
            $moved += $update->rowCount();
        }
        $parent = $pdo->prepare(
            'UPDATE tracking_groups SET split_at = :split_at, updated_at = :updated_at WHERE id = :id'
        );
        $parent->execute([':split_at' => $now, ':updated_at' => $now, ':id' => $parentId]);
        return $moved;
    });
}

/** All descendants, including archived history; UNION also terminates on cycles.
 * @return list<array<string,mixed>>
 */
function tracking_descendants(PDO $pdo, int $parentId): array
{
    $query = $pdo->prepare(<<<'SQL'
WITH RECURSIVE descendants(id) AS (
    SELECT id FROM tracking_groups WHERE parent_id=:parent
    UNION
    SELECT g.id FROM tracking_groups g JOIN descendants d ON g.parent_id=d.id
)
SELECT g.*, (SELECT COUNT(*) FROM tracking_assignments a WHERE a.group_id=g.id) AS token_count
FROM tracking_groups g JOIN descendants d ON d.id=g.id ORDER BY g.id
SQL);
    $query->execute([':parent' => $parentId]);
    return $query->fetchAll();
}

/** Called only inside explicit re-splitting's transaction, never during upgrades.
 * Preserve IDs, FKs, mappings, events, timestamps and original path/ordinal in
 * the internal history path; free both UNIQUE(path) and UNIQUE(parent_id,child_no).
 */
function tracking_retire_archived_paths(PDO $pdo, int $parentId): void
{
    $history = tracking_descendants($pdo, $parentId);
    foreach ($history as $row) {
        if ($row['status'] !== 'ARCHIVED' || (int) $row['token_count'] !== 0) {
            throw new DomainException('历史拆分仍有有效子组或Token，不能重新拆分');
        }
    }
    $maximum = $pdo->prepare('SELECT MAX(child_no) FROM tracking_groups WHERE parent_id=:parent');
    $maximum->execute([':parent' => $parentId]);
    $slot = max(20, (int) $maximum->fetchColumn());
    $update = $pdo->prepare('UPDATE tracking_groups SET path=:path,child_no=:no WHERE id=:id');
    foreach ($history as $row) {
        if (str_starts_with($row['path'], '@archived/')) continue;
        $number = (int) $row['parent_id'] === $parentId ? ++$slot : (int) $row['child_no'];
        $update->execute([':path' => '@archived/' . $row['id'] . '/' . $row['path'],
            ':no' => $number, ':id' => (int) $row['id']]);
    }
}

/** Archive a complete ACTIVE layer and return only its Tokens to its direct parent. */
function tracking_undo_split(PDO $pdo, int $parentId): int
{
    return write_transaction($pdo, static function () use ($pdo, $parentId): int {
        $parent = tracking_group($pdo, $parentId);
        $children = tracking_children($pdo, $parentId);
        $count = count($children);
        if ($parent['path'] === 'root' || $parent['status'] !== 'ACTIVE' || $count < 2 || $count > 20
            || array_map(static fn ($row) => (int) $row['child_no'], $children) !== range(1, $count)) {
            throw new DomainException('仅允许撤销完整的ACTIVE拆分');
        }
        foreach (tracking_descendants($pdo, $parentId) as $row) {
            if ($row['status'] === 'DRAFT'
                || ($row['status'] === 'ACTIVE' && (int) $row['parent_id'] !== $parentId)) {
                throw new DomainException('请先撤销或处理下级拆分');
            }
            if ($row['status'] === 'ARCHIVED' && (int) $row['token_count'] !== 0) {
                throw new DomainException('归档子组仍有Token分配，不能撤销拆分');
            }
        }
        if (tracking_mode($pdo) === 'enforced') {
            if (tracking_available_mapping($pdo, $parentId, true) === []) {
                throw new DomainException('父组当前没有可用映射，请配置至少1个当前目标入口后再撤销拆分。');
            }
        }
        $now = time();
        $move = $pdo->prepare('UPDATE tracking_assignments SET group_id=:parent,updated_at=:now WHERE group_id=:child');
        $archive = $pdo->prepare("UPDATE tracking_groups SET status='ARCHIVED',updated_at=:now WHERE id=:id AND status='ACTIVE'");
        $moved = 0;
        foreach ($children as $child) {
            $move->execute([':parent' => $parentId, ':now' => $now, ':child' => (int) $child['id']]);
            $moved += $move->rowCount();
            $archive->execute([':now' => $now, ':id' => (int) $child['id']]);
            if ($archive->rowCount() !== 1) throw new RuntimeException('Active tracking child changed during undo');
        }
        if (tracking_mode($pdo) === 'enforced') tracking_validate_enforced_ready($pdo);
        // split_at remains historical, not a flag for effective leaf status.
        $update = $pdo->prepare('UPDATE tracking_groups SET updated_at=:now WHERE id=:id');
        $update->execute([':now' => $now, ':id' => $parentId]);
        return $moved;
    });
}

/** @return list<array<string, mixed>> */
function tracking_active_leaves(PDO $pdo): array
{
    return $pdo->query(<<<'SQL'
SELECT g.id, g.path
FROM tracking_groups g
WHERE g.status = 'ACTIVE' AND g.parent_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'ACTIVE'
  )
ORDER BY g.path
SQL)->fetchAll();
}

function tracking_validate_enforced_ready(PDO $pdo): void
{
    $leaves = tracking_active_leaves($pdo);
    if ($leaves === []) {
        throw new DomainException('No active tracking leaves exist');
    }
    foreach ($leaves as $leaf) {
        if (tracking_available_mapping($pdo, (int) $leaf['id'], true) === [])
            throw new DomainException('入口组' . $leaf['path'] . '当前没有任何可用映射，该组Token订阅将返回503');
    }
}

function tracking_set_mode(PDO $pdo, string $mode): void
{
    if (!in_array($mode, TRACKING_MODES, true)) {
        throw new InvalidArgumentException('Invalid tracking mode');
    }
    write_transaction($pdo, static function () use ($pdo, $mode): void {
        if ($mode === 'enforced') {
            tracking_validate_enforced_ready($pdo);
        }
        setting_set($pdo, 'tracking_mode', $mode);
        bump_config_version($pdo);
    });
}

/** @return list<array<string, mixed>> */
function tracking_list_groups(PDO $pdo): array
{
    $rows = $pdo->query(<<<'SQL'
SELECT g.id, g.parent_id, g.child_no, g.path, g.status, g.split_at, g.created_at, g.updated_at,
       COUNT(DISTINCT a.token_hash) AS token_count,
       COUNT(DISTINCT CASE WHEN s.state='CURRENT' AND s.last_snapshot_id=(SELECT MAX(id) FROM tracking_source_snapshots) THEN m.id END) AS mapping_count,
       COUNT(DISTINCT CASE WHEN s.state='CURRENT' AND s.last_snapshot_id=(SELECT MAX(id) FROM tracking_source_snapshots) AND m.target_host IS NOT NULL AND TRIM(m.target_host) != '' THEN m.id END) AS mapping_filled_count,
       EXISTS(SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'ACTIVE') AS has_active_children,
       EXISTS(SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'DRAFT') AS has_draft_children
FROM tracking_groups g
LEFT JOIN tracking_assignments a ON a.group_id = g.id
LEFT JOIN tracking_entry_mappings m ON m.group_id = g.id
LEFT JOIN tracking_sources s ON s.source_host=m.source_host
WHERE g.parent_id IS NOT NULL AND g.status != 'ARCHIVED'
GROUP BY g.id
ORDER BY g.path
SQL)->fetchAll();
    foreach ($rows as &$row) {
        foreach (['id', 'child_no', 'token_count', 'mapping_count', 'mapping_filled_count', 'has_active_children', 'has_draft_children'] as $key) {
            $row[$key] = (int) $row[$key];
        }
        $row['parent_id'] = (int) $row['parent_id'];
        $row['split_at'] = $row['split_at'] === null ? null : (int) $row['split_at'];
        $row['created_at'] = (int) $row['created_at'];
        $row['updated_at'] = (int) $row['updated_at'];
        $row['mappings'] = tracking_group_mappings($pdo, (int) $row['id']);
    }
    unset($row);
    usort($rows, static fn ($left, $right) => strnatcmp($left['path'], $right['path']));
    return $rows;
}

function tracking_record_transform_event(
    PDO $pdo,
    ?int $groupId,
    string $mode,
    string $format,
    string $outcome,
    array $counts = []
): void {
    if (!in_array($mode, ['preflight', 'enforced'], true)
        || !in_array($outcome, TRACKING_EVENT_OUTCOMES, true)
        || !preg_match('/^[A-Z0-9_]{1,32}$/D', $format)
    ) {
        throw new InvalidArgumentException('Invalid tracking event');
    }
    $total = $counts['total_nodes'] ?? 0;
    $emitted = $counts['emitted_nodes'] ?? 0;
    $skipped = $counts['skipped_nodes'] ?? 0;
    if (!is_int($total) || !is_int($emitted) || !is_int($skipped) || min($total, $emitted, $skipped) < 0
        || $total !== $emitted + $skipped) throw new InvalidArgumentException('Invalid node counts');
    $statement = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_transform_events (group_id, mode, format, outcome, created_at,total_nodes,emitted_nodes,skipped_nodes)
VALUES (:group_id, :mode, :format, :outcome, :created_at,:total,:emitted,:skipped)
SQL);
    $statement->execute([':group_id' => $groupId, ':mode' => $mode, ':format' => $format,
        ':outcome' => $outcome, ':created_at' => time(), ':total' => $total, ':emitted' => $emitted, ':skipped' => $skipped]);
    if (((int) $pdo->lastInsertId() % 100) === 0) {
        $cleanup = $pdo->prepare('DELETE FROM tracking_transform_events WHERE created_at < :cutoff');
        $cleanup->execute([':cutoff' => time() - 30 * 86400]);
    }
}

function tracking_record_transform_event_safe(
    PDO $pdo,
    ?int $groupId,
    string $mode,
    string $format,
    string $outcome,
    array $counts = []
): void {
    try {
        tracking_record_transform_event($pdo, $groupId, $mode, $format, $outcome, $counts);
    } catch (Throwable $error) {
        error_log('Tracking event persistence failure: ' . $error::class);
    }
}

/** @return array<string, mixed> */
function tracking_transform_stats(PDO $pdo): array
{
    $since = time() - 86400;
    $statement = $pdo->prepare(<<<'SQL'
SELECT COUNT(*) AS requests,
       SUM(CASE WHEN outcome IN ('SUCCESS','PARTIAL_SUCCESS') THEN 1 ELSE 0 END) AS successes,
       SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) AS full_successes,
       SUM(CASE WHEN outcome = 'PARTIAL_SUCCESS' THEN 1 ELSE 0 END) AS partial_successes,
       SUM(CASE WHEN outcome NOT IN ('SUCCESS','PARTIAL_SUCCESS') THEN 1 ELSE 0 END) AS failures,
       SUM(skipped_nodes) AS skipped_nodes,
       SUM(total_nodes) AS total_nodes,
       SUM(emitted_nodes) AS emitted_nodes,
       SUM(CASE WHEN outcome = 'NO_USABLE_NODES' THEN 1 ELSE 0 END) AS no_usable_nodes,
       SUM(CASE WHEN outcome = 'UNKNOWN_FORMAT' THEN 1 ELSE 0 END) AS unknown_formats,
       SUM(CASE WHEN outcome = 'MAPPING_INCOMPLETE' THEN 1 ELSE 0 END) AS mapping_incomplete,
       SUM(CASE WHEN outcome = 'PARSE_FAILED' THEN 1 ELSE 0 END) AS parse_failed,
       SUM(CASE WHEN outcome = 'RESPONSE_TOO_LARGE' THEN 1 ELSE 0 END) AS response_too_large
FROM tracking_transform_events WHERE created_at >= :since
SQL);
    $statement->execute([':since' => $since]);
    $row = $statement->fetch() ?: [];
    $stats = [];
    foreach (['requests', 'successes', 'full_successes', 'partial_successes', 'failures', 'skipped_nodes', 'total_nodes', 'emitted_nodes', 'no_usable_nodes', 'unknown_formats', 'mapping_incomplete',
        'parse_failed', 'response_too_large'] as $key) {
        $stats[$key] = (int) ($row[$key] ?? 0);
    }
    $formats = $pdo->prepare(
        'SELECT format, COUNT(*) AS count FROM tracking_transform_events '
        . 'WHERE created_at >= :since GROUP BY format ORDER BY format'
    );
    $formats->execute([':since' => $since]);
    $stats['formats'] = [];
    foreach ($formats as $format) {
        $stats['formats'][(string) $format['format']] = (int) $format['count'];
    }
    return $stats;
}
