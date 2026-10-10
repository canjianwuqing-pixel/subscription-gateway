<?php

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

const TRACKING_MODES = ['off', 'preflight', 'enforced'];
const TRACKING_GROUP_STATUSES = ['DRAFT', 'ACTIVE', 'ARCHIVED'];
const TRACKING_EVENT_OUTCOMES = [
    'SUCCESS',
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
        if (count($children) !== 3 || array_map(static fn (array $row): int => (int) $row['child_no'], $children) !== [1, 2, 3]) {
            throw new RuntimeException('Active tracking split is incomplete');
        }
        $childNo = tracking_child_number($tokenHash, $current);
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
        } catch (Throwable) {
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

/** Learn only parser-validated connection hosts; never overwrite targets or prune sources.
 * @param list<string> $hosts
 */
function tracking_sync_source_hosts(PDO $pdo, array $hosts): void
{
    $sources = [];
    foreach ($hosts as $host) $sources[normalize_tracking_host($host)] = true;
    if (count($sources) > 1000) throw new InvalidArgumentException('原入口超过1000个，无法同步');
    if ($sources === []) return;
    write_transaction($pdo, static function () use ($pdo, $sources): void {
        $insert = $pdo->prepare('INSERT INTO tracking_entry_mappings '
            . '(group_id,source_host,target_host,created_at,updated_at) VALUES (:group,:source,NULL,:now,:now) '
            . 'ON CONFLICT(group_id,source_host) DO NOTHING');
        $now = time();
        foreach (tracking_active_leaves($pdo) as $leaf) {
            // Pending children stay compatible with sources learned after splitting.
            $ids = [(int) $leaf['id']];
            foreach (tracking_children($pdo, (int) $leaf['id'], 'DRAFT') as $child) $ids[] = (int) $child['id'];
            foreach ($ids as $id) {
                foreach (array_keys($sources) as $source) {
                    $insert->execute([':group' => $id, ':source' => $source, ':now' => $now]);
                }
            }
        }
    });
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
    $mapping = [];
    foreach (tracking_group_mappings($pdo, $groupId) as $row) {
        if ($row['target_host'] === null || $row['target_host'] === '') {
            throw new DomainException('Tracking mapping is incomplete');
        }
        $mapping[normalize_tracking_host($row['source_host'])] = normalize_tracking_host($row['target_host']);
    }
    if ($mapping === []) {
        throw new DomainException('Tracking mapping is incomplete');
    }
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
        if ($group['status'] === 'ACTIVE' && !tracking_group_is_active_leaf($pdo, $groupId)) {
            throw new DomainException('Only leaf groups can have effective mappings');
        }
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
            if ($group['status'] === 'ACTIVE' && $target === null) {
                throw new InvalidArgumentException('Active leaf mappings require a target host');
            }
            if (isset($normalized[$source])) {
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
function tracking_create_split(PDO $pdo, int $parentId): array
{
    return write_transaction($pdo, static function () use ($pdo, $parentId): array {
        $parent = tracking_group($pdo, $parentId);
        if ($parent['path'] === 'root' || !tracking_group_is_active_leaf($pdo, $parentId)) {
            throw new DomainException('Only an active leaf group can be split');
        }
        $existing = $pdo->prepare('SELECT COUNT(*) FROM tracking_groups WHERE parent_id = :parent_id');
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
        $children = [];
        for ($childNo = 1; $childNo <= 3; $childNo++) {
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

/** @return list<array<string, mixed>> */
function tracking_validate_split(PDO $pdo, int $parentId): array
{
    $parent = tracking_group($pdo, $parentId);
    if ($parent['status'] !== 'ACTIVE' || !tracking_group_is_active_leaf($pdo, $parentId)) {
        throw new DomainException('Split parent must still be an active leaf');
    }
    $children = tracking_children($pdo, $parentId, 'DRAFT');
    if (count($children) !== 3 || array_map(static fn (array $row): int => (int) $row['child_no'], $children) !== [1, 2, 3]) {
        throw new DomainException('Split must contain exactly three draft children');
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
            if ($mapping['target_host'] === null || trim($mapping['target_host']) === '') {
                throw new DomainException('Every draft entry mapping requires a target host');
            }
            normalize_tracking_host($mapping['target_host']);
            $sources[] = $source;
        }
        sort($sources, SORT_STRING);
        if ($expectedSources !== $sources) {
            throw new DomainException('Draft children must cover the parent source hosts');
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
            $childNo = tracking_child_number($tokenHash, $parentId);
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
    $expected = null;
    foreach ($leaves as $leaf) {
        $sources = array_keys(tracking_effective_mapping($pdo, (int) $leaf['id']));
        sort($sources, SORT_STRING);
        if ($expected === null) {
            $expected = $sources;
        } elseif ($expected !== $sources) {
            throw new DomainException('All active leaves must cover the same source hosts');
        }
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
       COUNT(DISTINCT m.id) AS mapping_count,
       EXISTS(SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'ACTIVE') AS has_active_children,
       EXISTS(SELECT 1 FROM tracking_groups c WHERE c.parent_id = g.id AND c.status = 'DRAFT') AS has_draft_children
FROM tracking_groups g
LEFT JOIN tracking_assignments a ON a.group_id = g.id
LEFT JOIN tracking_entry_mappings m ON m.group_id = g.id
WHERE g.parent_id IS NOT NULL
GROUP BY g.id
ORDER BY g.path
SQL)->fetchAll();
    foreach ($rows as &$row) {
        foreach (['id', 'child_no', 'token_count', 'mapping_count', 'has_active_children', 'has_draft_children'] as $key) {
            $row[$key] = (int) $row[$key];
        }
        $row['parent_id'] = (int) $row['parent_id'];
        $row['split_at'] = $row['split_at'] === null ? null : (int) $row['split_at'];
        $row['created_at'] = (int) $row['created_at'];
        $row['updated_at'] = (int) $row['updated_at'];
        $row['mappings'] = tracking_group_mappings($pdo, (int) $row['id']);
    }
    unset($row);
    return $rows;
}

function tracking_record_transform_event(
    PDO $pdo,
    ?int $groupId,
    string $mode,
    string $format,
    string $outcome
): void {
    if (!in_array($mode, ['preflight', 'enforced'], true)
        || !in_array($outcome, TRACKING_EVENT_OUTCOMES, true)
        || !preg_match('/^[A-Z0-9_]{1,32}$/D', $format)
    ) {
        throw new InvalidArgumentException('Invalid tracking event');
    }
    $statement = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_transform_events (group_id, mode, format, outcome, created_at)
VALUES (:group_id, :mode, :format, :outcome, :created_at)
SQL);
    $statement->execute([':group_id' => $groupId, ':mode' => $mode, ':format' => $format,
        ':outcome' => $outcome, ':created_at' => time()]);
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
    string $outcome
): void {
    try {
        tracking_record_transform_event($pdo, $groupId, $mode, $format, $outcome);
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
       SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) AS successes,
       SUM(CASE WHEN outcome != 'SUCCESS' THEN 1 ELSE 0 END) AS failures,
       SUM(CASE WHEN outcome = 'UNKNOWN_FORMAT' THEN 1 ELSE 0 END) AS unknown_formats,
       SUM(CASE WHEN outcome = 'MAPPING_INCOMPLETE' THEN 1 ELSE 0 END) AS mapping_incomplete,
       SUM(CASE WHEN outcome = 'PARSE_FAILED' THEN 1 ELSE 0 END) AS parse_failed,
       SUM(CASE WHEN outcome = 'RESPONSE_TOO_LARGE' THEN 1 ELSE 0 END) AS response_too_large
FROM tracking_transform_events WHERE created_at >= :since
SQL);
    $statement->execute([':since' => $since]);
    $row = $statement->fetch() ?: [];
    $stats = [];
    foreach (['requests', 'successes', 'failures', 'unknown_formats', 'mapping_incomplete',
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
