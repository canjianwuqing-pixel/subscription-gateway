<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}

require_once '/app/src/compiler.php';

$pdo = app_db();
$command = $argv[1] ?? '';

switch ($command) {
    case 'configure':
        $origin = (string) ($argv[2] ?? '');
        validate_upstream_url($origin);
        write_transaction($pdo, static function () use ($pdo, $origin): void {
            setting_set($pdo, 'upstream_url', $origin);
            setting_set($pdo, 'rate_enabled', '0');
            bump_config_version($pdo);
        });
        break;
    case 'token':
        $token = (string) ($argv[2] ?? '');
        $state = (string) ($argv[3] ?? '');
        $expiresAt = $state === 'TEMP_BLOCKED' ? time() + 40 : null;
        write_transaction($pdo, static function () use ($pdo, $token, $state, $expiresAt): void {
            save_token($pdo, $token, $state, $expiresAt);
            bump_config_version($pdo);
        });
        break;
    case 'ip':
        $address = (string) ($argv[2] ?? '');
        $action = (string) ($argv[3] ?? '');
        write_transaction($pdo, static function () use ($pdo, $address, $action): void {
            add_ip_rule($pdo, $address, $action);
            bump_config_version($pdo);
        });
        break;
    case 'clear-ip':
        write_transaction($pdo, static function () use ($pdo): void {
            $pdo->exec('DELETE FROM ip_rules');
            bump_config_version($pdo);
        });
        break;
    case 'ua':
        $action = (string) ($argv[2] ?? '');
        write_transaction($pdo, static function () use ($pdo, $action): void {
            add_ua_rule($pdo, 'CI_Blocked_Client', $action);
            bump_config_version($pdo);
        });
        break;
    case 'clear-ua':
        write_transaction($pdo, static function () use ($pdo): void {
            $pdo->exec('DELETE FROM ua_rules');
            bump_config_version($pdo);
        });
        break;
    case 'rate':
        $enabled = ($argv[2] ?? '') === 'on';
        save_rate_settings($pdo, $enabled, $enabled ? 1 : 20, 0);
        break;
    case 'tracking-configure':
        $token = (string) ($argv[2] ?? '');
        $mode = (string) ($argv[3] ?? '');
        validate_token_format($token);
        tracking_assignment_for_hash($pdo, token_hash_value($token));
        tracking_sync_source_hosts($pdo, ['origin.example.invalid']);
        foreach (tracking_active_leaves($pdo) as $leaf) {
            tracking_save_group_mappings($pdo, (int) $leaf['id'], [[
                'source_host' => 'origin.example.invalid',
                'target_host' => 'group' . str_replace('.', '-', (string) $leaf['path']) . '.example.invalid',
            ]]);
        }
        tracking_set_mode($pdo, $mode);
        break;
    case 'tracking-mode':
        tracking_set_mode($pdo, (string) ($argv[2] ?? ''));
        break;
    case 'tracking-target':
        $token = (string) ($argv[2] ?? '');
        validate_token_format($token);
        $groupId = tracking_assignment_for_hash($pdo, token_hash_value($token));
        $mapping = tracking_effective_mapping($pdo, $groupId);
        echo $mapping['origin.example.invalid'] . "\n";
        exit(0);
    case 'assert-assigned':
        $token = (string) ($argv[2] ?? '');
        validate_token_format($token);
        $statement = $pdo->prepare('SELECT group_id FROM tracking_assignments WHERE token_hash=:hash');
        $statement->execute([':hash' => token_hash_value($token)]);
        $groupId = (int) $statement->fetchColumn();
        if (!tracking_group_is_active_leaf($pdo, $groupId)) {
            throw new RuntimeException('Token assignment is missing or not an active leaf');
        }
        break;
    case 'assert-learned':
        $expectedSource = (string) ($argv[2] ?? 'origin.example.invalid');
        foreach (tracking_active_leaves($pdo) as $leaf) {
            $rows = tracking_group_mappings($pdo, (int) $leaf['id']);
            $matched = array_values(array_filter($rows, static fn ($row) => $row['source_host'] === $expectedSource));
            if (count($matched) !== 1 || $matched[0]['target_host'] !== null) {
                throw new RuntimeException('Learning did not add exactly one empty target to every leaf');
            }
            foreach ($rows as $row) {
                if (str_contains($row['source_host'], 'sni-only') || str_contains($row['source_host'], 'name-only')) {
                    throw new RuntimeException('Learning captured a non-connection field');
                }
            }
        }
        break;
    case 'assignment-digest':
        echo hash('sha256', json_encode($pdo->query('SELECT * FROM tracking_assignments ORDER BY token_hash')->fetchAll(), JSON_THROW_ON_ERROR)), "\n";
        exit(0);
    case 'branch-assignment-digest':
        $query = $pdo->prepare('WITH RECURSIVE branch(id) AS (SELECT id FROM tracking_groups WHERE id=:id '
            . 'UNION SELECT g.id FROM tracking_groups g JOIN branch b ON g.parent_id=b.id) '
            . 'SELECT * FROM tracking_assignments WHERE group_id NOT IN (SELECT id FROM branch) ORDER BY token_hash');
        $query->execute([':id' => (int) ($argv[2] ?? 0)]);
        echo hash('sha256', json_encode($query->fetchAll(), JSON_THROW_ON_ERROR)), "\n";
        exit(0);
    case 'assert-assigned-to':
        if (tracking_assignment_for_hash($pdo, token_hash_value((string) $argv[2])) !== (int) $argv[3]) {
            throw new RuntimeException('Token did not return to its direct parent');
        }
        break;
    case 'assert-binary-history':
        $parent = (int) ($argv[2] ?? 0);
        $children = tracking_children($pdo, $parent, 'ARCHIVED');
        if (count($children) < 2 || (int) $pdo->query('PRAGMA user_version')->fetchColumn() !== 6
            || $pdo->query('PRAGMA foreign_key_check')->fetchAll() !== []
            || $pdo->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN) !== ['ok']) {
            throw new RuntimeException('Binary split history or SQLite integrity check failed');
        }
        foreach ($children as $child) {
            if (tracking_group_mappings($pdo, (int) $child['id']) === []) throw new RuntimeException('Archived mappings were deleted');
            $query = $pdo->prepare('SELECT COUNT(*) FROM tracking_assignments WHERE group_id=:id');
            $query->execute([':id' => (int) $child['id']]);
            if ((int) $query->fetchColumn() !== 0) throw new RuntimeException('Archived child still holds assignments');
        }
        break;
    case 'assert-mapping':
        $statement = $pdo->prepare('SELECT source_host, target_host FROM tracking_entry_mappings WHERE group_id = :id');
        $statement->execute([':id' => (int) ($argv[2] ?? 0)]);
        if ($statement->fetchAll() !== [['source_host' => (string) ($argv[3] ?? ''),
            'target_host' => (string) ($argv[4] ?? '')]]) {
            throw new RuntimeException('HTTP mapping save did not persist the expected SQLite row');
        }
        break;
    case 'assert-ingested':
        $token = (string) ($argv[2] ?? '');
        validate_token_format($token);
        $statement = $pdo->prepare('SELECT id, token_encrypted, request_count FROM tokens WHERE token_hash = :hash');
        $statement->execute([':hash' => token_hash_value($token)]);
        $row = $statement->fetch();
        if (!is_array($row) || (int) $row['request_count'] < 1
            || str_contains((string) $row['token_encrypted'], $token)
            || decrypt_token((string) $row['token_encrypted']) !== $token
        ) {
            throw new RuntimeException('Token event was not securely ingested');
        }
        $statement = $pdo->prepare('SELECT COUNT(*) FROM access_logs WHERE token_id = :id');
        $statement->execute([':id' => (int) $row['id']]);
        if ((int) $statement->fetchColumn() < 1) {
            throw new RuntimeException('No access log was ingested');
        }
        $statement = $pdo->prepare('SELECT COUNT(*) FROM tracking_assignments WHERE token_hash=:hash');
        $statement->execute([':hash' => token_hash_value($token)]);
        if ((int) $statement->fetchColumn() !== 1) {
            throw new RuntimeException('off worker did not create a unique assignment');
        }
        break;
    default:
        throw new InvalidArgumentException('Unknown CI database action');
}

echo "CI_DB_OK\n";
