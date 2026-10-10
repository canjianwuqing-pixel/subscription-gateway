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
        break;
    default:
        throw new InvalidArgumentException('Unknown CI database action');
}

echo "CI_DB_OK\n";
