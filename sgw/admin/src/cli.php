<?php
declare(strict_types=1);
require_once __DIR__ . '/publish.php';

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

try {
    $command = $argv[1] ?? '';
    $pdo = app_db();
    if ($command === 'migrate') {
        echo 'MIGRATED', PHP_EOL;
    } elseif ($command === 'init-admin') {
        if (admin_count($pdo) !== 0) throw new RuntimeException('Administrator already exists');
        $username = (string) ($argv[2] ?? '');
        $password = rtrim((string) stream_get_contents(STDIN), "\r\n");
        create_admin($pdo, $username, $password);
        echo 'ADMIN_CREATED', PHP_EOL;
    } elseif ($command === 'reset-admin-password') {
        $password = rtrim((string) stream_get_contents(STDIN), "\r\n");
        $hash = password_hash_secure($password);
        $statement = $pdo->prepare('UPDATE admins SET password_hash = :hash, '
            . 'auth_version = auth_version + 1, updated_at = :updated');
        $statement->execute([':hash' => $hash, ':updated' => time()]);
        if ($statement->rowCount() !== 1) throw new RuntimeException('Expected exactly one administrator');
        echo 'PASSWORD_RESET', PHP_EOL;
    } elseif ($command === 'integrity') {
        if ($pdo->query('PRAGMA integrity_check')->fetchColumn() !== 'ok') {
            throw new RuntimeException('SQLite integrity_check failed');
        }
        echo 'SQLITE_OK', PHP_EOL;
    } elseif ($command === 'backup') {
        $target = (string) ($argv[2] ?? '');
        if (!preg_match('#^/backups/[A-Za-z0-9._-]+\.db$#D', $target)) {
            throw new InvalidArgumentException('Invalid backup destination');
        }
        $statement = $pdo->prepare('VACUUM INTO :path');
        $statement->execute([':path' => $target]);
        echo 'BACKUP_OK', PHP_EOL;
    } elseif ($command === 'compile') {
        if (setting_get($pdo, 'upstream_url', '') === '') {
            echo 'FAIL_CLOSED', PHP_EOL;
        } else {
            $result = publish_current_rules($pdo);
            if ($result['applied'] !== true) throw new RuntimeException('Gateway rule application did not complete');
            echo 'RULES_APPLIED', PHP_EOL;
        }
    } elseif ($command === 'versions') {
        $status = gateway_publish_status($pdo);
        echo $status['config_version'], ' ', $status['active_version'], PHP_EOL;
    } elseif ($command === 'upstream-state') {
        echo setting_get($pdo, 'upstream_url', '') === '' ? 'EMPTY' : 'CONFIGURED', PHP_EOL;
    } else {
        throw new InvalidArgumentException('Unknown CLI command');
    }
} catch (Throwable $error) {
    fwrite(STDERR, 'CLI failed: ' . $error::class . ': ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
