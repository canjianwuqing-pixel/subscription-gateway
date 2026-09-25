<?php

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

function event_log_files(string $path): array
{
    return [$path, $path . '.1', $path . '.2', $path . '.3', $path . '.4'];
}

function ingest_token_event(PDO $pdo, string $line, string $inode, int $offset): void
{
    $event = json_decode($line, true, 16);
    $valid = is_array($event)
        && is_string($event['token'] ?? null)
        && is_string($event['ip'] ?? null)
        && is_string($event['ua'] ?? null)
        && is_string($event['path'] ?? null)
        && is_string($event['policy'] ?? null)
        && is_numeric($event['time'] ?? null)
        && is_int($event['status'] ?? null)
        && strlen($event['ua']) <= 8192
        && strlen($event['path']) <= 2048
        && strlen($event['ip']) <= 64
        && $event['status'] >= 100 && $event['status'] <= 599;
    if ($valid) {
        try {
            validate_token_format($event['token']);
        } catch (InvalidArgumentException) {
            $valid = false;
        }
    }
    write_transaction($pdo, static function () use ($pdo, $event, $valid, $inode, $offset): void {
        if ($valid) {
            $token = $event['token'];
            $createdAt = (int) (float) $event['time'];
            $createdAt = max(1, min(time() + 300, $createdAt));
            $hash = token_hash_value($token);
            $insert = $pdo->prepare(<<<'SQL'
INSERT OR IGNORE INTO tokens
    (token_hash, token_encrypted, state, first_seen, last_seen, request_count, created_at, updated_at)
VALUES (:hash, :encrypted, 'NORMAL', :seen, :seen, 0, :seen, :seen)
SQL);
            $insert->execute([':hash' => $hash, ':encrypted' => encrypt_token($token), ':seen' => $createdAt]);
            $lookup = $pdo->prepare('SELECT id FROM tokens WHERE token_hash = :hash');
            $lookup->execute([':hash' => $hash]);
            $id = (int) $lookup->fetchColumn();
            $update = $pdo->prepare(<<<'SQL'
UPDATE tokens SET
    first_seen = MIN(COALESCE(first_seen, :first), :first),
    last_seen = MAX(COALESCE(last_seen, :last), :last),
    request_count = request_count + 1
WHERE id = :id
SQL);
            $update->execute([':first' => $createdAt, ':last' => $createdAt, ':id' => $id]);
            $access = $pdo->prepare(<<<'SQL'
INSERT INTO access_logs
    (token_id, client_ip, user_agent, request_path, status_code, decision, created_at)
VALUES (:token_id, :ip, :ua, :path, :status, :decision, :created_at)
SQL);
            $access->execute([
                ':token_id' => $id,
                ':ip' => $event['ip'],
                ':ua' => $event['ua'],
                ':path' => $event['path'],
                ':status' => $event['status'],
                ':decision' => substr($event['policy'], 0, 64),
                ':created_at' => $createdAt,
            ]);
        }
        setting_set($pdo, 'token_log_inode', $inode);
        setting_set($pdo, 'token_log_offset', (string) $offset);
    });
}

function worker_scan_once(PDO $pdo, string $path, int $limit = 100): int
{
    $storedInode = setting_get($pdo, 'token_log_inode', '');
    $offset = (int) setting_get($pdo, 'token_log_offset', '0');
    $source = null;
    foreach (event_log_files($path) as $file) {
        clearstatcache(true, $file);
        if (is_file($file) && !is_link($file) && (string) fileinode($file) === $storedInode) {
            $source = $file;
            break;
        }
    }
    if ($source === null) {
        $source = is_file($path) && !is_link($path) ? $path : null;
        $offset = 0;
    }
    if ($source === null) {
        return 0;
    }
    $handle = fopen($source, 'rb');
    if ($handle === false) {
        return 0;
    }
    $inode = (string) fileinode($source);
    try {
        if ($offset > 0 && $offset <= filesize($source)) {
            fseek($handle, $offset);
        } else {
            $offset = 0;
        }
        $processed = 0;
        while ($processed < $limit && ($line = fgets($handle, 32769)) !== false) {
            if (!str_ends_with($line, "\n")) {
                if (feof($handle)) {
                    break;
                }
                while (($part = fgets($handle, 32769)) !== false && !str_ends_with($part, "\n")) {
                }
                $line = '';
            }
            $position = ftell($handle);
            if ($position === false) {
                throw new RuntimeException('Cannot read event log offset');
            }
            ingest_token_event($pdo, $line, $inode, $position);
            $processed++;
        }
        if ($processed === 0 && $source !== $path && feof($handle)) {
            setting_set($pdo, 'token_log_inode', '');
            setting_set($pdo, 'token_log_offset', '0');
        }
        return $processed;
    } finally {
        fclose($handle);
    }
}

function worker_cleanup_if_due(PDO $pdo): int
{
    $now = time();
    if ($now - (int) setting_get($pdo, 'last_log_cleanup_at', '0') < 86400) {
        return 0;
    }
    $days = (int) setting_get($pdo, 'log_retention_days', '30');
    if ($days < 1 || $days > 3650) {
        throw new RuntimeException('Invalid log retention setting');
    }
    $deleted = 0;
    do {
        $count = write_transaction($pdo, static function () use ($pdo, $now, $days): int {
            $statement = $pdo->prepare(
                'DELETE FROM access_logs WHERE id IN '
                . '(SELECT id FROM access_logs WHERE created_at < :cutoff ORDER BY created_at LIMIT 1000)'
            );
            $statement->execute([':cutoff' => $now - $days * 86400]);
            return $statement->rowCount();
        });
        $deleted += $count;
    } while ($count === 1000);
    setting_set($pdo, 'last_log_cleanup_at', (string) $now);
    return $deleted;
}

function worker_loop(): never
{
    $path = (string) (getenv('TOKEN_EVENT_LOG_PATH') ?: '/var/log/subscription-gateway/token-events.log');
    while (true) {
        try {
            $pdo = app_db();
            worker_scan_once($pdo, $path);
            worker_cleanup_if_due($pdo);
        } catch (Throwable $error) {
            error_log('Token event worker failure: ' . $error::class);
        }
        sleep(1);
    }
}

if (realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    worker_loop();
}
