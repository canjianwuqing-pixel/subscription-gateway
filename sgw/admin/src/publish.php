<?php

declare(strict_types=1);

require_once __DIR__ . '/compiler.php';

const PUBLISH_TIMEOUT_SECONDS = 8;

function control_directory(): string
{
    return (string) (getenv('CONTROL_DIR') ?: '/control');
}

function atomic_control_write(string $path, string $content): void
{
    $temporary = $path . '.tmp';
    if (is_link($temporary)) {
        throw new RuntimeException('Unsafe temporary control file');
    }
    $handle = fopen($temporary, 'wb');
    if ($handle === false) {
        throw new RuntimeException('Cannot open temporary control file');
    }
    try {
        if (!chmod($temporary, 0640)) {
            throw new RuntimeException('Cannot secure temporary control file');
        }
        $length = strlen($content);
        $written = 0;
        while ($written < $length) {
            $count = fwrite($handle, substr($content, $written));
            if ($count === false || $count === 0) {
                throw new RuntimeException('Cannot write temporary control file');
            }
            $written += $count;
        }
        if (!fflush($handle) || !fsync($handle)) {
            throw new RuntimeException('Cannot sync temporary control file');
        }
    } finally {
        fclose($handle);
    }
    if (!rename($temporary, $path)) {
        throw new RuntimeException('Cannot atomically publish control file');
    }
}

function active_gateway_version(): int
{
    $path = control_directory() . '/active_version';
    if (!is_file($path) || is_link($path)) {
        return 0;
    }
    $value = trim((string) file_get_contents($path));
    return preg_match('/^(0|[1-9][0-9]*)$/D', $value) ? (int) $value : 0;
}

function gateway_publish_status(PDO $pdo): array
{
    $configured = (int) setting_get($pdo, 'config_version', '0');
    $active = active_gateway_version();
    return [
        'config_version' => $configured,
        'active_version' => $active,
        'pending' => $configured > $active,
    ];
}

function matching_publish_result(string $path, string $id, int $version, string $sha256): ?array
{
    if (!is_file($path) || is_link($path)) {
        return null;
    }
    $result = json_decode((string) file_get_contents($path), true);
    if (!is_array($result)
        || ($result['id'] ?? null) !== $id
        || ($result['version'] ?? null) !== $version
        || ($result['sha256'] ?? null) !== $sha256
        || !is_bool($result['ok'] ?? null)
    ) {
        return null;
    }
    return $result;
}

function publish_current_rules(PDO $pdo): array
{
    $directory = control_directory();
    if (!is_dir($directory) || !is_writable($directory) || is_link($directory)) {
        return ['applied' => null, 'error_code' => 'CONTROL_UNAVAILABLE'];
    }
    $lock = fopen($directory . '/publish.lock', 'c+');
    if ($lock === false) {
        return ['applied' => null, 'error_code' => 'LOCK_UNAVAILABLE'];
    }
    try {
        if (!flock($lock, LOCK_EX)) {
            return ['applied' => null, 'error_code' => 'LOCK_UNAVAILABLE'];
        }
        try {
            $pdo->beginTransaction();
            try {
                $compiled = compile_gateway_rules($pdo);
                $version = (int) setting_get($pdo, 'config_version', '0');
                $pdo->commit();
            } catch (Throwable $error) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $error;
            }
            $candidate = $compiled['rules'];
            $sha256 = hash('sha256', $candidate);
            $id = bin2hex(random_bytes(16));
            atomic_control_write($directory . '/candidate.conf', $candidate);
            atomic_control_write($directory . '/request.json', json_encode([
                'id' => $id,
                'version' => $version,
                'sha256' => $sha256,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
            $resultPath = $directory . '/result.json';
            $deadline = microtime(true) + PUBLISH_TIMEOUT_SECONDS;
            do {
                $result = matching_publish_result($resultPath, $id, $version, $sha256);
                if ($result !== null) {
                    return [
                        'applied' => $result['ok'],
                        'error_code' => $result['ok'] ? null : (string) ($result['error_code'] ?? 'GATEWAY_REJECTED'),
                        'version' => $version,
                        'ignored_temp_blocked' => $compiled['ignored_temp_blocked'],
                    ];
                }
                usleep(100000);
            } while (microtime(true) < $deadline);
            return [
                'applied' => null,
                'error_code' => 'GATEWAY_PENDING',
                'version' => $version,
                'ignored_temp_blocked' => $compiled['ignored_temp_blocked'],
            ];
        } catch (Throwable $error) {
            error_log('Gateway publish failure: ' . $error::class);
            return ['applied' => null, 'error_code' => 'PUBLISH_FAILED'];
        } finally {
            flock($lock, LOCK_UN);
        }
    } finally {
        fclose($lock);
    }
}
