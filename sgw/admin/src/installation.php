<?php
declare(strict_types=1);

require_once __DIR__ . '/publish.php';

function installation_extensions_check(): void
{
    foreach (['pdo_sqlite', 'sodium', 'curl', 'yaml'] as $extension) {
        if (!extension_loaded($extension)) {
            throw new RuntimeException('Installation requires PHP extension: ' . $extension);
        }
    }
}

/** @return array{schema:int,tracking_mode:string,upstream:string} */
function installation_database_check(PDO $pdo): array
{
    $schema = (int) $pdo->query('PRAGMA user_version')->fetchColumn();
    if ($schema !== DATABASE_SCHEMA_VERSION) {
        throw new RuntimeException('Unexpected database schema: ' . $schema . '; expected ' . DATABASE_SCHEMA_VERSION);
    }
    if ($pdo->query('PRAGMA integrity_check')->fetchColumn() !== 'ok'
        || $pdo->query('PRAGMA foreign_key_check')->fetch() !== false) {
        throw new RuntimeException('SQLite integrity/foreign key check failed');
    }
    if (admin_count($pdo) !== 1) {
        throw new RuntimeException('Expected exactly one administrator');
    }
    $mode = tracking_mode($pdo);
    $groups = $pdo->query("SELECT id,parent_id,child_no,path,status FROM tracking_groups WHERE path IN ('root','1','2','3')")
        ->fetchAll();
    $byPath = [];
    foreach ($groups as $group) $byPath[$group['path']] = $group;
    $root = $byPath['root'] ?? null;
    if (!is_array($root) || $root['parent_id'] !== null || (int) $root['child_no'] !== 0 || $root['status'] !== 'ACTIVE') {
        throw new RuntimeException('Tracking root structure is incomplete');
    }
    foreach ([1, 2, 3] as $childNo) {
        $child = $byPath[(string) $childNo] ?? null;
        if (!is_array($child) || (int) $child['parent_id'] !== (int) $root['id']
            || (int) $child['child_no'] !== $childNo || $child['status'] !== 'ACTIVE') {
            throw new RuntimeException('Initial tracking group structure is incomplete');
        }
    }
    return ['schema' => $schema, 'tracking_mode' => $mode,
        'upstream' => setting_get($pdo, 'upstream_url', '') === '' ? 'EMPTY' : 'CONFIGURED'];
}

function installation_transformer_check(): void
{
    installation_extensions_check();
    // No token/mode is supplied: the real Transformer must reject this local
    // request before reading SQLite or contacting an upstream. This proves the
    // Nginx 8081 -> separate FPM 9001 -> PHP path, not just an open TCP port.
    $curl = curl_init('http://127.0.0.1:8081/api/v1/install-check/subscribe');
    if ($curl === false) throw new RuntimeException('Cannot initialize Transformer health probe');
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROXY => '']);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_errno($curl);
    curl_close($curl);
    if ($error !== CURLE_OK || $status !== 403 || $body !== 'Subscription transformation unavailable.') {
        throw new RuntimeException('Internal Transformer 8081/FPM probe failed');
    }
}
