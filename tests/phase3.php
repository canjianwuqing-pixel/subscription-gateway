<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/sgw/admin/src/analytics.php';

$phase3Directory = $temporaryRoot . DIRECTORY_SEPARATOR . 'phase3';
mkdir($phase3Directory, 0700, true);
$phase3Pdo = open_database($phase3Directory . '/worker.db');
initialize_database($phase3Pdo);
setting_set($phase3Pdo, 'upstream_url', 'https://backend.example.test');

test_case('v1 SQLite settings/admin schema migrates through tracking schema without deleting data', function () use ($phase3Directory): void {
    $old = open_database($phase3Directory . '/old.db');
    $old->exec('CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, '
        . 'created_at INTEGER, updated_at INTEGER)');
    $old->exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)');
    $old->exec('CREATE TABLE tokens (id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE)');
    $old->exec("INSERT INTO settings VALUES ('config_version', '7', 1)");
    $old->exec('PRAGMA user_version=1');
    initialize_database($old);
    expect_same(3, (int) $old->query('PRAGMA user_version')->fetchColumn());
    expect_same('7', setting_get($old, 'config_version'));
    expect_same('30', setting_get($old, 'log_retention_days'));
    $columns = $old->query('PRAGMA table_info(admins)')->fetchAll();
    expect_true(in_array('auth_version', array_column($columns, 'name'), true));
    $old = null;
});

test_case('SQLite VACUUM INTO backup contains a consistent database', function () use ($phase3Pdo, $phase3Directory): void {
    $target = $phase3Directory . '/snapshot.db';
    $statement = $phase3Pdo->prepare('VACUUM INTO :path');
    $statement->execute([':path' => $target]);
    $copy = open_database($target);
    expect_same('ok', $copy->query('PRAGMA integrity_check')->fetchColumn());
    $copy = null;
});

test_case('TEMP_BLOCKED future marker expires without Admin database access', function () use ($phase3Pdo): void {
    $token = str_repeat('a', 32);
    save_token($phase3Pdo, $token, 'TEMP_BLOCKED', time() + 120);
    $manual = $phase3Pdo->query('SELECT first_seen, last_seen FROM tokens LIMIT 1')->fetch();
    expect_same(null, $manual['first_seen']);
    expect_same(null, $manual['last_seen']);
    $rules = compile_gateway_rules($phase3Pdo)['rules'];
    expect_true(str_contains($rules, $token . ' TEMP_BLOCKED;'));
    expect_true(str_contains($rules, 'TOKEN_TEMP_BLOCKED 1;'));
    $statement = $phase3Pdo->prepare('UPDATE tokens SET expires_at = :past WHERE token_hash = :hash');
    $statement->execute([':past' => time() - 1, ':hash' => token_hash_value($token)]);
    $compiled = compile_gateway_rules($phase3Pdo);
    expect_true(!str_contains($compiled['rules'], $token . ' TEMP_BLOCKED;'));
    expect_same(1, $compiled['ignored_temp_blocked']);
});

test_case('duplicate configured Token parameter is rejected while other query keys remain valid', function () use ($phase3Pdo): void {
    $rules = compile_gateway_rules($phase3Pdo)['rules'];
    expect_true(str_contains($rules, 'map $args $token_query_duplicate'));
    $pattern = '/(?:^|&)token(?:=[^&]*)?(?:&[^&]*)*&token(?:=|&|$)/i';
    foreach (['token=abc&token=def', 'token=abc&flag=meta&token=def', 'flag=x&TOKEN=a&token=b'] as $query) {
        expect_same(1, preg_match($pattern, $query));
    }
    foreach (['token=abc', 'token=abc&flag=meta', 'flag=meta&token=abc'] as $query) {
        expect_same(0, preg_match($pattern, $query));
    }
    setting_set($phase3Pdo, 'token_query_key', 'auth_key');
    expect_true(str_contains(compile_gateway_rules($phase3Pdo)['rules'], 'map $arg_auth_key $token_valid'));
    setting_set($phase3Pdo, 'token_query_key', 'token');
});

test_case('ordinary Gateway log excludes query and separate event log uses configured Token key', function () use ($phase3Pdo, $root): void {
    $nginx = (string) file_get_contents($root . '/sgw/gateway/nginx.conf');
    expect_true((bool) preg_match('/log_format gateway escape=json(.*?);/s', $nginx, $match));
    expect_true(str_contains($match[1], '"path":"$uri"'));
    foreach (['$request_uri', '$request', '$args', '$arg_token', '$http_referer'] as $forbidden) {
        expect_same(0, preg_match('/' . preg_quote($forbidden, '/') . '(?![A-Za-z0-9_])/', $match[1]));
    }
    expect_true(str_contains($nginx, 'token-events.log token_events if=$token_event_loggable'));
    $rules = compile_gateway_rules($phase3Pdo)['rules'];
    expect_true(str_contains($rules, '$arg_token'));
    expect_true(str_contains($rules, '$token_event_loggable'));
});

test_case('worker ingests event, HMAC indexes Token, encrypts plaintext and resumes from offset', function () use ($phase3Pdo, $phase3Directory): void {
    $path = $phase3Directory . '/token-events.log';
    $token = str_repeat('b', 32);
    $line = json_encode(['time' => (float) time(), 'token' => $token, 'ip' => '192.0.2.10',
        'ua' => 'Client/1', 'status' => 200, 'path' => '/api/v1/x/subscribe', 'policy' => 'PASS']) . "\n";
    file_put_contents($path, $line);
    expect_same(1, worker_scan_once($phase3Pdo, $path), 'Worker did not ingest first line');
    expect_same(0, worker_scan_once($phase3Pdo, $path), 'Worker duplicated a line');
    $lookup = $phase3Pdo->prepare('SELECT id, token_hash, token_encrypted, request_count FROM tokens WHERE token_hash = :hash');
    $lookup->execute([':hash' => token_hash_value($token)]);
    $row = $lookup->fetch();
    expect_same(token_hash_value($token), $row['token_hash'], 'HMAC mismatch');
    expect_true(!str_contains((string) $row['token_encrypted'], $token));
    expect_same($token, decrypt_token((string) $row['token_encrypted']), 'Decrypt mismatch');
    expect_same(1, (int) $row['request_count'], 'Token count mismatch');
    $log = $phase3Pdo->query('SELECT token_id, client_ip, user_agent FROM access_logs')->fetch();
    expect_same((int) $row['id'], (int) $log['token_id'], 'Token id mismatch');
    expect_same('192.0.2.10', $log['client_ip'], 'IP mismatch');
});

test_case('worker continues after log rename and recreation', function () use ($phase3Pdo, $phase3Directory): void {
    $path = $phase3Directory . '/token-events.log';
    rename($path, $path . '.1');
    $line = json_encode(['time' => (float) time(), 'token' => str_repeat('c', 32), 'ip' => '192.0.2.11',
        'ua' => 'Client/2', 'status' => 403, 'path' => '/api/v1/y/subscribe', 'policy' => 'TOKEN_BLOCKED']) . "\n";
    file_put_contents($path, $line);
    worker_scan_once($phase3Pdo, $path);
    worker_scan_once($phase3Pdo, $path);
    expect_same(2, (int) $phase3Pdo->query('SELECT COUNT(*) FROM access_logs')->fetchColumn());
});

test_case('analytics groups recent requests without exposing full Token', function () use ($phase3Pdo): void {
    $rows = token_analysis_rows($phase3Pdo);
    expect_true(count($rows) >= 2);
    expect_true(!array_key_exists('token_encrypted', $rows[0]));
    $page = access_log_page($phase3Pdo, ['window' => '24h', 'page' => 1]);
    expect_same(2, count($page['rows']));
    $detail = token_detail_data($phase3Pdo, (int) $rows[0]['id'], '24h');
    expect_true(is_array($detail));
});

test_case('retention removes only old access logs', function () use ($phase3Pdo): void {
    $phase3Pdo->exec('UPDATE access_logs SET created_at = 1 WHERE id = (SELECT MIN(id) FROM access_logs)');
    setting_set($phase3Pdo, 'log_retention_days', '30');
    expect_same(1, worker_cleanup_if_due($phase3Pdo), 'Cleanup count mismatch');
    expect_same(1, (int) $phase3Pdo->query('SELECT COUNT(*) FROM access_logs')->fetchColumn(), 'Remaining log mismatch');
    expect_same(3, (int) $phase3Pdo->query('SELECT COUNT(*) FROM tokens')->fetchColumn(), 'Token preservation mismatch');
    expect_same(0, worker_cleanup_if_due($phase3Pdo), 'Cleanup reran early');
});

test_case('password change increments auth version and invalidates old Session', function (): void {
    $database = app_db();
    start_admin_session();
    $admin = authenticate_admin($database, 'admin_test', 'Correct-Horse-Battery-42');
    complete_login_session($admin);
    expect_true(is_authenticated());
    $version = change_admin_password(
        $database,
        $admin['id'],
        'Correct-Horse-Battery-42',
        'New-Strong-Password-123'
    );
    expect_same($admin['auth_version'] + 1, $version);
    expect_true(!is_authenticated());
    $new = authenticate_admin($database, 'admin_test', 'New-Strong-Password-123');
    expect_true(is_array($new));
    complete_login_session($new);
    expect_true(is_authenticated());
    destroy_admin_session();
});

$phase3Pdo = null;
