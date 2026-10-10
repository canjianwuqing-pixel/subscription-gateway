<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$temporaryRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'subscription-gateway-tests-' . bin2hex(random_bytes(6));
$dataDirectory = $temporaryRoot . DIRECTORY_SEPARATOR . 'data';
$sessionDirectory = $temporaryRoot . DIRECTORY_SEPARATOR . 'sessions';
$rateDirectory = $temporaryRoot . DIRECTORY_SEPARATOR . 'rate';
mkdir($dataDirectory, 0700, true);
mkdir($sessionDirectory, 0700, true);
mkdir($rateDirectory, 0700, true);

putenv('DATABASE_PATH=' . $dataDirectory . DIRECTORY_SEPARATOR . 'main.db');
putenv('ADMIN_SECRET_PATH=test_secret_path_123456');
putenv('SESSION_NAME=subscription_gateway_test');
putenv('SESSION_COOKIE_SECURE=true');
putenv('LOGIN_RATE_DIR=' . $rateDirectory);
putenv('TOKEN_HMAC_KEY=' . base64_encode(str_repeat('H', 32)));
putenv('TOKEN_ENCRYPTION_KEY=' . base64_encode(str_repeat('E', 32)));

ini_set('session.save_path', $sessionDirectory);

foreach (['PDO', 'pdo_sqlite', 'sqlite3', 'sodium', 'curl', 'yaml'] as $extension) {
    if (!extension_loaded($extension)) {
        throw new RuntimeException("Test PHP is missing required extension: {$extension}");
    }
}

require $root . '/sgw/admin/src/api.php';

$passed = 0;
$failed = 0;
$failures = [];

function test_case(string $name, callable $test): void
{
    global $passed, $failed, $failures;
    try {
        $test();
        $passed++;
    } catch (Throwable $error) {
        $failed++;
        $failures[] = $name . ': ' . $error::class . ': ' . $error->getMessage();
    }
}

function expect_true(bool $condition, string $message = 'Expected condition to be true'): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expect_same(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message !== '' ? $message : 'Values are not identical');
    }
}

function expect_exception(callable $callback, string $class): void
{
    try {
        $callback();
    } catch (Throwable $error) {
        if ($error instanceof $class) {
            return;
        }
        throw new RuntimeException('Expected ' . $class . ', received ' . $error::class);
    }
    throw new RuntimeException("Expected {$class}, but no exception was thrown");
}

function table_count(PDO $pdo, string $table): int
{
    if (!in_array($table, ['admins', 'tokens', 'ip_rules', 'ua_rules', 'settings', 'access_logs',
        'tracking_groups', 'tracking_assignments', 'tracking_entry_mappings', 'tracking_transform_events'], true)) {
        throw new InvalidArgumentException('Unexpected test table');
    }
    return (int) $pdo->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
}

function remove_test_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            rmdir($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }
    rmdir($path);
}

/** @return array{process:resource,pipes:array<int,resource>} */
function spawn_test_worker(string $script, array $arguments = []): array
{
    $command = [PHP_BINARY, $script, ...$arguments];
    $process = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to launch PHP test worker');
    }
    fclose($pipes[0]);
    return ['process' => $process, 'pipes' => $pipes];
}

function worker_output_excerpt(string|false $output): string
{
    $text = (string) $output;
    foreach (['TOKEN_HMAC_KEY', 'TOKEN_ENCRYPTION_KEY', 'ADMIN_PASSWORD'] as $name) {
        $secret = getenv($name);
        if (is_string($secret) && $secret !== '') {
            $text = str_replace($secret, '[REDACTED]', $text);
        }
    }
    $text = preg_replace('/(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/i', '[REDACTED_TOKEN]', $text) ?? '';
    $truncated = strlen($text) > 2048;
    $encoded = json_encode(substr($text, 0, 2048), JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
    return ($encoded === false ? '"[unavailable]"' : $encoded) . ($truncated ? ' (truncated)' : '');
}

function finish_test_worker(array $worker): string
{
    $output = stream_get_contents($worker['pipes'][1]);
    $errors = stream_get_contents($worker['pipes'][2]);
    fclose($worker['pipes'][1]);
    fclose($worker['pipes'][2]);
    $code = proc_close($worker['process']);
    if ($code !== 0) {
        throw new RuntimeException('PHP test worker failed: exit=' . $code
            . ', stdout=' . worker_output_excerpt($output)
            . ', stderr=' . worker_output_excerpt($errors));
    }
    return trim((string) $output);
}

$databasePath = $dataDirectory . DIRECTORY_SEPARATOR . 'main.db';
$pdo = open_database($databasePath);

test_case('empty database initialization creates core and tracking tables', function () use ($pdo): void {
    initialize_database($pdo);
    $statement = $pdo->prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    );
    $statement->execute();
    $tables = array_column($statement->fetchAll(), 'name');
    expect_same(['access_logs', 'admins', 'ip_rules', 'settings', 'tokens', 'tracking_assignments',
        'tracking_entry_mappings', 'tracking_groups', 'tracking_transform_events', 'ua_rules'], $tables);
});

test_case('user_version is five and initialization is idempotent', function () use ($pdo): void {
    expect_same(5, (int) $pdo->query('PRAGMA user_version')->fetchColumn());
    setting_set($pdo, 'idempotence_probe', 'preserved');
    initialize_database($pdo);
    expect_same('preserved', setting_get($pdo, 'idempotence_probe'));
});

test_case('SQLite runtime PRAGMAs are enabled', function () use ($pdo): void {
    expect_same('wal', strtolower((string) $pdo->query('PRAGMA journal_mode')->fetchColumn()));
    expect_same(1, (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn());
    expect_same(5000, (int) $pdo->query('PRAGMA busy_timeout')->fetchColumn());
    expect_same(1, (int) $pdo->query('PRAGMA synchronous')->fetchColumn());
});

test_case('64-bit PHP is required', function (): void {
    expect_true(PHP_INT_SIZE >= 8);
    require_64bit_php();
});

test_case('administrator password is hashed and verified', function () use ($pdo): void {
    $password = 'Correct-Horse-Battery-42';
    create_admin($pdo, 'admin_test', $password);
    $statement = $pdo->prepare('SELECT password_hash FROM admins WHERE username = :username');
    $statement->execute([':username' => 'admin_test']);
    $stored = (string) $statement->fetchColumn();
    expect_true($stored !== $password);
    expect_true(password_verify($password, $stored));
    expect_same('admin_test', authenticate_admin($pdo, 'admin_test', $password)['username'] ?? null);
    expect_same(null, authenticate_admin($pdo, 'admin_test', 'wrong-password-value'));
});

test_case('Token HMAC is stable and does not equal plaintext', function (): void {
    $token = '0123456789abcdef0123456789abcdef';
    expect_same(token_hash_value($token), token_hash_value($token));
    expect_true(token_hash_value($token) !== $token);
    expect_same(64, strlen(token_hash_value($token)));
});

test_case('missing, placeholder and short keys are rejected', function (): void {
    $original = getenv('TOKEN_HMAC_KEY');
    putenv('TOKEN_HMAC_KEY');
    expect_exception(static fn () => decode_app_key('TOKEN_HMAC_KEY'), RuntimeException::class);
    putenv('TOKEN_HMAC_KEY=CHANGE_ME_BASE64_32_BYTES');
    expect_exception(static fn () => decode_app_key('TOKEN_HMAC_KEY'), RuntimeException::class);
    putenv('TOKEN_HMAC_KEY=' . base64_encode('too-short'));
    expect_exception(static fn () => decode_app_key('TOKEN_HMAC_KEY'), RuntimeException::class);
    putenv('TOKEN_HMAC_KEY=' . $original);
});

test_case('Token encryption round trip succeeds', function (): void {
    $token = '0123456789abcdef0123456789abcdef';
    $encrypted = encrypt_token($token);
    expect_true(!str_contains($encrypted, $token));
    expect_same($token, decrypt_token($encrypted));
});

test_case('wrong Token encryption key cannot decrypt', function (): void {
    $encrypted = encrypt_token('0123456789abcdef0123456789abcdef');
    expect_exception(
        static fn () => decrypt_token_with_key($encrypted, str_repeat('W', 32)),
        RuntimeException::class
    );
});

test_case('Token plaintext is not stored in SQLite', function () use ($pdo, $databasePath): void {
    $token = 'fedcba9876543210fedcba9876543210';
    save_token($pdo, $token, 'NORMAL');
    foreach ([$databasePath, $databasePath . '-wal', $databasePath . '-shm'] as $path) {
        if (is_file($path)) {
            expect_true(!str_contains((string) file_get_contents($path), $token), "Plaintext Token found in {$path}");
        }
    }
    $statement = $pdo->prepare('SELECT token_hash, token_encrypted FROM tokens WHERE token_hash = :token_hash');
    $statement->execute([':token_hash' => token_hash_value($token)]);
    $row = $statement->fetch();
    expect_true(is_array($row));
    expect_true($row['token_hash'] !== $token && $row['token_encrypted'] !== $token);
});

test_case('non-temporary Token states clear expires_at', function () use ($pdo): void {
    $token = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    $id = save_token($pdo, $token, 'TEMP_BLOCKED', time() + 600);
    save_token($pdo, $token, 'WHITELIST', time() + 9999);
    $statement = $pdo->prepare('SELECT state, expires_at FROM tokens WHERE id = :id');
    $statement->execute([':id' => $id]);
    $row = $statement->fetch();
    expect_same('WHITELIST', $row['state']);
    expect_same(null, $row['expires_at']);
});

test_case('SQL data input cannot change schema', function () use ($pdo): void {
    add_ua_rule($pdo, "curl'); DROP TABLE tokens;--", 'BLACKLIST');
    expect_same(1, (int) $pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'tokens'")->fetchColumn());
});

test_case('CSRF accepts exact token and rejects wrong token', function (): void {
    start_admin_session();
    $token = csrf_token();
    expect_true(verify_csrf_token($token));
    expect_true(!verify_csrf_token($token . 'x'));
    $_SERVER['HTTP_X_CSRF_TOKEN'] = $token . 'x';
    expect_exception(static fn () => require_csrf(), HttpError::class);
    unset($_SERVER['HTTP_X_CSRF_TOKEN']);
});

test_case('unauthenticated Admin access is rejected', function (): void {
    unset($_SESSION['admin_id'], $_SESSION['admin_username']);
    expect_exception(static fn () => require_authentication(), HttpError::class);
});

test_case('wrong Secret Path is rejected', function (): void {
    expect_exception(static fn () => resolve_admin_route('/wrong/api/session'), HttpError::class);
    expect_same('/api/session', resolve_admin_route('/test_secret_path_123456/api/session?x=1'));
});

test_case('direct PHP access is blocked by Admin Nginx', function () use ($root): void {
    $nginx = (string) file_get_contents($root . '/sgw/admin/nginx.conf');
    expect_true((bool) preg_match('/location\s+~\s+\\\.php\$\s*\{\s*return\s+404;/s', $nginx));
    expect_true(str_contains($nginx, 'fastcgi_param SCRIPT_FILENAME /app/src/index.php;'));
});

test_case('successful login rotates the Session ID', function () use ($pdo): void {
    $before = session_id();
    $admin = authenticate_admin($pdo, 'admin_test', 'Correct-Horse-Battery-42');
    expect_true(is_array($admin));
    complete_login_session($admin);
    expect_true(session_id() !== '' && session_id() !== $before);
    expect_true(is_authenticated());
});

test_case('Session cookie attributes are secure', function (): void {
    $options = session_cookie_options();
    expect_same(true, $options['secure']);
    expect_same(true, $options['httponly']);
    expect_same('Strict', $options['samesite']);
    expect_same(1, (int) ini_get('session.use_strict_mode'));
});

test_case('login rate limiter blocks repeated failures and clears on success', function () use ($pdo): void {
    $ip = '192.0.2.77';
    clear_login_failures($ip);
    for ($index = 0; $index < LOGIN_MAX_FAILURES; $index++) {
        expect_same(null, authenticate_admin_rate_limited($pdo, $ip, 'admin_test', 'wrong-password-value'));
    }
    expect_exception(
        static fn () => authenticate_admin_rate_limited($pdo, $ip, 'admin_test', 'wrong-password-value'),
        HttpError::class
    );
    clear_login_failures($ip);
    expect_true(is_array(authenticate_admin_rate_limited($pdo, $ip, 'admin_test', 'Correct-Horse-Battery-42')));
});

test_case('Origin must match Host when present', function (): void {
    $_SERVER['HTTP_HOST'] = 'admin.example.test';
    $_SERVER['HTTP_ORIGIN'] = 'https://admin.example.test';
    validate_origin_and_host();
    $_SERVER['HTTP_HOST'] = 'admin.example.test:8443';
    $_SERVER['HTTP_ORIGIN'] = 'https://admin.example.test:8443';
    validate_origin_and_host();
    $_SERVER['HTTP_HOST'] = 'admin.example.test:443';
    $_SERVER['HTTP_ORIGIN'] = 'https://admin.example.test';
    validate_origin_and_host();
    $_SERVER['HTTP_HOST'] = 'admin.example.test:8443';
    $_SERVER['HTTP_ORIGIN'] = 'https://evil.example.test';
    expect_exception(static fn () => validate_origin_and_host(), HttpError::class);
    $_SERVER['HTTP_ORIGIN'] = 'https://admin.example.test:8443/path';
    expect_exception(static fn () => validate_origin_and_host(), HttpError::class);
    unset($_SERVER['HTTP_HOST'], $_SERVER['HTTP_ORIGIN']);
});

test_case('IPv4 validation and CIDR canonicalization work', function (): void {
    expect_same('1.2.3.4/32', parse_ipv4_network('1.2.3.4')['network']);
    $network = parse_ipv4_network('1.2.3.7/24');
    expect_same('1.2.3.0/24', $network['network']);
    expect_same(16909056, $network['start']);
    expect_same(16909311, $network['end']);
    expect_same(['network' => '0.0.0.0/0', 'start' => 0, 'end' => 4294967295, 'prefix' => 0], parse_ipv4_network('1.2.3.4/0'));
    expect_same(['network' => '255.255.255.255/32', 'start' => 4294967295, 'end' => 4294967295, 'prefix' => 32], parse_ipv4_network('255.255.255.255/32'));
});

test_case('invalid IPv4, CIDR and IPv6 are rejected', function (): void {
    foreach (['999.999.999.999', '1.2.3.4/999', '1.2.3', 'deadbeef', '2001:db8::1'] as $input) {
        expect_exception(static fn () => parse_ipv4_network($input), InvalidArgumentException::class);
    }
});

test_case('overlapping IP white and black rules are rejected', function () use ($pdo): void {
    add_ip_rule($pdo, '10.10.0.0/16', 'WHITELIST');
    expect_exception(
        static fn () => add_ip_rule($pdo, '10.10.2.0/24', 'BLACKLIST'),
        DomainException::class
    );
});

test_case('UA input is stored as plain text and rejects controls', function () use ($pdo): void {
    $id = add_ua_rule($pdo, 'curl.*literal', 'BLACKLIST');
    expect_true($id > 0);
    $statement = $pdo->prepare('SELECT pattern FROM ua_rules WHERE id = :id');
    $statement->execute([':id' => $id]);
    expect_same('curl.*literal', $statement->fetchColumn());
    expect_exception(static fn () => validate_ua_pattern("bad\nua"), InvalidArgumentException::class);
});

test_case('Rate settings enforce safe integer ranges', function (): void {
    expect_same([true, 20, 5], validate_rate_settings(true, 20, 5));
    expect_exception(static fn () => validate_rate_settings(true, 0, 5), InvalidArgumentException::class);
    expect_exception(static fn () => validate_rate_settings(true, 20, -1), InvalidArgumentException::class);
    expect_exception(static fn () => validate_rate_settings('not-bool', 20, 5), InvalidArgumentException::class);
    foreach (['false', 'true', 0, 1, null] as $value) {
        expect_exception(static fn () => validate_rate_settings($value, 20, 5), InvalidArgumentException::class);
    }
    expect_exception(static fn () => validate_rate_settings(true, '20', 5), InvalidArgumentException::class);
    expect_exception(static fn () => validate_rate_settings(true, 20, 10001), InvalidArgumentException::class);
});

test_case('Rate request requires every field and JSON boolean', function (): void {
    foreach (['rate_enabled', 'rate_per_minute', 'rate_burst'] as $missing) {
        $body = ['rate_enabled' => true, 'rate_per_minute' => 20, 'rate_burst' => 5];
        unset($body[$missing]);
        expect_exception(static fn () => validate_rate_request_body($body), InvalidArgumentException::class);
    }
    expect_exception(
        static fn () => validate_rate_request_body(['rate_enabled' => 'false', 'rate_per_minute' => 20, 'rate_burst' => 5]),
        InvalidArgumentException::class
    );
    expect_same([false, 20, 5], validate_rate_request_body(decode_json_object('{"rate_enabled":false,"rate_per_minute":20,"rate_burst":5}')));
});

test_case('top-level JSON array is rejected', function (): void {
    expect_exception(static fn () => decode_json_object('[1,2,3]'), HttpError::class);
    expect_exception(static fn () => decode_json_object('null'), HttpError::class);
});

test_case('rule and version changes roll back together', function () use ($pdo): void {
    $before = (int) setting_get($pdo, 'config_version');
    expect_exception(static function () use ($pdo): void {
        write_transaction($pdo, static function () use ($pdo): void {
            add_ip_rule($pdo, '192.0.2.0/24', 'BLACKLIST');
            bump_config_version($pdo);
            throw new RuntimeException('Simulated failure');
        });
    }, RuntimeException::class);
    expect_same($before, (int) setting_get($pdo, 'config_version'));
    expect_same(0, (int) $pdo->query("SELECT COUNT(*) FROM ip_rules WHERE network = '192.0.2.0/24'")->fetchColumn());
    write_transaction($pdo, static function () use ($pdo): void {
        add_ip_rule($pdo, '192.0.2.0/24', 'BLACKLIST');
        bump_config_version($pdo);
    });
    expect_same($before + 1, (int) setting_get($pdo, 'config_version'));
});

test_case('duplicate and overlapping IP rules are conflicts', function () use ($pdo): void {
    expect_exception(static fn () => add_ip_rule($pdo, '192.0.2.0/24', 'BLACKLIST'), DomainException::class);
    expect_exception(static fn () => add_ip_rule($pdo, '192.0.2.10/32', 'WHITELIST'), DomainException::class);
});

test_case('UA case variants are one rule across both actions', function () use ($pdo): void {
    add_ua_rule($pdo, 'curl', 'BLACKLIST');
    expect_exception(static fn () => add_ua_rule($pdo, 'CURL', 'BLACKLIST'), DomainException::class);
    expect_exception(static fn () => add_ua_rule($pdo, 'CuRl', 'WHITELIST'), DomainException::class);
});

test_case('Rate update increments version once and commits together', function () use ($pdo): void {
    $before = (int) setting_get($pdo, 'config_version');
    save_rate_settings($pdo, false, 99, 7);
    expect_same($before + 1, (int) setting_get($pdo, 'config_version'));
    expect_same('0', setting_get($pdo, 'rate_enabled'));
    expect_same('99', setting_get($pdo, 'rate_per_minute'));
    expect_same('7', setting_get($pdo, 'rate_burst'));
});

test_case('expired login rate file is removed, live file remains', function () use ($rateDirectory): void {
    $oldIp = '192.0.2.221';
    $liveIp = '192.0.2.222';
    clear_login_failures($oldIp);
    clear_login_failures($liveIp);
    $oldPath = login_rate_file($oldIp);
    $livePath = login_rate_file($liveIp);
    touch($oldPath, time() - LOGIN_WINDOW_SECONDS - 7200);
    expect_true(cleanup_login_rate_files($rateDirectory) >= 1);
    expect_true(!file_exists($oldPath));
    expect_true(file_exists($livePath));
});

test_case('login rate directory and files use restricted permissions', function () use ($rateDirectory): void {
    $path = login_rate_file('192.0.2.245');
    expect_true(!str_contains(basename($path), '192.0.2.245'));
    clear_login_failures('192.0.2.245');
    expect_true(is_file($path));
    if (PHP_OS_FAMILY !== 'Windows') {
        expect_same(0, fileperms($rateDirectory) & 0027);
        expect_same(0600, fileperms($path) & 0777);
    }
});

test_case('parallel version increments do not lose updates', function () use ($pdo, $temporaryRoot, $root): void {
    $script = $temporaryRoot . DIRECTORY_SEPARATOR . 'increment-worker.php';
    file_put_contents($script, '<?php require ' . var_export($root . '/sgw/admin/src/db.php', true)
        . '; $db = app_db(); for ($i = 0; $i < 20; $i++) {'
        . ' write_transaction($db, static function () use ($db): void { bump_config_version($db); }); }');
    $before = (int) setting_get($pdo, 'config_version');
    $workers = [];
    for ($index = 0; $index < 3; $index++) {
        $workers[] = spawn_test_worker($script);
    }
    foreach ($workers as $worker) {
        finish_test_worker($worker);
    }
    expect_same($before + 60, (int) setting_get($pdo, 'config_version'));
});

test_case('parallel overlapping IP white and black additions cannot both commit', function () use ($pdo, $temporaryRoot, $root): void {
    $script = $temporaryRoot . DIRECTORY_SEPARATOR . 'ip-worker.php';
    $barrier = $temporaryRoot . DIRECTORY_SEPARATOR . 'ip-start';
    file_put_contents($script, '<?php require ' . var_export($root . '/sgw/admin/src/rules.php', true)
        . '; while (!is_file($argv[3])) { usleep(1000); }'
        . ' try { add_ip_rule(app_db(), $argv[2], $argv[1]); echo "OK"; }'
        . ' catch (DomainException $error) { echo "CONFLICT"; }');
    $workers = [
        spawn_test_worker($script, ['WHITELIST', '198.18.0.0/16', $barrier]),
        spawn_test_worker($script, ['BLACKLIST', '198.18.1.0/24', $barrier]),
    ];
    file_put_contents($barrier, 'go');
    $results = array_map('finish_test_worker', $workers);
    sort($results);
    expect_same(['CONFLICT', 'OK'], $results);
    expect_same(1, (int) $pdo->query('SELECT COUNT(*) FROM ip_rules WHERE network_start <= 3323068673 AND network_end >= 3323068673')->fetchColumn());
});

test_case('parallel login failures are counted atomically', function () use ($temporaryRoot, $root): void {
    $script = $temporaryRoot . DIRECTORY_SEPARATOR . 'login-worker.php';
    $barrier = $temporaryRoot . DIRECTORY_SEPARATOR . 'login-start';
    $ip = '192.0.2.244';
    clear_login_failures($ip);
    file_put_contents($script, '<?php require ' . var_export($root . '/sgw/admin/src/api.php', true)
        . '; while (!is_file($argv[1])) { usleep(1000); }'
        . ' try { authenticate_admin_rate_limited(app_db(), $argv[2], "admin_test", "wrong-password-value"); echo "FAIL"; }'
        . ' catch (HttpError $error) { echo $error->status === 429 ? "LIMIT" : "OTHER"; }');
    $workers = [];
    for ($index = 0; $index < 8; $index++) {
        $workers[] = spawn_test_worker($script, [$barrier, $ip]);
    }
    file_put_contents($barrier, 'go');
    $results = array_map('finish_test_worker', $workers);
    expect_same(5, count(array_filter($results, static fn ($value): bool => $value === 'FAIL')));
    expect_same(3, count(array_filter($results, static fn ($value): bool => $value === 'LIMIT')));
});

test_case('logout destroys authenticated Session data', function (): void {
    destroy_admin_session();
    expect_true(!is_authenticated());
});

require __DIR__ . '/phase2.php';
require __DIR__ . '/phase3.php';
require __DIR__ . '/schema_fixture_helpers.php';
require __DIR__ . '/phase4.php';
require __DIR__ . '/installation.php';
require __DIR__ . '/admin_workflow.php';
require __DIR__ . '/mapping_json.php';
require __DIR__ . '/subscription_metadata.php';
require __DIR__ . '/flexible_splits.php';
require __DIR__ . '/binary_splits.php';
require __DIR__ . '/schema_v4.php';
require __DIR__ . '/source_lifecycle.php';
require __DIR__ . '/partial_delivery.php';
require __DIR__ . '/schema_v5.php';
require __DIR__ . '/tracking_ui.php';

if ($failed === 0) {
    echo "PASS: {$passed} tests\n";
} else {
    echo "FAIL: {$failed} of " . ($passed + $failed) . " tests failed\n";
    foreach ($failures as $failure) {
        echo " - {$failure}\n";
    }
}

$pdo = null;
gc_collect_cycles();
remove_test_tree($temporaryRoot);
exit($failed === 0 ? 0 : 1);
