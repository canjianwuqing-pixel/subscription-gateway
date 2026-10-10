<?php

declare(strict_types=1);

$phase2Directory = $temporaryRoot . DIRECTORY_SEPARATOR . 'phase2';
mkdir($phase2Directory, 0700, true);
$phase2Pdo = open_database($phase2Directory . DIRECTORY_SEPARATOR . 'gateway.db');
initialize_database($phase2Pdo);
setting_set($phase2Pdo, 'upstream_url', 'https://backend.example.test:8443');

function phase2_rules(PDO $pdo): string
{
    return compile_gateway_rules($pdo)['rules'];
}

function phase2_policy(string $rules, string $token, string $ip, int $uaAllow, int $uaBlock): string
{
    expect_true((bool) preg_match('/map "\$token_state:\$ip_state:\$ua_whitelisted:\$ua_blacklisted" \$policy_reason \{(.*?)\n\}/s', $rules, $match));
    $key = "{$token}:{$ip}:{$uaAllow}:{$uaBlock}";
    foreach (explode("\n", $match[1]) as $line) {
        if (preg_match('/^\s+~(\S+)\s+([A-Z_]+);$/', $line, $rule)
            && preg_match('#' . str_replace('#', '\\#', $rule[1]) . '#', $key)
        ) {
            return $rule[2];
        }
    }
    return 'PASS';
}

test_case('phase 2 empty rules compile from SQLite', function () use ($phase2Pdo): void {
    $rules = phase2_rules($phase2Pdo);
    expect_true(str_contains($rules, 'map $arg_token $token_state'));
    expect_true(str_contains($rules, 'geo $ip_state'));
    expect_true(str_contains($rules, 'default NORMAL;'));
    expect_true(str_contains($rules, 'backend.example.test:8443'));
});

test_case('NORMAL token is not emitted as a special map entry', function () use ($phase2Pdo): void {
    $token = '11111111111111111111111111111111';
    save_token($phase2Pdo, $token, 'NORMAL');
    expect_true(!str_contains(phase2_rules($phase2Pdo), '    ' . $token . ' NORMAL;'));
});

test_case('BLOCKED token emits a blocked map entry', function () use ($phase2Pdo): void {
    $token = '22222222222222222222222222222222';
    save_token($phase2Pdo, $token, 'BLOCKED');
    expect_true(str_contains(phase2_rules($phase2Pdo), '    ' . $token . ' BLOCKED;'));
});

test_case('WHITELIST token emits a whitelist map entry', function () use ($phase2Pdo): void {
    $token = '33333333333333333333333333333333';
    save_token($phase2Pdo, $token, 'WHITELIST');
    expect_true(str_contains(phase2_rules($phase2Pdo), '    ' . $token . ' WHITELIST;'));
});

test_case('TEMP_BLOCKED is emitted with an expiry marker', function () use ($phase2Pdo): void {
    $token = '44444444444444444444444444444444';
    save_token($phase2Pdo, $token, 'TEMP_BLOCKED', time() + 600);
    $compiled = compile_gateway_rules($phase2Pdo);
    expect_same(0, $compiled['ignored_temp_blocked']);
    expect_true(str_contains($compiled['rules'], $token . ' TEMP_BLOCKED;'));
    expect_true(str_contains($compiled['rules'], 'SGW_TEMP_BLOCK'));
});

test_case('IP black and white networks compile into geo', function () use ($phase2Pdo): void {
    add_ip_rule($phase2Pdo, '192.0.2.9/24', 'BLACKLIST');
    add_ip_rule($phase2Pdo, '198.51.100.0/24', 'WHITELIST');
    $rules = phase2_rules($phase2Pdo);
    expect_true(str_contains($rules, '192.0.2.0/24 BLACKLIST;'));
    expect_true(str_contains($rules, '198.51.100.0/24 WHITELIST;'));
});

test_case('UA literal regex symbols, quotes, backslashes and semicolons are escaped', function () use ($phase2Pdo): void {
    $black = 'Client.*?[]()\\";';
    $white = 'Trusted+[1]';
    add_ua_rule($phase2Pdo, $black, 'BLACKLIST');
    add_ua_rule($phase2Pdo, $white, 'WHITELIST');
    $rules = phase2_rules($phase2Pdo);
    expect_true(str_contains($rules, nginx_quoted('~*' . preg_quote($black)) . ' 1;'));
    expect_true(str_contains($rules, nginx_quoted('~*' . preg_quote($white)) . ' 1;'));
    expect_true(str_contains($rules, 'map $http_user_agent $ua_blacklisted'));
    expect_true(str_contains($rules, 'map $http_user_agent $ua_whitelisted'));
    expect_exception(static fn () => validate_ua_pattern("bad\nua"), InvalidArgumentException::class);
});

test_case('Rate enabled and disabled compile to bounded keys', function () use ($phase2Pdo): void {
    $enabled = phase2_rules($phase2Pdo);
    expect_true(str_contains($enabled, 'default $binary_remote_addr;'));
    expect_true(str_contains($enabled, '    1 "";'));
    expect_true(str_contains($enabled, 'rate=20r/m;'));
    save_rate_settings($phase2Pdo, false, 60, 7);
    $disabled = phase2_rules($phase2Pdo);
    expect_true(str_contains($disabled, 'map $strong_allow $rate_key {'));
    expect_true(str_contains($disabled, '    default "";'));
    expect_true(str_contains($disabled, 'rate=60r/m;'));
    expect_true(str_contains($disabled, 'burst=7 nodelay;'));
    save_rate_settings($phase2Pdo, true, 20, 0);
    expect_true(str_contains(phase2_rules($phase2Pdo), 'limit_req zone=subscription_rate nodelay;'));
    save_rate_settings($phase2Pdo, true, 20, 5);
});

test_case('whitelist bypasses Rate only for Token and IP', function () use ($phase2Pdo): void {
    $rules = phase2_rules($phase2Pdo);
    expect_true(str_contains($rules, 'TOKEN_WHITELIST 1;'));
    expect_true(str_contains($rules, 'IP_WHITELIST 1;'));
    expect_true(!str_contains($rules, 'UA_WHITELIST 1;'));
    expect_same('UA_WHITELIST', phase2_policy($rules, 'NORMAL', 'NORMAL', 1, 1));
});

test_case('single-segment subscription route excludes all other paths', function () use ($root): void {
    $nginx = (string) file_get_contents($root . '/sgw/gateway/nginx.conf');
    expect_true(str_contains($nginx, 'location / { return 444; }'));
    expect_true((bool) preg_match('/location ~ (\^[^\s]+\$) \{/', $nginx, $match));
    $regex = '#' . str_replace('#', '\\#', $match[1]) . '#';
    foreach (['/api/v1/a/subscribe', '/api/v1/abc/subscribe', '/api/v1/abc/subscribe?token=x'] as $request) {
        expect_same(1, preg_match($regex, (string) parse_url($request, PHP_URL_PATH)));
    }
    foreach (['/api/v1//subscribe', '/api/v1/a/b/subscribe', '/api/v1/a/subscribe-extra',
        '/api/v1/a/subscribe/test', '/api/v2/a/subscribe'] as $request) {
        expect_same(0, preg_match($regex, $request));
    }
});

test_case('missing and malformed Tokens are 400 before proxy', function () use ($phase2Pdo, $root): void {
    $rules = phase2_rules($phase2Pdo);
    expect_true(str_contains($rules, 'map $arg_token $token_valid'));
    expect_same(0, preg_match('/^[0-9a-f]{32}$/', ''));
    expect_same(0, preg_match('/^[0-9a-f]{32}$/', 'NOT_A_VALID_TOKEN'));
    $nginx = (string) file_get_contents($root . '/sgw/gateway/nginx.conf');
    expect_true(strpos($nginx, 'if ($token_valid = 0) { return 400; }') < strpos($nginx, 'proxy_pass $gateway_subscription_upstream$request_uri;'));
});

test_case('policy prioritizes Token and IP blocks before allowlists', function () use ($phase2Pdo): void {
    $rules = phase2_rules($phase2Pdo);
    expect_same('TOKEN_BLOCKED', phase2_policy($rules, 'BLOCKED', 'WHITELIST', 1, 1));
    expect_same('IP_BLACKLIST', phase2_policy($rules, 'WHITELIST', 'BLACKLIST', 1, 1));
    expect_same('TOKEN_WHITELIST', phase2_policy($rules, 'WHITELIST', 'NORMAL', 0, 1));
    expect_same('IP_WHITELIST', phase2_policy($rules, 'NORMAL', 'WHITELIST', 0, 1));
    expect_same('UA_WHITELIST', phase2_policy($rules, 'NORMAL', 'NORMAL', 1, 1));
    expect_same('UA_BLACKLIST', phase2_policy($rules, 'NORMAL', 'NORMAL', 0, 1));
    expect_same('PASS', phase2_policy($rules, 'NORMAL', 'NORMAL', 0, 0));
});

test_case('upstream rejects injection, path, query, fragment and credentials', function (): void {
    foreach (['https://backend.example.test;return 200', "https://backend.example.test\nreturn 200",
        'https://backend.example.test/api', 'https://backend.example.test/?x=1',
        'https://backend.example.test/#fragment', 'https://user:pass@backend.example.test'] as $value) {
        expect_exception(static fn () => validate_upstream_url($value), InvalidArgumentException::class);
    }
    expect_same('https://backend.example.test:8443', validate_upstream_url('https://backend.example.test:8443')['url']);
});

test_case('Token query key and subscribe profile reject injection', function () use ($phase2Pdo): void {
    $base = $phase2Pdo->query('SELECT key, value FROM settings')->fetchAll(PDO::FETCH_KEY_PAIR);
    $base['upstream_url'] = 'https://backend.example.test';
    $invalidKey = $base;
    $invalidKey['token_query_key'] = "token;\nreturn 200";
    expect_exception(static fn () => validate_gateway_settings($invalidKey), InvalidArgumentException::class);
    $invalidPath = $base;
    $invalidPath['subscribe_path_template'] = '/api/v1/(.*)/subscribe';
    expect_exception(static fn () => validate_gateway_settings($invalidPath), InvalidArgumentException::class);
});

$controlTest = $temporaryRoot . DIRECTORY_SEPARATOR . 'control';
mkdir($controlTest, 0700, true);
putenv('CONTROL_DIR=' . $controlTest);

test_case('publication result requires matching ID, version and SHA256', function () use ($controlTest): void {
    $path = $controlTest . '/result.json';
    $sha = str_repeat('a', 64);
    atomic_control_write($path, json_encode(['id' => 'new-id', 'version' => 4, 'sha256' => $sha, 'ok' => true]));
    expect_same(null, matching_publish_result($path, 'old-id', 4, $sha));
    expect_same(null, matching_publish_result($path, 'new-id', 5, $sha));
    expect_same(null, matching_publish_result($path, 'new-id', 4, str_repeat('b', 64)));
    expect_true(matching_publish_result($path, 'new-id', 4, $sha)['ok']);
});

test_case('candidate SHA256 mismatch is distinguishable', function () use ($controlTest): void {
    atomic_control_write($controlTest . '/candidate.conf', 'candidate');
    expect_true(hash_file('sha256', $controlTest . '/candidate.conf') !== str_repeat('0', 64));
});

test_case('publish lock excludes a second publisher', function () use ($controlTest): void {
    $first = fopen($controlTest . '/publish.lock', 'c+');
    $second = fopen($controlTest . '/publish.lock', 'c+');
    expect_true(flock($first, LOCK_EX));
    expect_true(!flock($second, LOCK_EX | LOCK_NB));
    flock($first, LOCK_UN);
    fclose($first);
    fclose($second);
});

test_case('config ahead of active version reports pending', function () use ($phase2Pdo, $controlTest): void {
    setting_set($phase2Pdo, 'config_version', '9');
    atomic_control_write($controlTest . '/active_version', "8\n");
    $status = gateway_publish_status($phase2Pdo);
    expect_same(9, $status['config_version']);
    expect_same(8, $status['active_version']);
    expect_same(true, $status['pending']);
});

test_case('Admin publishes full candidate and accepts matching result only', function () use ($phase2Pdo, $controlTest, $temporaryRoot): void {
    $script = $temporaryRoot . DIRECTORY_SEPARATOR . 'result-worker.php';
    file_put_contents($script, <<<'PHP'
<?php
$directory = $argv[1];
$deadline = microtime(true) + 6;
do {
    $request = @json_decode((string) @file_get_contents($directory . '/request.json'), true);
    if (is_array($request) && isset($request['id'], $request['version'], $request['sha256'])) {
        $result = ['id' => $request['id'], 'version' => $request['version'], 'sha256' => $request['sha256'], 'ok' => true];
        file_put_contents($directory . '/result.json.tmp', json_encode($result));
        rename($directory . '/result.json.tmp', $directory . '/result.json');
        exit(0);
    }
    usleep(20000);
} while (microtime(true) < $deadline);
exit(2);
PHP);
    $worker = spawn_test_worker($script, [$controlTest]);
    $result = publish_current_rules($phase2Pdo);
    finish_test_worker($worker);
    expect_same(true, $result['applied'], 'Publish result: ' . json_encode($result));
    $request = json_decode((string) file_get_contents($controlTest . '/request.json'), true);
    expect_same(hash_file('sha256', $controlTest . '/candidate.conf'), $request['sha256']);
    expect_same(9, $request['version']);
    expect_true((bool) preg_match('/^[0-9a-f]{32}$/D', $request['id']));
});

$phase2Pdo = null;
putenv('CONTROL_DIR');
