<?php

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

const SUBSCRIBE_TEMPLATE_V1 = '/api/v1/{segment}/subscribe';

function validate_upstream_url(string $url): array
{
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
        || !in_array($parts['scheme'], ['http', 'https'], true)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['path'])
        || isset($parts['query']) || isset($parts['fragment'])
    ) {
        throw new InvalidArgumentException('upstream_url must be an HTTP(S) origin without path, query or credentials');
    }
    $host = (string) $parts['host'];
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
        && (strlen($host) > 253 || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
    ) {
        throw new InvalidArgumentException('upstream_url host is invalid');
    }
    $port = $parts['port'] ?? null;
    if ($port !== null && ($port < 1 || $port > 65535)) {
        throw new InvalidArgumentException('upstream_url port is invalid');
    }
    return [
        'url' => strtolower((string) $parts['scheme']) . '://' . strtolower($host)
            . ($port === null ? '' : ':' . $port),
        'host' => strtolower($host),
    ];
}

function validate_gateway_settings(array $settings): array
{
    $upstream = validate_upstream_url((string) ($settings['upstream_url'] ?? ''));
    if (($settings['subscribe_path_template'] ?? null) !== SUBSCRIBE_TEMPLATE_V1) {
        throw new InvalidArgumentException('Unsupported subscribe_path_template');
    }
    $tokenKey = $settings['token_query_key'] ?? null;
    if (!is_string($tokenKey) || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,31}$/D', $tokenKey)) {
        throw new InvalidArgumentException('Invalid token_query_key');
    }
    if (($settings['token_format_profile'] ?? null) !== 'v2board_guid_v1') {
        throw new InvalidArgumentException('Unsupported token_format_profile');
    }
    $enabled = $settings['rate_enabled'] ?? null;
    if (!in_array($enabled, ['0', '1'], true)) {
        throw new InvalidArgumentException('Invalid rate_enabled');
    }
    $rate = $settings['rate_per_minute'] ?? null;
    $burst = $settings['rate_burst'] ?? null;
    if (!is_string($rate) || !preg_match('/^[1-9][0-9]*$/D', $rate)
        || !is_string($burst) || !preg_match('/^(0|[1-9][0-9]*)$/D', $burst)
    ) {
        throw new InvalidArgumentException('Invalid rate settings');
    }
    [$rateEnabled, $rateValue, $burstValue] = validate_rate_settings($enabled === '1', (int) $rate, (int) $burst);
    return [
        'upstream_url' => $upstream['url'],
        'upstream_host' => $upstream['host'],
        'subscribe_path_template' => SUBSCRIBE_TEMPLATE_V1,
        'token_query_key' => $tokenKey,
        'token_format_profile' => 'v2board_guid_v1',
        'rate_enabled' => $rateEnabled,
        'rate_per_minute' => $rateValue,
        'rate_burst' => $burstValue,
    ];
}

function gateway_settings(PDO $pdo): array
{
    $rows = $pdo->query('SELECT key, value FROM settings')->fetchAll(PDO::FETCH_KEY_PAIR);
    return validate_gateway_settings($rows);
}

function nginx_quoted(string $value): string
{
    if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
        throw new InvalidArgumentException('Nginx value contains control characters');
    }
    return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
}

function compile_gateway_rules(PDO $pdo): array
{
    $settings = gateway_settings($pdo);
    $lines = [
        '# Generated from SQLite. Do not edit.',
        'map "" $gateway_ready { default 1; }',
        'map "" $gateway_upstream { default ' . nginx_quoted($settings['upstream_url']) . '; }',
        'map "" $gateway_upstream_host { default ' . nginx_quoted($settings['upstream_host']) . '; }',
        'map $arg_' . $settings['token_query_key'] . ' $token_valid {',
        '    default 0;',
        '    "~^[0-9a-f]{32}$" 1;',
        '}',
        'map $args $token_query_duplicate {',
        '    default 0;',
        '    ' . nginx_quoted('~*(?:^|&)' . preg_quote($settings['token_query_key'])
            . '(?:=[^&]*)?(?:&[^&]*)*&' . preg_quote($settings['token_query_key']) . '(?:=|&|$)') . ' 1;',
        '}',
        'map $args $token_query_unsafe { default 0; "~;|(?:^|&)[^=&%]*%" 1; }',
        'map "$token_valid:$token_query_duplicate:$token_query_unsafe" $token_event_loggable '
            . '{ default 0; "1:0:0" 1; }',
        'log_format token_events escape=json',
        '    ' . nginx_quoted('{"time":$msec,"token":"$arg_' . $settings['token_query_key']
            . '","ip":"$remote_addr","ua":"$http_user_agent","status":$status,'
            . '"path":"$uri","policy":"$log_decision"}') . ';',
        'map $arg_' . $settings['token_query_key'] . ' $token_state {',
        '    default NORMAL;',
    ];
    $ignoredTemp = 0;
    $tokens = $pdo->query('SELECT token_encrypted, state, expires_at FROM tokens ORDER BY token_hash')->fetchAll();
    foreach ($tokens as $row) {
        $state = (string) $row['state'];
        if ($state === 'TEMP_BLOCKED') {
            $expiresAt = (int) $row['expires_at'];
            if ($expiresAt <= time()) {
                $ignoredTemp++;
                continue;
            }
            $token = decrypt_token((string) $row['token_encrypted']);
            validate_token_format($token);
            $lines[] = '    # SGW_TEMP_BLOCK ' . $expiresAt . ' ' . $token;
            $lines[] = '    ' . $token . ' TEMP_BLOCKED;';
            continue;
        }
        if (!in_array($state, ['BLOCKED', 'WHITELIST'], true)) {
            continue;
        }
        $token = decrypt_token((string) $row['token_encrypted']);
        validate_token_format($token);
        $lines[] = '    ' . $token . ' ' . $state . ';';
    }
    $lines[] = '}';
    $lines[] = 'geo $ip_state {';
    $lines[] = '    default NORMAL;';
    foreach ($pdo->query('SELECT network, action FROM ip_rules ORDER BY network_start, prefix_length') as $row) {
        $network = (string) $row['network'];
        if (parse_ipv4_network($network)['network'] !== $network
            || !in_array($row['action'], ['BLACKLIST', 'WHITELIST'], true)
        ) {
            throw new RuntimeException('Invalid IP rule in SQLite');
        }
        $lines[] = '    ' . $network . ' ' . $row['action'] . ';';
    }
    $lines[] = '}';
    foreach (['WHITELIST' => 'ua_whitelisted', 'BLACKLIST' => 'ua_blacklisted'] as $action => $variable) {
        $lines[] = 'map $http_user_agent $' . $variable . ' {';
        $lines[] = '    default 0;';
        $stmt = $pdo->prepare('SELECT pattern FROM ua_rules WHERE action = :action ORDER BY lower(pattern)');
        $stmt->execute([':action' => $action]);
        foreach ($stmt as $row) {
            $pattern = validate_ua_pattern((string) $row['pattern']);
            $lines[] = '    ' . nginx_quoted('~*' . preg_quote($pattern)) . ' 1;';
        }
        $lines[] = '}';
    }
    array_push($lines,
        'map "$token_state:$ip_state:$ua_whitelisted:$ua_blacklisted" $policy_reason {',
        '    default PASS;',
        '    ~^BLOCKED: TOKEN_BLOCKED;',
        '    ~^TEMP_BLOCKED: TOKEN_TEMP_BLOCKED;',
        '    ~^[^:]+:BLACKLIST: IP_BLACKLIST;',
        '    ~^WHITELIST: TOKEN_WHITELIST;',
        '    ~^[^:]+:WHITELIST: IP_WHITELIST;',
        '    ~^[^:]+:[^:]+:1: UA_WHITELIST;',
        '    ~^[^:]+:[^:]+:0:1$ UA_BLACKLIST;',
        '}',
        'map "$limit_req_status:$policy_reason" $log_decision {',
        '    default $policy_reason;',
        '    ~^REJECTED: RATE_LIMIT;',
        '}',
        'map $policy_reason $policy_block {',
        '    default 0;',
        '    TOKEN_BLOCKED 1;',
        '    TOKEN_TEMP_BLOCKED 1;',
        '    IP_BLACKLIST 1;',
        '    UA_BLACKLIST 1;',
        '}',
        'map $policy_reason $strong_allow {',
        '    default 0;',
        '    TOKEN_WHITELIST 1;',
        '    IP_WHITELIST 1;',
        '}',
        'map $strong_allow $rate_key {',
        '    default ' . ($settings['rate_enabled'] ? '$binary_remote_addr' : '""') . ';',
        '    1 "";',
        '}',
        'limit_req_zone $rate_key zone=subscription_rate:10m rate=' . $settings['rate_per_minute'] . 'r/m;',
        'limit_req zone=subscription_rate'
            . ($settings['rate_burst'] > 0 ? ' burst=' . $settings['rate_burst'] : '') . ' nodelay;',
        'limit_req_status 429;'
    );
    return ['rules' => implode("\n", $lines) . "\n", 'ignored_temp_blocked' => $ignoredTemp];
}
