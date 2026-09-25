<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';

const TOKEN_AEAD_AAD = 'subscription-gateway:token:v1';
const RATE_PER_MINUTE_MAX = 10000;
const RATE_BURST_MAX = 10000;

function validate_rule_note(string $note): string
{
    $note = trim($note);
    if (strlen($note) > 500 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $note)) {
        throw new InvalidArgumentException('Rule note is invalid');
    }
    return $note;
}

function token_hash_value(string $token): string
{
    return hash_hmac('sha256', $token, app_config()['token_hmac_key']);
}

function encrypt_token_with_key(string $token, string $key): string
{
    if (strlen($key) !== 32) {
        throw new InvalidArgumentException('Token encryption key must contain exactly 32 bytes');
    }
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $token,
        TOKEN_AEAD_AAD,
        $nonce,
        $key
    );
    return 'v1:' . base64_encode($nonce . $ciphertext);
}

function encrypt_token(string $token): string
{
    return encrypt_token_with_key($token, app_config()['token_encryption_key']);
}

function decrypt_token_with_key(string $encrypted, string $key): string
{
    if (strlen($key) !== 32 || !str_starts_with($encrypted, 'v1:')) {
        throw new RuntimeException('Invalid token encryption payload');
    }
    $payload = base64_decode(substr($encrypted, 3), true);
    $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    if ($payload === false || strlen($payload) <= $nonceLength) {
        throw new RuntimeException('Invalid token encryption payload');
    }

    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        substr($payload, $nonceLength),
        TOKEN_AEAD_AAD,
        substr($payload, 0, $nonceLength),
        $key
    );
    if ($plaintext === false) {
        throw new RuntimeException('Token authentication failed');
    }
    return $plaintext;
}

function decrypt_token(string $encrypted): string
{
    return decrypt_token_with_key($encrypted, app_config()['token_encryption_key']);
}

function validate_token_format(string $token, string $profile = 'v2board_guid_v1'): void
{
    if ($profile !== 'v2board_guid_v1') {
        throw new InvalidArgumentException('Unsupported token format profile');
    }
    if (!preg_match('/^[0-9a-f]{32}$/D', $token)) {
        throw new InvalidArgumentException('Token must be 32 lowercase hexadecimal characters');
    }
}

function validate_token_state(string $state, ?int $expiresAt): array
{
    $allowed = ['NORMAL', 'WHITELIST', 'BLOCKED', 'TEMP_BLOCKED'];
    if (!in_array($state, $allowed, true)) {
        throw new InvalidArgumentException('Invalid token state');
    }
    if ($state === 'TEMP_BLOCKED') {
        if ($expiresAt === null || $expiresAt <= time()) {
            throw new InvalidArgumentException('TEMP_BLOCKED requires a future expires_at');
        }
    } else {
        $expiresAt = null;
    }
    return [$state, $expiresAt];
}

function save_token(
    PDO $pdo,
    string $token,
    string $state = 'NORMAL',
    ?int $expiresAt = null,
    string $note = ''
): int {
    validate_token_format($token, setting_get($pdo, 'token_format_profile', 'v2board_guid_v1'));
    [$state, $expiresAt] = validate_token_state($state, $expiresAt);
    $note = validate_rule_note($note);

    $hash = token_hash_value($token);
    $now = time();
    $statement = $pdo->prepare(<<<'SQL'
INSERT INTO tokens (
    token_hash, token_encrypted, state, expires_at, note,
    first_seen, last_seen, request_count, created_at, updated_at
) VALUES (
    :token_hash, :token_encrypted, :state, :expires_at, :note,
    :first_seen, :last_seen, 0, :created_at, :updated_at
)
ON CONFLICT(token_hash) DO UPDATE SET
    state = excluded.state,
    expires_at = excluded.expires_at,
    note = excluded.note,
    updated_at = excluded.updated_at
SQL);
    $statement->execute([
        ':token_hash' => $hash,
        ':token_encrypted' => encrypt_token($token),
        ':state' => $state,
        ':expires_at' => $expiresAt,
        ':note' => $note,
        ':first_seen' => null,
        ':last_seen' => null,
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);

    $lookup = $pdo->prepare('SELECT id FROM tokens WHERE token_hash = :token_hash');
    $lookup->execute([':token_hash' => $hash]);
    return (int) $lookup->fetchColumn();
}

/** @return list<array<string, mixed>> */
function list_tokens_for_admin(PDO $pdo, int $limit = 100): array
{
    $limit = max(1, min(500, $limit));
    $statement = $pdo->prepare(
        'SELECT id, token_encrypted, state, expires_at, note, first_seen, last_seen, '
        . 'request_count, created_at, updated_at FROM tokens ORDER BY updated_at DESC LIMIT :limit'
    );
    $statement->bindValue(':limit', $limit, PDO::PARAM_INT);
    $statement->execute();

    $rows = [];
    while ($row = $statement->fetch()) {
        $expiresAt = $row['expires_at'] === null ? null : (int) $row['expires_at'];
        $effectiveState = (string) $row['state'];
        if ($effectiveState === 'TEMP_BLOCKED' && $expiresAt !== null && $expiresAt <= time()) {
            $effectiveState = 'NORMAL';
        }
        $rows[] = [
            'id' => (int) $row['id'],
            'token' => decrypt_token((string) $row['token_encrypted']),
            'state' => $effectiveState,
            'stored_state' => (string) $row['state'],
            'expires_at' => $expiresAt,
            'note' => (string) $row['note'],
            'first_seen' => $row['first_seen'] === null ? null : (int) $row['first_seen'],
            'last_seen' => $row['last_seen'] === null ? null : (int) $row['last_seen'],
            'request_count' => (int) $row['request_count'],
            'created_at' => (int) $row['created_at'],
            'updated_at' => (int) $row['updated_at'],
        ];
    }
    return $rows;
}

/** @return array{network:string,start:int,end:int,prefix:int} */
function parse_ipv4_network(string $input): array
{
    $input = trim($input);
    if ($input === '' || str_contains($input, ':')) {
        throw new InvalidArgumentException('Only IPv4 and IPv4 CIDR are supported');
    }
    $parts = explode('/', $input, 2);
    $ip = $parts[0];
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new InvalidArgumentException('Invalid IPv4 address');
    }

    $prefix = 32;
    if (isset($parts[1])) {
        if ($parts[1] === '' || !preg_match('/^(?:[0-9]|[12][0-9]|3[0-2])$/D', $parts[1])) {
            throw new InvalidArgumentException('IPv4 CIDR prefix must be between 0 and 32');
        }
        $prefix = (int) $parts[1];
    }

    $packed = inet_pton($ip);
    $unpacked = $packed === false ? false : unpack('Naddress', $packed);
    if ($unpacked === false) {
        throw new InvalidArgumentException('Invalid IPv4 address');
    }
    $address = (int) $unpacked['address'];
    $mask = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
    $start = $address & $mask;
    $end = $start | ((~$mask) & 0xFFFFFFFF);
    $canonicalIp = inet_ntop(pack('N', $start));
    if ($canonicalIp === false) {
        throw new RuntimeException('Unable to canonicalize IPv4 network');
    }
    return [
        'network' => $canonicalIp . '/' . $prefix,
        'start' => $start,
        'end' => $end,
        'prefix' => $prefix,
    ];
}

function add_ip_rule(PDO $pdo, string $network, string $action, string $note = ''): int
{
    if (!in_array($action, ['WHITELIST', 'BLACKLIST'], true)) {
        throw new InvalidArgumentException('Invalid IP rule action');
    }
    $parsed = parse_ipv4_network($network);
    $note = validate_rule_note($note);
    return write_transaction($pdo, static function () use ($pdo, $parsed, $action, $note): int {
        $conflict = $pdo->prepare(<<<'SQL'
SELECT network, action
FROM ip_rules
WHERE network_start <= :network_end
  AND network_end >= :network_start
LIMIT 1
SQL);
        $conflict->execute([
            ':network_end' => $parsed['end'],
            ':network_start' => $parsed['start'],
        ]);
        $existing = $conflict->fetch();
        if (is_array($existing)) {
            throw new DomainException("IP rule conflicts with {$existing['action']} {$existing['network']}");
        }

        $statement = $pdo->prepare(<<<'SQL'
INSERT INTO ip_rules (
    network, network_start, network_end, prefix_length, action, note, created_at
) VALUES (
    :network, :network_start, :network_end, :prefix_length, :action, :note, :created_at
)
SQL);
        $statement->execute([
            ':network' => $parsed['network'],
            ':network_start' => $parsed['start'],
            ':network_end' => $parsed['end'],
            ':prefix_length' => $parsed['prefix'],
            ':action' => $action,
            ':note' => $note,
            ':created_at' => time(),
        ]);
        return (int) $pdo->lastInsertId();
    });
}

/** @return list<array<string, mixed>> */
function list_ip_rules(PDO $pdo): array
{
    $statement = $pdo->prepare(
        'SELECT id, network, action, note, created_at FROM ip_rules ORDER BY action, network_start'
    );
    $statement->execute();
    return $statement->fetchAll();
}

function validate_ua_pattern(string $pattern): string
{
    $pattern = trim($pattern);
    if ($pattern === '' || strlen($pattern) > 256) {
        throw new InvalidArgumentException('UA pattern must contain 1-256 bytes');
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $pattern)) {
        throw new InvalidArgumentException('UA pattern contains control characters');
    }
    return $pattern;
}

function add_ua_rule(PDO $pdo, string $pattern, string $action, string $note = ''): int
{
    if (!in_array($action, ['WHITELIST', 'BLACKLIST'], true)) {
        throw new InvalidArgumentException('Invalid UA rule action');
    }
    $pattern = validate_ua_pattern($pattern);
    $note = validate_rule_note($note);
    $comparisonPattern = strtolower($pattern);
    return write_transaction($pdo, static function () use ($pdo, $pattern, $comparisonPattern, $action, $note): int {
        $conflict = $pdo->prepare('SELECT pattern, action FROM ua_rules WHERE lower(pattern) = :pattern LIMIT 1');
        $conflict->execute([':pattern' => $comparisonPattern]);
        $existing = $conflict->fetch();
        if (is_array($existing)) {
            throw new DomainException("UA rule conflicts with {$existing['action']} {$existing['pattern']}");
        }
        $statement = $pdo->prepare(
            'INSERT INTO ua_rules (pattern, action, note, created_at) '
            . 'VALUES (:pattern, :action, :note, :created_at)'
        );
        $statement->execute([
            ':pattern' => $pattern,
            ':action' => $action,
            ':note' => $note,
            ':created_at' => time(),
        ]);
        return (int) $pdo->lastInsertId();
    });
}

/** @return list<array<string, mixed>> */
function list_ua_rules(PDO $pdo): array
{
    $statement = $pdo->prepare(
        'SELECT id, pattern, action, note, created_at FROM ua_rules ORDER BY action, pattern'
    );
    $statement->execute();
    return $statement->fetchAll();
}

function validate_rate_settings(mixed $enabled, mixed $rate, mixed $burst): array
{
    if (!is_bool($enabled)) {
        throw new InvalidArgumentException('rate_enabled must be boolean');
    }
    if (!is_int($rate) || $rate < 1 || $rate > RATE_PER_MINUTE_MAX) {
        throw new InvalidArgumentException('rate_per_minute must be between 1 and ' . RATE_PER_MINUTE_MAX);
    }
    if (!is_int($burst) || $burst < 0 || $burst > RATE_BURST_MAX) {
        throw new InvalidArgumentException('rate_burst must be between 0 and ' . RATE_BURST_MAX);
    }
    return [$enabled, $rate, $burst];
}

function save_rate_settings(PDO $pdo, mixed $enabled, mixed $rate, mixed $burst): void
{
    [$enabledValue, $rateValue, $burstValue] = validate_rate_settings($enabled, $rate, $burst);
    write_transaction($pdo, static function () use ($pdo, $enabledValue, $rateValue, $burstValue): void {
        setting_set($pdo, 'rate_enabled', $enabledValue ? '1' : '0');
        setting_set($pdo, 'rate_per_minute', (string) $rateValue);
        setting_set($pdo, 'rate_burst', (string) $burstValue);
        bump_config_version($pdo);
    });
}

function delete_rule_by_id(PDO $pdo, string $table, int $id): void
{
    if (!in_array($table, ['ip_rules', 'ua_rules'], true)) {
        throw new InvalidArgumentException('Unsupported rule table');
    }
    $statement = $pdo->prepare("DELETE FROM {$table} WHERE id = :id");
    $statement->execute([':id' => $id]);
}
