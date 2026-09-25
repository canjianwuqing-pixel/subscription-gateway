<?php

declare(strict_types=1);

const DATABASE_SCHEMA_VERSION = 1;

function env_required(string $name): string
{
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        throw new RuntimeException("Missing required environment variable: {$name}");
    }
    return trim($value);
}

function env_bool(string $name, bool $default): bool
{
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        return $default;
    }
    $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($parsed === null) {
        throw new RuntimeException("Invalid boolean environment variable: {$name}");
    }
    return $parsed;
}

function decode_app_key(string $name): string
{
    $encoded = env_required($name);
    if (str_starts_with($encoded, 'CHANGE_ME')) {
        throw new RuntimeException("{$name} still contains an example placeholder");
    }
    $decoded = base64_decode($encoded, true);
    if ($decoded === false || strlen($decoded) !== 32) {
        throw new RuntimeException("{$name} must be Base64 for exactly 32 bytes");
    }
    return $decoded;
}

/** @return array<string, mixed> */
function app_config(): array
{
    static $config = null;
    if ($config !== null) {
        return $config;
    }

    if (!extension_loaded('pdo_sqlite') || !extension_loaded('sodium')) {
        throw new RuntimeException('Admin requires PDO SQLite and Sodium extensions');
    }
    require_64bit_php();

    $secretPath = env_required('ADMIN_SECRET_PATH');
    if (!preg_match('/^[A-Za-z0-9_-]{12,128}$/D', $secretPath)) {
        throw new RuntimeException('ADMIN_SECRET_PATH must be one URL-safe segment of 12-128 characters');
    }
    if (str_starts_with($secretPath, 'CHANGE_ME')) {
        throw new RuntimeException('ADMIN_SECRET_PATH still contains an example placeholder');
    }

    $sessionName = getenv('SESSION_NAME') ?: 'subscription_gateway_session';
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $sessionName)) {
        throw new RuntimeException('SESSION_NAME is invalid');
    }

    $config = [
        'database_path' => env_required('DATABASE_PATH'),
        'admin_secret_path' => $secretPath,
        'session_name' => $sessionName,
        'session_cookie_secure' => env_bool('SESSION_COOKIE_SECURE', true),
        'token_hmac_key' => decode_app_key('TOKEN_HMAC_KEY'),
        'token_encryption_key' => decode_app_key('TOKEN_ENCRYPTION_KEY'),
        'login_rate_dir' => trim((string) (getenv('LOGIN_RATE_DIR') ?: '/tmp/subscription-gateway-login-rate')),
    ];

    if (hash_equals($config['token_hmac_key'], $config['token_encryption_key'])) {
        throw new RuntimeException('TOKEN_HMAC_KEY and TOKEN_ENCRYPTION_KEY must be different');
    }

    return $config;
}

function require_64bit_php(): void
{
    if (PHP_INT_SIZE < 8) {
        throw new RuntimeException('Only 64-bit PHP is supported.');
    }
}

function open_database(string $path): PDO
{
    $directory = dirname($path);
    if (!is_dir($directory) || !is_writable($directory)) {
        throw new RuntimeException('SQLite data directory is missing or not writable');
    }

    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA synchronous=NORMAL');
    $pdo->exec('PRAGMA foreign_keys=ON');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $expected = [
        'journal_mode' => 'wal',
        'synchronous' => 1,
        'foreign_keys' => 1,
        'busy_timeout' => 5000,
    ];
    foreach ($expected as $pragma => $value) {
        $actual = $pdo->query('PRAGMA ' . $pragma)->fetchColumn();
        if (($pragma === 'journal_mode' ? strtolower((string) $actual) : (int) $actual) !== $value) {
            throw new RuntimeException('SQLite PRAGMA could not be enabled: ' . $pragma);
        }
    }
    return $pdo;
}

function app_db(): PDO
{
    static $pdo = null;
    if (!$pdo instanceof PDO) {
        $pdo = open_database((string) app_config()['database_path']);
        initialize_database($pdo);
    }
    return $pdo;
}

function initialize_database(PDO $pdo): void
{
    $version = (int) $pdo->query('PRAGMA user_version')->fetchColumn();
    if ($version > DATABASE_SCHEMA_VERSION) {
        throw new RuntimeException('Database schema is newer than this application');
    }
    if ($version === DATABASE_SCHEMA_VERSION) {
        return;
    }

    $pdo->beginTransaction();
    try {
        if ($version === 0) {
            $pdo->exec(<<<'SQL'
CREATE TABLE admins (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_encrypted BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'NORMAL'
        CHECK (state IN ('NORMAL', 'WHITELIST', 'BLOCKED', 'TEMP_BLOCKED')),
    expires_at INTEGER,
    note TEXT NOT NULL DEFAULT '',
    first_seen INTEGER,
    last_seen INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (
        (state = 'TEMP_BLOCKED' AND expires_at IS NOT NULL)
        OR
        (state != 'TEMP_BLOCKED' AND expires_at IS NULL)
    )
);

CREATE TABLE ip_rules (
    id INTEGER PRIMARY KEY,
    network TEXT NOT NULL UNIQUE,
    network_start INTEGER NOT NULL,
    network_end INTEGER NOT NULL,
    prefix_length INTEGER NOT NULL CHECK (prefix_length BETWEEN 0 AND 32),
    action TEXT NOT NULL CHECK (action IN ('WHITELIST', 'BLACKLIST')),
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    CHECK (network_start >= 0 AND network_end >= network_start AND network_end <= 4294967295)
);

CREATE TABLE ua_rules (
    id INTEGER PRIMARY KEY,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('WHITELIST', 'BLACKLIST')),
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (pattern, action)
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY,
    token_id INTEGER,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    request_path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    request_time_ms INTEGER,
    upstream_status INTEGER,
    decision TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE SET NULL
);

CREATE INDEX idx_tokens_state ON tokens(state);
CREATE INDEX idx_tokens_last_seen ON tokens(last_seen);
CREATE INDEX idx_access_logs_token_created ON access_logs(token_id, created_at);
CREATE INDEX idx_access_logs_ip_created ON access_logs(client_ip, created_at);
CREATE INDEX idx_access_logs_ua_created ON access_logs(user_agent, created_at);
CREATE INDEX idx_access_logs_created ON access_logs(created_at);
SQL);

            $defaults = [
                'subscribe_path_template' => '/api/v1/{segment}/subscribe',
                'token_query_key' => 'token',
                'token_format_profile' => 'v2board_guid_v1',
                'rate_enabled' => '1',
                'rate_per_minute' => '20',
                'rate_burst' => '5',
                'config_version' => '0',
            ];
            $statement = $pdo->prepare(
                'INSERT INTO settings (key, value, updated_at) VALUES (:key, :value, :updated_at)'
            );
            $now = time();
            foreach ($defaults as $key => $value) {
                $statement->execute([':key' => $key, ':value' => $value, ':updated_at' => $now]);
            }

            $pdo->exec('PRAGMA user_version=1');
        }
        $pdo->commit();
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }
}

function setting_get(PDO $pdo, string $key, ?string $default = null): ?string
{
    $statement = $pdo->prepare('SELECT value FROM settings WHERE key = :key');
    $statement->execute([':key' => $key]);
    $value = $statement->fetchColumn();
    return $value === false ? $default : (string) $value;
}

function setting_set(PDO $pdo, string $key, string $value): void
{
    $statement = $pdo->prepare(<<<'SQL'
INSERT INTO settings (key, value, updated_at)
VALUES (:key, :value, :updated_at)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
SQL);
    $statement->execute([':key' => $key, ':value' => $value, ':updated_at' => time()]);
}

function bump_config_version(PDO $pdo): int
{
    $statement = $pdo->prepare(<<<'SQL'
INSERT INTO settings (key, value, updated_at) VALUES ('config_version', '1', :updated_at)
ON CONFLICT(key) DO UPDATE SET
    value = CAST(settings.value AS INTEGER) + 1,
    updated_at = excluded.updated_at
SQL);
    $statement->execute([':updated_at' => time()]);
    return (int) setting_get($pdo, 'config_version', '0');
}

function write_transaction(PDO $pdo, callable $callback): mixed
{
    static $active = null;
    $active ??= new WeakMap();
    if (isset($active[$pdo]) || $pdo->inTransaction()) {
        return $callback();
    }
    $pdo->exec('BEGIN IMMEDIATE');
    $active[$pdo] = true;
    try {
        $result = $callback();
        $pdo->exec('COMMIT');
        return $result;
    } catch (Throwable $error) {
        $pdo->exec('ROLLBACK');
        throw $error;
    } finally {
        unset($active[$pdo]);
    }
}

function preferred_password_algorithm(): string|int|null
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
}

function password_hash_secure(string $password): string
{
    if (strlen($password) < 12 || strlen($password) > 1024) {
        throw new InvalidArgumentException('Password must contain 12-1024 bytes');
    }
    $hash = password_hash($password, preferred_password_algorithm());
    if ($hash === false) {
        throw new RuntimeException('Password hashing failed');
    }
    return $hash;
}

function admin_count(PDO $pdo): int
{
    return (int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
}

function create_admin(PDO $pdo, string $username, string $password): int
{
    $username = trim($username);
    if (!preg_match('/^[A-Za-z0-9_.-]{3,64}$/D', $username)) {
        throw new InvalidArgumentException('Administrator username is invalid');
    }
    return insert_admin_hash($pdo, $username, password_hash_secure($password));
}

function insert_admin_hash(PDO $pdo, string $username, string $passwordHash): int
{
    if (!preg_match('/^[A-Za-z0-9_.-]{3,64}$/D', $username)) {
        throw new InvalidArgumentException('Administrator username is invalid');
    }
    if (password_get_info($passwordHash)['algoName'] === 'unknown') {
        throw new InvalidArgumentException('Administrator password hash is invalid');
    }
    $now = time();
    $statement = $pdo->prepare(
        'INSERT INTO admins (username, password_hash, created_at, updated_at) '
        . 'VALUES (:username, :password_hash, :created_at, :updated_at)'
    );
    $statement->execute([
        ':username' => $username,
        ':password_hash' => $passwordHash,
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);
    return (int) $pdo->lastInsertId();
}

/** @return array{id:int,username:string}|null */
function authenticate_admin(PDO $pdo, string $username, string $password): ?array
{
    $statement = $pdo->prepare('SELECT id, username, password_hash FROM admins WHERE username = :username');
    $statement->execute([':username' => trim($username)]);
    $row = $statement->fetch();

    if (!is_array($row)) {
        password_verify($password, password_hash(bin2hex(random_bytes(24)), PASSWORD_DEFAULT));
        return null;
    }
    if (!password_verify($password, (string) $row['password_hash'])) {
        return null;
    }

    if (password_needs_rehash((string) $row['password_hash'], preferred_password_algorithm())) {
        $update = $pdo->prepare(
            'UPDATE admins SET password_hash = :password_hash, updated_at = :updated_at WHERE id = :id'
        );
        $update->execute([
            ':password_hash' => password_hash_secure($password),
            ':updated_at' => time(),
            ':id' => (int) $row['id'],
        ]);
    }

    return ['id' => (int) $row['id'], 'username' => (string) $row['username']];
}
