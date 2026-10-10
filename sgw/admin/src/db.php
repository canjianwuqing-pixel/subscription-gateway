<?php

declare(strict_types=1);

const DATABASE_SCHEMA_VERSION = 4;
const TRACKING_ALGORITHM_VERSION = 1;

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

function tracking_group_key(): string
{
    return hash_hmac(
        'sha256',
        'subscription-gateway/tracking-group-key/v1',
        (string) app_config()['token_hmac_key'],
        true
    );
}

function tracking_child_number(string $tokenHash, int $parentGroupId, int $childCount = 3): int
{
    if (!preg_match('/^[0-9a-f]{64}$/D', $tokenHash) || $parentGroupId < 1 || $childCount < 2 || $childCount > 20) {
        throw new InvalidArgumentException('Invalid tracking assignment input');
    }
    $digest = hash_hmac(
        'sha256',
        'parent:' . $parentGroupId . "\0" . $tokenHash,
        tracking_group_key(),
        true
    );
    $number = unpack('Nvalue', substr($digest, 0, 4));
    if (!is_array($number)) {
        throw new RuntimeException('Unable to calculate tracking assignment');
    }
    return ((int) $number['value'] % $childCount) + 1;
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

    // SQLite's table-rebuild migration requires FK enforcement disabled BEFORE
    // the transaction. Check all relationships before commit and restore it below.
    if ($pdo->inTransaction()) {
        throw new RuntimeException('Database migration requires its own transaction');
    }
    $pdo->exec('PRAGMA foreign_keys=OFF');
    try {
        $pdo->beginTransaction();
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
            $version = 1;
        }
        if ($version === 1) {
            $pdo->exec('ALTER TABLE admins ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1');
            $statement = $pdo->prepare('INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (:key, :value, :time)');
            $statement->execute([':key' => 'log_retention_days', ':value' => '30', ':time' => time()]);
            $pdo->exec('PRAGMA user_version=2');
            $version = 2;
        }
        if ($version === 2) {
            $pdo->exec(<<<'SQL'
CREATE TABLE tracking_groups (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    child_no INTEGER NOT NULL,
    path TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'ARCHIVED')),
    split_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES tracking_groups(id) ON DELETE RESTRICT,
    UNIQUE (parent_id, child_no),
    CHECK (
        (parent_id IS NULL AND child_no = 0 AND path = 'root')
        OR
        (parent_id IS NOT NULL AND child_no BETWEEN 1 AND 3)
    )
);

CREATE TABLE tracking_assignments (
    token_hash TEXT PRIMARY KEY,
    group_id INTEGER NOT NULL,
    algorithm_version INTEGER NOT NULL CHECK (algorithm_version >= 1),
    assigned_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES tracking_groups(id) ON DELETE RESTRICT,
    CHECK (length(token_hash) = 64)
);

CREATE TABLE tracking_entry_mappings (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL,
    source_host TEXT NOT NULL COLLATE NOCASE,
    target_host TEXT COLLATE NOCASE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES tracking_groups(id) ON DELETE CASCADE,
    UNIQUE (group_id, source_host)
);

CREATE TABLE tracking_transform_events (
    id INTEGER PRIMARY KEY,
    group_id INTEGER,
    mode TEXT NOT NULL CHECK (mode IN ('preflight', 'enforced')),
    format TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES tracking_groups(id) ON DELETE SET NULL
);

CREATE INDEX idx_tracking_assignments_group ON tracking_assignments(group_id);
CREATE INDEX idx_tracking_mappings_group ON tracking_entry_mappings(group_id);
CREATE INDEX idx_tracking_events_created ON tracking_transform_events(created_at);
CREATE INDEX idx_tracking_events_group_created ON tracking_transform_events(group_id, created_at);
SQL);
            $now = time();
            $group = $pdo->prepare(
                'INSERT INTO tracking_groups (id, parent_id, child_no, path, status, created_at, updated_at) '
                . 'VALUES (:id, :parent_id, :child_no, :path, :status, :created_at, :updated_at)'
            );
            $group->execute([':id' => 1, ':parent_id' => null, ':child_no' => 0, ':path' => 'root',
                ':status' => 'ACTIVE', ':created_at' => $now, ':updated_at' => $now]);
            foreach ([1 => 2, 2 => 3, 3 => 4] as $childNo => $id) {
                $group->execute([':id' => $id, ':parent_id' => 1, ':child_no' => $childNo,
                    ':path' => (string) $childNo, ':status' => 'ACTIVE',
                    ':created_at' => $now, ':updated_at' => $now]);
            }
            $setting = $pdo->prepare(
                'INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (:key, :value, :updated_at)'
            );
            foreach (['tracking_mode' => 'off', 'tracking_algorithm_version' => '1'] as $key => $value) {
                $setting->execute([':key' => $key, ':value' => $value, ':updated_at' => $now]);
            }
            $assignment = $pdo->prepare(<<<'SQL'
INSERT INTO tracking_assignments
    (token_hash, group_id, algorithm_version, assigned_at, updated_at)
VALUES (:token_hash, :group_id, :algorithm_version, :assigned_at, :updated_at)
SQL);
            foreach ($pdo->query('SELECT token_hash FROM tokens ORDER BY id') as $token) {
                $childNo = tracking_child_number((string) $token['token_hash'], 1);
                $assignment->execute([
                    ':token_hash' => (string) $token['token_hash'],
                    ':group_id' => $childNo + 1,
                    ':algorithm_version' => TRACKING_ALGORITHM_VERSION,
                    ':assigned_at' => $now,
                    ':updated_at' => $now,
                ]);
            }
            $pdo->exec('PRAGMA user_version=3');
            $version = 3;
        }
        if ($version === 3) {
            $pdo->exec(<<<'SQL'
CREATE TABLE tracking_groups_v4 (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    child_no INTEGER NOT NULL,
    path TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'ARCHIVED')),
    split_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES tracking_groups(id) ON DELETE RESTRICT,
    UNIQUE (parent_id, child_no),
    CHECK (
        (parent_id IS NULL AND child_no = 0 AND path = 'root')
        OR
        (parent_id IS NOT NULL AND child_no >= 1)
    )
);
INSERT INTO tracking_groups_v4
    (id, parent_id, child_no, path, status, split_at, created_at, updated_at)
SELECT id, parent_id, child_no, path, status, split_at, created_at, updated_at FROM tracking_groups;
DROP TABLE tracking_groups;
ALTER TABLE tracking_groups_v4 RENAME TO tracking_groups;
SQL);
            if ($pdo->query('PRAGMA foreign_key_check')->fetchAll() !== []
                || $pdo->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN) !== ['ok']) {
                throw new RuntimeException('Database migration integrity check failed');
            }
            $pdo->exec('PRAGMA user_version=4');
        }
        $pdo->commit();
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    } finally {
        $pdo->exec('PRAGMA foreign_keys=ON');
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
    if (strlen($password) < 6 || strlen($password) > 1024) {
        throw new InvalidArgumentException('密码长度必须为6至1024字节');
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
    $statement = $pdo->prepare('SELECT id, username, password_hash, auth_version FROM admins WHERE username = :username');
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

    return ['id' => (int) $row['id'], 'username' => (string) $row['username'],
        'auth_version' => (int) $row['auth_version']];
}

function change_admin_password(PDO $pdo, int $id, string $current, string $replacement): int
{
    if (strlen($replacement) < 6 || strlen($replacement) > 1024) {
        throw new InvalidArgumentException('新密码长度必须为6至1024字节');
    }
    return write_transaction($pdo, static function () use ($pdo, $id, $current, $replacement): int {
        $query = $pdo->prepare('SELECT password_hash FROM admins WHERE id = :id');
        $query->execute([':id' => $id]);
        $old = $query->fetchColumn();
        if (!is_string($old) || !password_verify($current, $old)) {
            throw new DomainException('当前密码不正确');
        }
        $update = $pdo->prepare('UPDATE admins SET password_hash = :hash, auth_version = auth_version + 1, '
            . 'updated_at = :updated WHERE id = :id');
        $update->execute([':hash' => password_hash_secure($replacement), ':updated' => time(), ':id' => $id]);
        $version = $pdo->prepare('SELECT auth_version FROM admins WHERE id = :id');
        $version->execute([':id' => $id]);
        return (int) $version->fetchColumn();
    });
}
