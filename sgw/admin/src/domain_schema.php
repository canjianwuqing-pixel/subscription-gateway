<?php
declare(strict_types=1);

function migrate_domain_schema(PDO $pdo): void
{
    $pdo->exec(<<<'SQL'
CREATE TABLE cloudflare_credentials (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
 token_encrypted TEXT NOT NULL, token_last4 TEXT NOT NULL,
 zone_id TEXT NOT NULL, zone_name TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 last_tested_at INTEGER, last_test_ok INTEGER CHECK(last_test_ok IN (0,1)), last_error TEXT
);
CREATE TABLE gateway_domains (
 id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT NOT NULL UNIQUE COLLATE NOCASE,
 role TEXT NOT NULL CHECK(role IN ('PRIMARY','ALIAS')),
 status TEXT NOT NULL CHECK(status IN ('PENDING','ACTIVE','ERROR','REMOVING')),
 credential_id INTEGER REFERENCES cloudflare_credentials(id) ON DELETE RESTRICT,
 certificate_path TEXT NOT NULL, expires_at INTEGER, last_error TEXT,
 next_check_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 CHECK(role='ALIAS' OR (status='ACTIVE' AND credential_id IS NULL AND certificate_path='/ssl/active')),
 CHECK(role='PRIMARY' OR credential_id IS NOT NULL)
);
CREATE UNIQUE INDEX gateway_one_primary ON gateway_domains(role) WHERE role='PRIMARY';
CREATE TRIGGER gateway_keep_primary BEFORE DELETE ON gateway_domains WHEN OLD.role='PRIMARY'
 BEGIN SELECT RAISE(ABORT,'Primary domain cannot be deleted'); END;
CREATE TABLE certificate_jobs (
 domain_id INTEGER PRIMARY KEY REFERENCES gateway_domains(id) ON DELETE CASCADE,
 operation TEXT NOT NULL CHECK(operation IN ('ISSUE','RENEW','REMOVE')),
 state TEXT NOT NULL CHECK(state IN ('PENDING','RUNNING','RETRY','DONE')),
 previous_status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_retry_at INTEGER NOT NULL DEFAULT 0, last_error TEXT,
 release TEXT, previous_release TEXT, request_id TEXT, request_sha TEXT,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
SQL);
    $fqdn = strtolower(env_required('GATEWAY_DOMAIN'));
    if (strlen($fqdn) > 253 || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/D', $fqdn)) {
        throw new RuntimeException('Invalid primary domain');
    }
    $query = $pdo->prepare("INSERT INTO gateway_domains(fqdn,role,status,certificate_path,created_at,updated_at) VALUES (?,'PRIMARY','ACTIVE','/ssl/active',?,?)");
    $query->execute([$fqdn, time(), time()]);
    if ($pdo->query('PRAGMA foreign_key_check')->fetchAll() !== []
        || $pdo->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN) !== ['ok']) {
        throw new RuntimeException('Database migration integrity check failed');
    }
}
