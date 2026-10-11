<?php
declare(strict_types=1);

/** Test-only downgrade; never run against a deployment database. */
function schema_remove_v7_fixture(PDO $db): void
{
    $db->exec('DROP TABLE IF EXISTS certificate_jobs; DROP TRIGGER IF EXISTS gateway_keep_primary; DROP TABLE IF EXISTS gateway_domains; DROP TABLE IF EXISTS cloudflare_credentials;');
}

function schema_remove_v5_fixture(PDO $db): void
{
    schema_remove_v7_fixture($db);
    $db->exec('DROP TABLE tracking_sources');
    $db->exec('DROP TABLE tracking_source_snapshots');
    foreach (['total_nodes', 'emitted_nodes', 'skipped_nodes'] as $column) {
        $db->exec('ALTER TABLE tracking_transform_events DROP COLUMN ' . $column);
    }
    $db->exec('PRAGMA user_version=4');
}

/** Reconstruct the actual v5 source CHECK for legacy migration tests only. */
function schema_v5_sources_fixture(PDO $db): void
{
    schema_remove_v7_fixture($db);
    $db->exec('PRAGMA foreign_keys=OFF');
    $db->beginTransaction();
    $db->exec(<<<'SQL'
CREATE TABLE tracking_sources_v5 (
    source_host TEXT PRIMARY KEY COLLATE NOCASE,
    origin TEXT NOT NULL CHECK (origin IN ('AUTO','MANUAL')),
    ever_seen INTEGER NOT NULL DEFAULT 0 CHECK (ever_seen IN (0,1)),
    state TEXT NOT NULL CHECK (state IN ('CURRENT','SUSPECT','INACTIVE','UNSEEN','DELETED')),
    first_seen_at INTEGER, last_seen_at INTEGER,
    missing_count INTEGER NOT NULL DEFAULT 0 CHECK (missing_count >= 0),
    first_snapshot_id INTEGER, last_snapshot_id INTEGER, deleted_at INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    FOREIGN KEY (first_snapshot_id) REFERENCES tracking_source_snapshots(id),
    FOREIGN KEY (last_snapshot_id) REFERENCES tracking_source_snapshots(id)
);
INSERT INTO tracking_sources_v5 SELECT * FROM tracking_sources;
DROP TABLE tracking_sources;
ALTER TABLE tracking_sources_v5 RENAME TO tracking_sources;
PRAGMA user_version=5;
SQL);
    $db->commit();$db->exec('PRAGMA foreign_keys=ON');
}
