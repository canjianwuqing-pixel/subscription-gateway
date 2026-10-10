<?php
declare(strict_types=1);

/** Test-only downgrade; never run against a deployment database. */
function schema_remove_v5_fixture(PDO $db): void
{
    $db->exec('DROP TABLE tracking_sources');
    $db->exec('DROP TABLE tracking_source_snapshots');
    foreach (['total_nodes', 'emitted_nodes', 'skipped_nodes'] as $column) {
        $db->exec('ALTER TABLE tracking_transform_events DROP COLUMN ' . $column);
    }
    $db->exec('PRAGMA user_version=4');
}
