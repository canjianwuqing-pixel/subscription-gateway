<?php

declare(strict_types=1);

/** Construct an actual v3 schema: only tracking_groups differs from v4. */
function schema_v3_fixture(): PDO
{
    [$db, $parent] = flexible_split_fixture();
    historical_split_fixture($db, $parent, 3);
    flexible_fill_children($db, $parent);
    historical_activate_fixture($db, $parent);
    $nested = (int) tracking_children($db, $parent)[1]['id'];
    historical_split_fixture($db, $nested, 3);
    flexible_fill_children($db, $nested);
    historical_activate_fixture($db, $nested);
    $pending = historical_split_fixture($db, 3, 3);
    tracking_save_group_targets($db, (int) $pending[0]['id'], [['source_host' => 'na001.example.com', 'target_host' => 'draft.example.com']]);
    $db->exec("UPDATE tracking_groups SET status = 'ARCHIVED' WHERE id = " . (int) $pending[2]['id']);
    tracking_record_transform_event($db, $nested, 'preflight', 'URI', 'SUCCESS');
    tracking_record_transform_event($db, null, 'enforced', 'BASE64', 'UNKNOWN_FORMAT');
    create_admin($db, 'schema_admin', 'schema-test-password');
    save_token($db, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'WHITELIST');
    add_ip_rule($db, '192.0.2.0/24', 'BLACKLIST');
    add_ua_rule($db, 'SchemaClient', 'WHITELIST');
    schema_remove_v5_fixture($db);
    $db->exec('PRAGMA foreign_keys=OFF');
    $db->beginTransaction();
    $db->exec(<<<'SQL'
CREATE TABLE tracking_groups_v3 (
    id INTEGER PRIMARY KEY, parent_id INTEGER, child_no INTEGER NOT NULL,
    path TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('DRAFT','ACTIVE','ARCHIVED')),
    split_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES tracking_groups(id) ON DELETE RESTRICT,
    UNIQUE (parent_id,child_no),
    CHECK ((parent_id IS NULL AND child_no=0 AND path='root')
        OR (parent_id IS NOT NULL AND child_no BETWEEN 1 AND 3))
);
INSERT INTO tracking_groups_v3 SELECT * FROM tracking_groups;
DROP TABLE tracking_groups;
ALTER TABLE tracking_groups_v3 RENAME TO tracking_groups;
PRAGMA user_version=3;
SQL);
    $db->commit();
    $db->exec('PRAGMA foreign_keys=ON');
    return $db;
}

$schemaV3Pdo = schema_v3_fixture();
$schemaBefore = [];
foreach (['tracking_groups', 'tracking_assignments', 'tracking_entry_mappings', 'tracking_transform_events',
    'admins', 'tokens', 'ip_rules', 'ua_rules', 'settings', 'access_logs'] as $table) {
    $schemaBefore[$table] = $schemaV3Pdo->query('SELECT * FROM ' . $table . ' ORDER BY 1')->fetchAll();
}
$schemaBeforeFks = [];
foreach (['tracking_groups', 'tracking_assignments', 'tracking_entry_mappings', 'tracking_transform_events'] as $table) {
    $schemaBeforeFks[$table] = $schemaV3Pdo->query('PRAGMA foreign_key_list(' . $table . ')')->fetchAll();
}
test_case('Real v3 schema migrates through v4 to v6 and initialization is idempotent', function () use ($schemaV3Pdo): void {
    expect_same(3, (int) $schemaV3Pdo->query('PRAGMA user_version')->fetchColumn());
    expect_true(str_contains($schemaV3Pdo->query("SELECT sql FROM sqlite_master WHERE name='tracking_groups'")->fetchColumn(), 'BETWEEN 1 AND 3'));
    initialize_database($schemaV3Pdo);
    expect_same(7, (int) $schemaV3Pdo->query('PRAGMA user_version')->fetchColumn());
    initialize_database($schemaV3Pdo);
});
foreach (['id', 'parent_id', 'child_no', 'path', 'status', 'split_at', 'created_at', 'updated_at'] as $column) {
    test_case('v3 migration preserves tracking_groups ' . $column, function () use ($schemaV3Pdo, $schemaBefore, $column): void {
        expect_same(array_column($schemaBefore['tracking_groups'], $column), $schemaV3Pdo->query('SELECT ' . $column . ' FROM tracking_groups ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
    });
}
foreach (array_keys($schemaBefore) as $table) {
    test_case('v3 migration preserves every row and column of ' . $table, function () use ($schemaV3Pdo, $schemaBefore, $table): void {
        $columns = $table === 'tracking_transform_events' ? 'id,group_id,mode,format,outcome,created_at' : '*';
        expect_same($schemaBefore[$table], $schemaV3Pdo->query('SELECT ' . $columns . ' FROM ' . $table . ' ORDER BY 1')->fetchAll());
    });
}
test_case('v3 migration retains foreign key definitions and enforcement', function () use ($schemaV3Pdo, $schemaBeforeFks): void {
    foreach ($schemaBeforeFks as $table => $before) expect_same($before, $schemaV3Pdo->query('PRAGMA foreign_key_list(' . $table . ')')->fetchAll());
    expect_same(1, (int) $schemaV3Pdo->query('PRAGMA foreign_keys')->fetchColumn());
    expect_same([], $schemaV3Pdo->query('PRAGMA foreign_key_check')->fetchAll());
    expect_same(['ok'], $schemaV3Pdo->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));
});
test_case('v3 migration retains exact root IDs paths and all fixed Token assignments', function () use ($schemaV3Pdo, $schemaBefore): void {
    expect_same([['id' => 2, 'path' => '1'], ['id' => 3, 'path' => '2'], ['id' => 4, 'path' => '3']],
        $schemaV3Pdo->query('SELECT id,path FROM tracking_groups WHERE parent_id=1 ORDER BY child_no')->fetchAll());
    foreach ($schemaBefore['tracking_assignments'] as $row) expect_same((int) $row['group_id'], tracking_assignment_for_hash($schemaV3Pdo, $row['token_hash']));
    expect_same($schemaBefore['tracking_assignments'], $schemaV3Pdo->query('SELECT * FROM tracking_assignments ORDER BY 1')->fetchAll());
});
test_case('Fresh v4 database allows child_no beyond three and enforces root constraints', function (): void {
    [$db, $parent] = mapping_json_fixture();
    expect_same(7, (int) $db->query('PRAGMA user_version')->fetchColumn());
    $db->exec("INSERT INTO tracking_groups (parent_id,child_no,path,status,created_at,updated_at) VALUES (2,99,'1.99','DRAFT',1,1)");
    expect_same(99, (int) $db->query("SELECT child_no FROM tracking_groups WHERE path='1.99'")->fetchColumn());
    foreach (["UPDATE tracking_groups SET child_no=1 WHERE path='root'",
        "UPDATE tracking_groups SET path='not-root' WHERE parent_id IS NULL",
        "UPDATE tracking_groups SET child_no=0 WHERE path='1.99'"] as $sql) expect_exception(fn () => $db->exec($sql), PDOException::class);
});
test_case('v3 migration failure rolls back complete data and restores FK enforcement', function (): void {
    $db = schema_v3_fixture();
    $before = $db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll();
    $assignments = flexible_assignments($db);
    $db->exec('CREATE TABLE tracking_groups_v4 (conflict TEXT)');
    expect_exception(fn () => initialize_database($db), PDOException::class);
    expect_same(3, (int) $db->query('PRAGMA user_version')->fetchColumn());
    expect_same($before, $db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll());
    expect_same($assignments, flexible_assignments($db));
    expect_same(1, (int) $db->query('PRAGMA foreign_keys')->fetchColumn());
    expect_same(['ok'], $db->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));
});
test_case('v3 migration refuses orphaned FK data without dropping existing tables', function (): void {
    $db = schema_v3_fixture();
    $db->exec('PRAGMA foreign_keys=OFF');
    $db->exec("UPDATE tracking_assignments SET group_id=999999 WHERE token_hash=(SELECT token_hash FROM tracking_assignments LIMIT 1)");
    $db->exec('PRAGMA foreign_keys=ON');
    $before = flexible_assignments($db);
    expect_exception(fn () => initialize_database($db), RuntimeException::class);
    expect_same(3, (int) $db->query('PRAGMA user_version')->fetchColumn());
    expect_same($before, flexible_assignments($db));
    expect_same(1, (int) $db->query('PRAGMA foreign_keys')->fetchColumn());
});
$schemaV3Pdo = null;
