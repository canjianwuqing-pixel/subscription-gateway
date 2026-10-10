<?php
declare(strict_types=1);

require_once $root . '/sgw/admin/src/installation.php';

function installation_test_database(): PDO
{
    global $temporaryRoot;
    $db = open_database($temporaryRoot . '/install-' . bin2hex(random_bytes(6)) . '.db');
    initialize_database($db);
    create_admin($db, 'install_test', 'safe-install-test-password');
    return $db;
}

test_case('installation diagnostics accept schema v5, initial off groups and empty upstream', function (): void {
    $db = installation_test_database();
    expect_same(['schema' => 5, 'tracking_mode' => 'off', 'upstream' => 'EMPTY'], installation_database_check($db));
});
test_case('installation diagnostics reject old schema without migrating it', function (): void {
    $db = installation_test_database();
    $db->exec('PRAGMA user_version=2');
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
    expect_same(2, (int) $db->query('PRAGMA user_version')->fetchColumn());
});
test_case('installation diagnostics reject future schema without modifying it', function (): void {
    $db = installation_test_database();
    $db->exec('PRAGMA user_version=6');
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
    expect_same(6, (int) $db->query('PRAGMA user_version')->fetchColumn());
});
test_case('installation diagnostics reject invalid tracking mode', function (): void {
    $db = installation_test_database();
    setting_set($db, 'tracking_mode', 'invalid-mode');
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
});
test_case('installation diagnostics reject missing initial tracking group', function (): void {
    $db = installation_test_database();
    $db->exec("DELETE FROM tracking_groups WHERE path='3'");
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
});
test_case('installation diagnostics reject invalid root topology', function (): void {
    $db = installation_test_database();
    $db->exec("UPDATE tracking_groups SET status='ARCHIVED' WHERE path='root'");
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
});
test_case('installation diagnostics reject absent administrator', function (): void {
    $db = installation_test_database();
    $db->exec('DELETE FROM admins');
    expect_exception(fn () => installation_database_check($db), RuntimeException::class);
});
test_case('installation diagnostics accept configured upstream without contacting it', function (): void {
    $db = installation_test_database();
    setting_set($db, 'upstream_url', 'https://backend.example.invalid');
    expect_same('CONFIGURED', installation_database_check($db)['upstream']);
});
test_case('installation diagnostic accepts all existing supported tracking modes', function (): void {
    $db = installation_test_database();
    foreach (TRACKING_MODES as $mode) {
        setting_set($db, 'tracking_mode', $mode);
        expect_same($mode, installation_database_check($db)['tracking_mode']);
    }
});
test_case('installation PHP extension check verifies curl and yaml', function (): void {
    installation_extensions_check();
    expect_true(extension_loaded('curl') && extension_loaded('yaml'));
});
test_case('installation transformer probe fails on unavailable internal 8081', function (): void {
    expect_exception(fn () => installation_transformer_check(), RuntimeException::class);
});
