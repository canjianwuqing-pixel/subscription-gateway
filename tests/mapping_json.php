<?php

declare(strict_types=1);

/** Each regression uses an isolated SQLite database and the real API decoder. */
function mapping_json_fixture(array $sources = ['na001.example.com']): array
{
    global $temporaryRoot;
    static $sequence = 0;
    $pdo = open_database($temporaryRoot . '/mapping-json-' . ++$sequence . '.db');
    initialize_database($pdo);
    tracking_sync_source_hosts($pdo, $sources);
    return [$pdo, (int) tracking_active_leaves($pdo)[0]['id']];
}

function mapping_json_save(PDO $pdo, int $groupId, string $raw): void
{
    $body = decode_json_object($raw);
    tracking_save_group_targets($pdo, $groupId, normalize_tracking_mapping_rows($body['mappings']));
}

test_case('Browser JSON keeps stdClass rows until tracking API normalization', function (): void {
    [$pdo, $groupId] = mapping_json_fixture();
    $raw = '{"mappings":[{"source_host":"na001.example.com","target_host":"43.198.74.153"}]}';
    $body = decode_json_object($raw);
    expect_true($body['mappings'][0] instanceof stdClass);
    $rows = normalize_tracking_mapping_rows($body['mappings']);
    expect_true(is_array($rows[0]));
    expect_true($body['mappings'][0] instanceof stdClass, 'Global decoder semantics must not change');
    tracking_save_group_targets($pdo, $groupId, $rows);
    expect_same('43.198.74.153', tracking_group_mappings($pdo, $groupId)[0]['target_host']);
});

test_case('Tracking API normalization also preserves native array rows', function (): void {
    $row = ['source_host' => 'na001.example.com', 'target_host' => 'entry-a.example.com'];
    expect_same([$row, $row], normalize_tracking_mapping_rows([$row, (object) $row]));
});

foreach (['43.198.74.153', '35.78.249.196', '3.1.51.25', '54.117.30.142',
    '43.206.136.211', '18.162.56.161', 'entry-a.example.com', '2001:0DB8::1'] as $target) {
    test_case('Browser JSON saves target ' . $target, function () use ($target): void {
        [$pdo, $groupId] = mapping_json_fixture();
        mapping_json_save($pdo, $groupId, json_encode(['mappings' => [
            ['source_host' => 'na001.example.com', 'target_host' => $target],
        ]], JSON_THROW_ON_ERROR));
        $statement = $pdo->prepare('SELECT source_host, target_host FROM tracking_entry_mappings WHERE group_id = :id');
        $statement->execute([':id' => $groupId]);
        expect_same([['source_host' => 'na001.example.com', 'target_host' => normalize_tracking_host($target)]], $statement->fetchAll());
    });
}

foreach (['https://example.com', 'example.com:443', '/path', 'bad host', 'example.com/path',
    'example.com?query=1', 'user@example.com', 'example.com\\path', "bad\nhost", "bad\0host", "bad\x7Fhost"] as $index => $target) {
    test_case('Browser JSON rejects unsafe target ' . $index, function () use ($target): void {
        [$pdo, $groupId] = mapping_json_fixture();
        $before = tracking_group_mappings($pdo, $groupId);
        $raw = json_encode(['mappings' => [['source_host' => 'na001.example.com', 'target_host' => $target]]], JSON_THROW_ON_ERROR);
        expect_exception(fn () => mapping_json_save($pdo, $groupId, $raw), InvalidArgumentException::class);
        expect_same($before, tracking_group_mappings($pdo, $groupId));
    });
}

foreach (['empty' => '', 'null' => null, 'missing' => null] as $kind => $target) {
    test_case('Browser JSON allows ACTIVE ' . $kind . ' target for node filtering', function () use ($kind, $target): void {
        [$pdo, $groupId] = mapping_json_fixture();
        $before = tracking_group_mappings($pdo, $groupId);
        $row = ['source_host' => 'na001.example.com'];
        if ($kind !== 'missing') $row['target_host'] = $target;
        $raw = json_encode(['mappings' => [$row]], JSON_THROW_ON_ERROR);
        mapping_json_save($pdo, $groupId, $raw);
        expect_same(null, tracking_group_mappings($pdo, $groupId)[0]['target_host']);
        expect_same([], tracking_effective_mapping($pdo, $groupId));
    });
}

foreach (['tampered' => ['evil.example.com', 'na002.example.com'],
    'missing' => ['na001.example.com'],
    'extra' => ['na001.example.com', 'na002.example.com', 'extra.example.com'],
    'duplicate' => ['na001.example.com', 'na001.example.com']] as $kind => $sources) {
    test_case('Browser JSON rejects ' . $kind . ' source set', function () use ($sources): void {
        [$pdo, $groupId] = mapping_json_fixture(['na001.example.com', 'na002.example.com']);
        $before = tracking_group_mappings($pdo, $groupId);
        $rows = array_map(static fn ($source) => ['source_host' => $source, 'target_host' => 'entry-a.example.com'], $sources);
        $raw = json_encode(['mappings' => $rows], JSON_THROW_ON_ERROR);
        expect_exception(fn () => mapping_json_save($pdo, $groupId, $raw), DomainException::class);
        expect_same($before, tracking_group_mappings($pdo, $groupId));
    });
}

foreach (['string' => 'invalid', 'integer' => 7, 'null' => null, 'boolean' => true, 'float' => 1.5] as $kind => $row) {
    test_case('Browser JSON rejects ' . $kind . ' mapping row', function () use ($row): void {
        [$pdo, $groupId] = mapping_json_fixture();
        $before = tracking_group_mappings($pdo, $groupId);
        $raw = json_encode(['mappings' => [$row]], JSON_THROW_ON_ERROR);
        expect_exception(fn () => mapping_json_save($pdo, $groupId, $raw), InvalidArgumentException::class);
        expect_same($before, tracking_group_mappings($pdo, $groupId));
    });
}

test_case('Mapping API rejects objects other than stdClass', function (): void {
    expect_exception(fn () => normalize_tracking_mapping_rows([new ArrayObject()]), InvalidArgumentException::class);
});

test_case('Browser JSON target edit retains enforced fail-closed validation', function (): void {
    [$pdo, $groupId] = mapping_json_fixture();
    $raw = '{"mappings":[{"source_host":"na001.example.com","target_host":"entry-a.example.com"}]}';
    $leaves = tracking_active_leaves($pdo);
    foreach ($leaves as $leaf) mapping_json_save($pdo, (int) $leaf['id'], $raw);
    tracking_set_mode($pdo, 'enforced');
    mapping_json_save($pdo, $groupId, str_replace('entry-a.example.com', '43.198.74.153', $raw));
    $before = tracking_group_mappings($pdo, $groupId);
    // Simulate incomplete peer mappings only in this temporary database.
    $statement = $pdo->prepare('UPDATE tracking_entry_mappings SET target_host = NULL WHERE group_id = :id');
    $statement->execute([':id' => (int) $leaves[1]['id']]);
    expect_exception(fn () => mapping_json_save($pdo, $groupId, $raw), DomainException::class);
    expect_same($before, tracking_group_mappings($pdo, $groupId));
    expect_same('enforced', tracking_mode($pdo));
});
