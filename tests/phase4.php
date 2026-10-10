<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/sgw/admin/src/subscription_transform.php';

$phase4Directory = $temporaryRoot . DIRECTORY_SEPARATOR . 'phase4';
mkdir($phase4Directory, 0700, true);
$phase4Database = $phase4Directory . DIRECTORY_SEPARATOR . 'tracking.db';
$phase4Pdo = open_database($phase4Database);
initialize_database($phase4Pdo);
setting_set($phase4Pdo, 'upstream_url', 'https://backend.example.test');

$phase4Hashes = [];
$phase4InitialAssignments = [];

test_case('tracking schema starts disabled with root and three active leaves', function () use ($phase4Pdo): void {
    expect_same('off', tracking_mode($phase4Pdo));
    expect_same(4, (int) $phase4Pdo->query('SELECT COUNT(*) FROM tracking_groups')->fetchColumn());
    expect_same(['1', '2', '3'], array_column(tracking_active_leaves($phase4Pdo), 'path'));
    expect_same(1, (int) setting_get($phase4Pdo, 'tracking_algorithm_version'));
});

test_case('one thousand Token hashes receive stable roughly balanced initial assignments', function () use (
    $phase4Pdo,
    &$phase4Hashes,
    &$phase4InitialAssignments
): void {
    $counts = [1 => 0, 2 => 0, 3 => 0];
    $paths = $phase4Pdo->query('SELECT id, path FROM tracking_groups WHERE path IN (\'1\',\'2\',\'3\')')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    for ($index = 0; $index < 1000; $index++) {
        $hash = hash('sha256', 'tracking-token-' . $index);
        $groupId = tracking_assignment_for_hash($phase4Pdo, $hash);
        expect_same($groupId, tracking_assignment_for_hash($phase4Pdo, $hash));
        $path = (int) $paths[$groupId];
        $counts[$path]++;
        $phase4Hashes[] = $hash;
        $phase4InitialAssignments[$hash] = $groupId;
    }
    foreach ($counts as $count) {
        expect_true($count >= 250 && $count <= 420, 'Initial tracking distribution is unexpectedly imbalanced');
    }
});

test_case('tracking assignment is stable in a separate PHP process', function () use (
    $phase4Pdo,
    $phase4Database,
    $phase4Directory,
    $root,
    &$phase4Hashes
): void {
    $hash = $phase4Hashes[17];
    $expected = tracking_assignment_for_hash($phase4Pdo, $hash);
    $script = $phase4Directory . DIRECTORY_SEPARATOR . 'tracking-worker.php';
    file_put_contents($script, '<?php require ' . var_export($root . '/sgw/admin/src/tracking.php', true)
        . '; $pdo=open_database($argv[1]); initialize_database($pdo); echo tracking_assignment_for_hash($pdo,$argv[2]);');
    expect_same((string) $expected, finish_test_worker(spawn_test_worker($script, [$phase4Database, $hash])));
});

test_case('entry host validation accepts hostnames and IPs but rejects URLs and configuration fragments', function (): void {
    expect_same('entry.example.invalid', normalize_tracking_host('ENTRY.Example.Invalid.'));
    expect_same('192.0.2.1', normalize_tracking_host('192.0.2.1'));
    expect_same('2001:db8::1', normalize_tracking_host('2001:0db8::1'));
    foreach (['https://entry.example.invalid', 'entry.example.invalid:443', 'entry.example.invalid/path',
        'entry.example.invalid?x=1', "entry.example.invalid\nmalicious"] as $invalid) {
        expect_exception(static fn () => normalize_tracking_host($invalid), InvalidArgumentException::class);
    }
});

test_case('active leaves can be configured with normalized relation mappings', function () use ($phase4Pdo): void {
    foreach (tracking_active_leaves($phase4Pdo) as $leaf) {
        tracking_save_group_mappings($phase4Pdo, (int) $leaf['id'], [[
            'source_host' => 'ORIGIN.EXAMPLE.INVALID',
            'target_host' => 'group' . $leaf['path'] . '.example.invalid',
        ]]);
    }
    tracking_validate_enforced_ready($phase4Pdo);
});

test_case('draft split does not move assignments and incomplete mappings cannot activate', function () use (
    $phase4Pdo,
    &$phase4InitialAssignments
): void {
    $parentId = (int) $phase4Pdo->query("SELECT id FROM tracking_groups WHERE path = '1'")->fetchColumn();
    $before = $phase4Pdo->query('SELECT token_hash, group_id FROM tracking_assignments ORDER BY token_hash')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    $children = tracking_create_split($phase4Pdo, $parentId);
    expect_same(['DRAFT', 'DRAFT', 'DRAFT'], array_column($children, 'status'));
    $draftIds = array_map('intval', array_column($children, 'id'));
    $newDuringDraft = tracking_assignment_for_hash($phase4Pdo, hash('sha256', 'new-token-during-draft'));
    expect_true(!in_array($newDuringDraft, $draftIds, true), 'A DRAFT group received a Token');
    $after = $phase4Pdo->query('SELECT token_hash, group_id FROM tracking_assignments ORDER BY token_hash')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    unset($after[hash('sha256', 'new-token-during-draft')]);
    expect_same($before, $after);
    foreach ($children as $index => $child) {
        tracking_save_group_mappings($phase4Pdo, (int) $child['id'], [[
            'source_host' => 'origin.example.invalid',
            'target_host' => $index === 0 ? 'group1-1.example.invalid' : '',
        ]]);
    }
    expect_exception(static fn () => tracking_activate_split($phase4Pdo, $parentId), DomainException::class);
    foreach ($children as $child) {
        tracking_save_group_mappings($phase4Pdo, (int) $child['id'], [[
            'source_host' => 'origin.example.invalid',
            'target_host' => 'group' . str_replace('.', '-', (string) $child['path']) . '.example.invalid',
        ]]);
    }
    tracking_save_group_mappings($phase4Pdo, (int) $children[0]['id'], [[
        'source_host' => 'different.example.invalid',
        'target_host' => 'group1-1.example.invalid',
    ]]);
    expect_exception(static fn () => tracking_validate_split($phase4Pdo, $parentId), DomainException::class);
    tracking_save_group_mappings($phase4Pdo, (int) $children[0]['id'], [[
        'source_host' => 'origin.example.invalid',
        'target_host' => 'group1-1.example.invalid',
    ]]);
});

test_case('activating group 1 split changes only assignments formerly in group 1', function () use (
    $phase4Pdo,
    &$phase4InitialAssignments
): void {
    $parentId = (int) $phase4Pdo->query("SELECT id FROM tracking_groups WHERE path = '1'")->fetchColumn();
    $movedExpected = (int) $phase4Pdo->query(
        'SELECT COUNT(*) FROM tracking_assignments WHERE group_id = ' . $parentId
    )->fetchColumn();
    expect_same($movedExpected, tracking_activate_split($phase4Pdo, $parentId));
    $children = array_map('intval', array_column(tracking_children($phase4Pdo, $parentId), 'id'));
    $current = $phase4Pdo->query('SELECT token_hash, group_id FROM tracking_assignments ORDER BY token_hash')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    foreach ($phase4InitialAssignments as $hash => $oldGroup) {
        $newGroup = (int) $current[$hash];
        if ($oldGroup === $parentId) {
            expect_true(in_array($newGroup, $children, true));
        } else {
            expect_same($oldGroup, $newGroup, 'A sibling group assignment changed during split');
        }
    }
    expect_same(0, (int) $phase4Pdo->query('SELECT COUNT(*) FROM tracking_assignments WHERE group_id = ' . $parentId)->fetchColumn());
});

test_case('recursive split of 1.2 changes only 1.2 and supports a new Token at the current leaf', function () use ($phase4Pdo): void {
    $parentId = (int) $phase4Pdo->query("SELECT id FROM tracking_groups WHERE path = '1.2'")->fetchColumn();
    $before = $phase4Pdo->query('SELECT token_hash, group_id FROM tracking_assignments ORDER BY token_hash')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    $children = tracking_create_split($phase4Pdo, $parentId);
    foreach ($children as $child) {
        tracking_save_group_mappings($phase4Pdo, (int) $child['id'], [[
            'source_host' => 'origin.example.invalid',
            'target_host' => 'group' . str_replace('.', '-', (string) $child['path']) . '.example.invalid',
        ]]);
    }
    tracking_activate_split($phase4Pdo, $parentId);
    $after = $phase4Pdo->query('SELECT token_hash, group_id FROM tracking_assignments ORDER BY token_hash')
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    $childIds = array_map('intval', array_column(tracking_children($phase4Pdo, $parentId), 'id'));
    foreach ($before as $hash => $oldGroup) {
        $newGroup = (int) $after[$hash];
        if ((int) $oldGroup === $parentId) {
            expect_true(in_array($newGroup, $childIds, true));
        } else {
            expect_same((int) $oldGroup, $newGroup, 'A non-1.2 assignment changed');
        }
    }
    $newHash = hash('sha256', 'new-token-after-recursive-split');
    $newGroup = tracking_assignment_for_hash($phase4Pdo, $newHash);
    expect_true(tracking_group_is_active_leaf($phase4Pdo, $newGroup));
    expect_true(!in_array((string) tracking_group($phase4Pdo, $newGroup)['path'], ['1', '1.2'], true));
});

test_case('an already nested leaf can be split again without code changes', function () use ($phase4Pdo): void {
    $parentId = (int) $phase4Pdo->query("SELECT id FROM tracking_groups WHERE path = '1.2.3'")->fetchColumn();
    $children = tracking_create_split($phase4Pdo, $parentId);
    expect_same(['1.2.3.1', '1.2.3.2', '1.2.3.3'], array_column($children, 'path'));
    foreach ($children as $child) {
        tracking_save_group_mappings($phase4Pdo, (int) $child['id'], [[
            'source_host' => 'origin.example.invalid',
            'target_host' => 'group' . str_replace('.', '-', (string) $child['path']) . '.example.invalid',
        ]]);
    }
    tracking_activate_split($phase4Pdo, $parentId);
    expect_same(3, count(tracking_children($phase4Pdo, $parentId)));
});

test_case('tracking modes validate enforced mappings and preserve explicit mode values', function () use ($phase4Pdo): void {
    tracking_validate_enforced_ready($phase4Pdo);
    foreach (['preflight', 'enforced', 'off'] as $mode) {
        tracking_set_mode($phase4Pdo, $mode);
        expect_same($mode, tracking_mode($phase4Pdo));
    }
});

test_case('enforced mode rejects an active mapping edit that would break global source coverage', function () use ($phase4Pdo): void {
    tracking_set_mode($phase4Pdo, 'enforced');
    $leaf = tracking_active_leaves($phase4Pdo)[0];
    $groupId = (int) $leaf['id'];
    $before = tracking_group_mappings($phase4Pdo, $groupId);
    expect_exception(static fn () => tracking_save_group_mappings($phase4Pdo, $groupId, [[
        'source_host' => 'different.example.invalid',
        'target_host' => 'isolated.example.invalid',
    ]]), DomainException::class);
    expect_same($before, tracking_group_mappings($phase4Pdo, $groupId));
    tracking_set_mode($phase4Pdo, 'off');
});

test_case('compiled modes keep the existing policy gate before selecting the proxy target', function () use ($phase4Pdo): void {
    setting_set($phase4Pdo, 'tracking_mode', 'preflight');
    $rules = compile_gateway_rules($phase4Pdo)['rules'];
    expect_true(str_contains($rules, 'default "http://admin:8081";'));
    expect_true(str_contains($rules, 'off $gateway_upstream;'));
    expect_true(str_contains($rules, 'default $arg_token;'));
    setting_set($phase4Pdo, 'tracking_mode', 'off');
});

test_case('Transformer is internal-only and fixes its upstream and TLS behavior', function () use ($root): void {
    $compose = (string) file_get_contents($root . '/sgw/docker-compose.yml');
    $transformer = (string) file_get_contents($root . '/sgw/admin/src/transformer.php');
    expect_true(str_contains($compose, 'expose:'));
    expect_true(!str_contains($compose, ':8081'));
    expect_true(str_contains($transformer, 'setting_get($pdo, \'upstream_url\', \'\')'));
    expect_true(str_contains($transformer, 'CURLOPT_SSL_VERIFYPEER => true'));
    expect_true(str_contains($transformer, 'CURLOPT_SSL_VERIFYHOST => 2'));
    expect_true(str_contains($transformer, 'CURLOPT_FOLLOWLOCATION => false'));
    expect_true(str_contains($transformer, 'TRANSFORM_MAX_BODY_BYTES = 8 * 1024 * 1024'));
});

$phase4Mapping = ['origin.example.invalid' => 'group1.example.invalid'];

test_case('Clash YAML changes only proxies server fields', function () use ($phase4Mapping): void {
    $yaml = <<<'YAML'
proxies:
  - name: "origin.example.invalid node"
    type: vless
    server: origin.example.invalid
    port: 443
    uuid: 01234567-89ab-cdef-0123-456789abcdef
    password: unchanged
    flow: xtls-rprx-vision
    sni: origin.example.invalid
    servername: origin.example.invalid
    reality-opts:
      public-key: public-key-value
      short-id: abcd
YAML;
    $result = tracking_transform_subscription_body($yaml, $phase4Mapping);
    expect_same('YAML', $result['format']);
    $before = yaml_parse($yaml);
    $after = yaml_parse($result['content']);
    expect_same('group1.example.invalid', $after['proxies'][0]['server']);
    $after['proxies'][0]['server'] = $before['proxies'][0]['server'];
    expect_same($before, $after);
});

test_case('VLESS Trojan Hysteria2 and TUIC URIs change only the authority host', function () use ($phase4Mapping): void {
    $lines = [
        'vless://uuid@origin.example.invalid:443?security=reality&sni=origin.example.invalid&pbk=key&sid=01&flow=xtls-rprx-vision#Node',
        'trojan://password@origin.example.invalid:8443?sni=origin.example.invalid#Trojan',
        'hysteria2://password@origin.example.invalid:7443?sni=origin.example.invalid&insecure=0#Hy2',
        'tuic://uuid:password@origin.example.invalid:9443?sni=origin.example.invalid#Tuic',
    ];
    $result = tracking_transform_subscription_body(implode("\n", $lines), $phase4Mapping);
    expect_same('URI', $result['format']);
    $expected = str_replace('@origin.example.invalid:', '@group1.example.invalid:', implode("\n", $lines));
    expect_same($expected, $result['content']);
});

test_case('Shadowsocks modern URI preserves credentials port and fragment', function () use ($phase4Mapping): void {
    $uri = 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@origin.example.invalid:8388#SS%20Node';
    $result = tracking_transform_subscription_body($uri, $phase4Mapping);
    expect_same('ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@group1.example.invalid:8388#SS%20Node', $result['content']);
});

test_case('Shadowsocks legacy Base64 authority changes only its host', function () use ($phase4Mapping): void {
    $authority = 'aes-256-gcm:password@origin.example.invalid:8388';
    $uri = 'ss://' . rtrim(base64_encode($authority), '=') . '#Legacy';
    $result = tracking_transform_subscription_body($uri, $phase4Mapping);
    $encoded = substr($result['content'], strlen('ss://'), -strlen('#Legacy'));
    $decoded = tracking_decode_base64($encoded, 'URI');
    expect_same('aes-256-gcm:password@group1.example.invalid:8388', $decoded['decoded']);
    expect_true(str_ends_with($result['content'], '#Legacy'));
});

test_case('VMess Base64 JSON changes only add', function () use ($phase4Mapping): void {
    $document = ['v' => '2', 'ps' => 'origin.example.invalid node', 'add' => 'origin.example.invalid',
        'port' => '443', 'id' => '01234567-89ab-cdef-0123-456789abcdef', 'aid' => '0',
        'scy' => 'auto', 'net' => 'tcp', 'tls' => 'tls', 'sni' => 'origin.example.invalid'];
    $uri = 'vmess://' . rtrim(base64_encode(json_encode($document, JSON_UNESCAPED_SLASHES)), '=');
    $result = tracking_transform_subscription_body($uri, $phase4Mapping);
    expect_same('VMESS', $result['format']);
    $payload = substr($result['content'], strlen('vmess://'));
    $decoded = tracking_decode_base64($payload, 'VMESS');
    $after = json_decode($decoded['decoded'], true, 64, JSON_THROW_ON_ERROR);
    expect_same('group1.example.invalid', $after['add']);
    $after['add'] = $document['add'];
    expect_same($document, $after);
});

test_case('whole Base64 subscription decodes transforms and re-encodes', function () use ($phase4Mapping): void {
    $plain = 'vless://uuid@origin.example.invalid:443?sni=origin.example.invalid#Node';
    $encoded = rtrim(strtr(base64_encode($plain), '+/', '-_'), '=');
    $result = tracking_transform_subscription_body($encoded, $phase4Mapping);
    expect_same('BASE64', $result['format']);
    $decoded = tracking_decode_base64($result['content'], 'BASE64');
    expect_same('vless://uuid@group1.example.invalid:443?sni=origin.example.invalid#Node', $decoded['decoded']);
});

test_case('invalid Base64 unknown formats and missing mappings fail without partial output', function () use ($phase4Mapping): void {
    try {
        tracking_transform_subscription_body('AAAAA===', $phase4Mapping);
        throw new RuntimeException('Invalid Base64 unexpectedly succeeded');
    } catch (TrackingTransformFailure $failure) {
        expect_same('PARSE_FAILED', $failure->reason);
        expect_same('BASE64', $failure->format);
    }
    try {
        tracking_transform_subscription_body('this is not a subscription!', $phase4Mapping);
        throw new RuntimeException('Unknown subscription unexpectedly succeeded');
    } catch (TrackingTransformFailure $failure) {
        expect_same('UNKNOWN_FORMAT', $failure->reason);
    }
    try {
        tracking_transform_subscription_body('vless://uuid@other.example.invalid:443#Node', $phase4Mapping);
        throw new RuntimeException('Incomplete mapping unexpectedly succeeded');
    } catch (TrackingTransformFailure $failure) {
        expect_same('MAPPING_INCOMPLETE', $failure->reason);
    }
});

test_case('tracking transform events provide bounded 24 hour aggregate statistics', function () use ($phase4Pdo): void {
    $groupId = (int) tracking_active_leaves($phase4Pdo)[0]['id'];
    tracking_record_transform_event($phase4Pdo, $groupId, 'preflight', 'YAML', 'SUCCESS');
    tracking_record_transform_event($phase4Pdo, $groupId, 'preflight', 'UNKNOWN', 'UNKNOWN_FORMAT');
    tracking_record_transform_event($phase4Pdo, $groupId, 'enforced', 'URI', 'MAPPING_INCOMPLETE');
    $stats = tracking_transform_stats($phase4Pdo);
    expect_same(3, $stats['requests']);
    expect_same(1, $stats['successes']);
    expect_same(2, $stats['failures']);
    expect_same(1, $stats['unknown_formats']);
    expect_same(1, $stats['mapping_incomplete']);
    expect_same(1, $stats['formats']['YAML']);
});

test_case('v2 database migrates to v3 without changing core data', function () use ($phase4Directory): void {
    $path = $phase4Directory . DIRECTORY_SEPARATOR . 'v2.db';
    $old = open_database($path);
    initialize_database($old);
    create_admin($old, 'migration_admin', 'Correct-Horse-Battery-42');
    $token = '1234567890abcdef1234567890abcdef';
    $tokenId = save_token($old, $token, 'BLOCKED');
    add_ip_rule($old, '198.51.100.0/24', 'BLACKLIST');
    add_ua_rule($old, 'MigrationClient', 'BLACKLIST');
    $log = $old->prepare('INSERT INTO access_logs '
        . '(token_id, client_ip, user_agent, request_path, status_code, decision, created_at) '
        . 'VALUES (:token_id, :ip, :ua, :path, 403, :decision, :created_at)');
    $log->execute([':token_id' => $tokenId, ':ip' => '198.51.100.5', ':ua' => 'MigrationClient',
        ':path' => '/api/v1/test/subscribe', ':decision' => 'TOKEN_BLOCKED', ':created_at' => time()]);
    foreach (['tracking_transform_events', 'tracking_entry_mappings', 'tracking_assignments', 'tracking_groups'] as $table) {
        $old->exec('DROP TABLE ' . $table);
    }
    $old->exec("DELETE FROM settings WHERE key IN ('tracking_mode','tracking_algorithm_version')");
    $old->exec('PRAGMA user_version=2');
    initialize_database($old);
    expect_same(3, (int) $old->query('PRAGMA user_version')->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM admins WHERE username = \'migration_admin\'')->fetchColumn());
    expect_same('BLOCKED', (string) $old->query('SELECT state FROM tokens WHERE id = ' . $tokenId)->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM ip_rules')->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM ua_rules')->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM access_logs')->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM tracking_assignments')->fetchColumn());
    $expectedGroup = tracking_child_number(token_hash_value($token), 1) + 1;
    expect_same($expectedGroup, (int) $old->query('SELECT group_id FROM tracking_assignments')->fetchColumn());
    expect_same('off', tracking_mode($old));
    $old = null;
});

test_case('failed v2 tracking migration rolls back schema version and preserves core rows', function () use ($phase4Directory): void {
    $path = $phase4Directory . DIRECTORY_SEPARATOR . 'rollback.db';
    $old = open_database($path);
    initialize_database($old);
    create_admin($old, 'rollback_admin', 'Correct-Horse-Battery-42');
    foreach (['tracking_transform_events', 'tracking_entry_mappings', 'tracking_assignments', 'tracking_groups'] as $table) {
        $old->exec('DROP TABLE ' . $table);
    }
    $old->exec('CREATE TABLE tracking_groups (conflict TEXT)');
    $old->exec('PRAGMA user_version=2');
    expect_exception(static fn () => initialize_database($old), PDOException::class);
    expect_same(2, (int) $old->query('PRAGMA user_version')->fetchColumn());
    expect_same(1, (int) $old->query('SELECT COUNT(*) FROM admins WHERE username = \'rollback_admin\'')->fetchColumn());
    $old = null;
});
