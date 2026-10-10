<?php

declare(strict_types=1);

// Isolated metadata fixtures; no application configuration or production data.
$workflowPdo = open_database($temporaryRoot . '/admin-workflow.db');
initialize_database($workflowPdo);
$workflowToken = '0123456789abcdef0123456789abcdef';
$workflowEvent = json_encode(['token' => $workflowToken, 'ip' => '192.0.2.45',
    'ua' => 'Workflow_Test/1', 'path' => '/api/v1/test/subscribe', 'policy' => 'PASS',
    'time' => time(), 'status' => 200], JSON_THROW_ON_ERROR);
$dashboardSource = file_get_contents($root . '/sgw/admin/src/dashboard.php');
$loginSource = file_get_contents($root . '/sgw/admin/src/index.php');

foreach (['prompt', 'confirm', 'alert'] as $nativeCall) {
    test_case('Admin has no native ' . $nativeCall . ' calls', function () use ($dashboardSource, $loginSource, $nativeCall): void {
        expect_same(0, preg_match('/\b' . $nativeCall . '\s*\(/', $dashboardSource . $loginSource));
    });
}
foreach (['dashboard' => $dashboardSource, 'login' => $loginSource] as $pageName => $source) {
    test_case($pageName . ' uses the requested light theme', function () use ($source): void {
        foreach (['color-scheme:light', '#F4F7FB', '#1F2937', '#DCE4EE', '#0891B2', '#DC2626'] as $color) {
            expect_true(str_contains($source, $color));
        }
        expect_true(!str_contains($source, 'color-scheme:dark'));
    });
}
test_case('Admin reusable modal supports ESC errors danger and custom forms', function () use ($dashboardSource): void {
    foreach (['<dialog id="modal"', 'modal-form', 'modal-description', 'modal-error',
        "addEventListener('cancel'", 'danger=false', 'build(body)', 'form.reportValidity()'] as $feature) {
        expect_true(str_contains($dashboardSource, $feature), $feature);
    }
});
test_case('Token UI uses complete selectable monospace values', function () use ($dashboardSource): void {
    foreach (['user-select:text', 'min-width:32ch', 'tokenView(r.token)', 'tokenView(d.token.token)', 'ui-monospace'] as $feature) {
        expect_true(str_contains($dashboardSource, $feature));
    }
    expect_true(!str_contains($dashboardSource, 'token_hint'));
    expect_true(!str_contains($dashboardSource, 'text-overflow:ellipsis'));
});
test_case('Token copy has Clipboard fallback and in-page success', function () use ($dashboardSource): void {
    foreach (['ondblclick', 'navigator.clipboard.writeText(token)', "execCommand('copy')", '手动复制 Token', '✓ Token 已复制'] as $feature) {
        expect_true(str_contains($dashboardSource, $feature));
    }
});
test_case('Log UI hides internal Token ID and submits full Token', function () use ($dashboardSource): void {
    expect_true(!str_contains($dashboardSource, 'Token ID'));
    expect_true(!str_contains($dashboardSource, 'token_id'));
    expect_true(str_contains($dashboardSource, "query.set('token',token.value)"));
});
test_case('Mapping modal makes source readonly and target wide editable', function () use ($dashboardSource): void {
    expect_true(str_contains($dashboardSource, "node('code',row.source_host,'source-host')"));
    expect_true(str_contains($dashboardSource, 'mapping-target'));
    expect_true(str_contains($dashboardSource, 'wide:true'));
    expect_true(!str_contains($dashboardSource, 'source_host=target_host'));
});
test_case('HTTP display includes Chinese statuses without treating 4xx as success', function () use ($dashboardSource): void {
    foreach (["200:'成功'", "400:'请求错误'", "401:'未授权'", "403:'已拦截'", "404:'未找到'", "429:'已限速'",
        "500:'服务错误'", "502:'上游/转换异常'", "503:'服务暂不可用'", "504:'上游超时'", "n>=400?'请求被拒绝'"] as $label) {
        expect_true(str_contains($dashboardSource, $label));
    }
});
test_case('Decision labels retain database codes and have Chinese fallback', function () use ($dashboardSource): void {
    foreach (["PASS:'正常放行'", "TOKEN_BLOCKED:'Token黑名单'", "TOKEN_TEMP_BLOCKED:'Token临时封禁'",
        "IP_BLACKLIST:'IP黑名单'", "TOKEN_WHITELIST:'Token白名单'", "IP_WHITELIST:'IP白名单'",
        "UA_WHITELIST:'UA白名单'", "UA_BLACKLIST:'UA黑名单'", "RATE_LIMIT:'请求限速'", '其他处理结果'] as $label) {
        expect_true(str_contains($dashboardSource, $label));
    }
});
test_case('Admin errors and password labels are Chinese', function () use ($dashboardSource): void {
    expect_true(str_contains($dashboardSource, '新密码（至少6位）'));
    expect_same('请先登录后台', admin_error_message('Authentication required'));
    expect_same('当前密码不正确', admin_error_message('当前密码不正确'));
    expect_true(preg_match('/\p{Han}/u', admin_error_message('Unknown future error')) === 1);
});
test_case('Static HTML does not embed complete Token data', function () use ($dashboardSource): void {
    expect_true(!preg_match('/[0-9a-f]{32}/', $dashboardSource));
    expect_true(!str_contains($dashboardSource, 'token_analysis_rows('));
});

test_case('off worker first event immediately assigns a stable leaf', function () use ($workflowPdo, $workflowEvent, $workflowToken): void {
    expect_same('off', tracking_mode($workflowPdo));
    ingest_token_event($workflowPdo, $workflowEvent, 'workflow', 1);
    expect_same(1, table_count($workflowPdo, 'tracking_assignments'));
    $leaf = tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken));
    expect_true(tracking_group_is_active_leaf($workflowPdo, $leaf));
});
test_case('Repeat events keep the original assignment and policy code', function () use ($workflowPdo, $workflowEvent, $workflowToken): void {
    $before = tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken));
    ingest_token_event($workflowPdo, $workflowEvent, 'workflow', 2);
    expect_same($before, tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken)));
    expect_same(1, table_count($workflowPdo, 'tracking_assignments'));
    expect_same(['PASS'], $workflowPdo->query('SELECT DISTINCT decision FROM access_logs')->fetchAll(PDO::FETCH_COLUMN));
});
test_case('Token analysis returns complete Token and current group but not ciphertext', function () use ($workflowPdo, $workflowToken): void {
    $rows = token_analysis_rows($workflowPdo);
    expect_same($workflowToken, $rows[0]['token']);
    expect_true(in_array($rows[0]['tracking_group_path'], ['1', '2', '3'], true));
    expect_true(!isset($rows[0]['token_encrypted']));
});
test_case('Token detail returns complete Token without ciphertext', function () use ($workflowPdo, $workflowToken): void {
    $id = (int) $workflowPdo->query('SELECT id FROM tokens LIMIT 1')->fetchColumn();
    $detail = token_detail_data($workflowPdo, $id, '24h');
    expect_same($workflowToken, $detail['token']['token']);
    expect_true($detail['token']['tracking_group_path'] !== null);
    expect_true(!isset($detail['token']['token_encrypted']));
});
test_case('Logs accept exact full Token search and return group with complete Token', function () use ($workflowPdo, $workflowToken): void {
    $result = access_log_page($workflowPdo, ['token' => $workflowToken]);
    expect_same(2, count($result['rows']));
    foreach ($result['rows'] as $row) {
        expect_same($workflowToken, $row['token']);
        expect_true($row['tracking_group_path'] !== null);
        expect_true(!isset($row['token_encrypted']));
        expect_same('/api/v1/test/subscribe', $row['request_path']);
    }
});
test_case('Unknown valid Token log search returns empty', function () use ($workflowPdo): void {
    expect_same([], access_log_page($workflowPdo, ['token' => str_repeat('f', 32)])['rows']);
});
test_case('Malformed Token log search is rejected before querying', function () use ($workflowPdo): void {
    foreach (['abc', str_repeat('A', 32), "' OR 1=1 --", str_repeat('0', 31)] as $invalid) {
        expect_exception(static fn () => access_log_page($workflowPdo, ['token' => $invalid]), InvalidArgumentException::class);
    }
});
test_case('Old unassociated logs show null Token and group', function () use ($workflowPdo): void {
    $workflowPdo->exec("INSERT INTO access_logs (token_id,client_ip,user_agent,request_path,status_code,decision,created_at) "
        . "VALUES (NULL,'192.0.2.99','Legacy','/',404,'PASS'," . time() . ')');
    $row = access_log_page($workflowPdo, ['ua' => 'Legacy'])['rows'][0];
    expect_same(null, $row['token']);
    expect_same(null, $row['tracking_group_path']);
});
test_case('Log page bounds Token decryption to 50 rows', function () use ($workflowPdo, $workflowEvent): void {
    for ($i = 0; $i < 55; $i++) ingest_token_event($workflowPdo, $workflowEvent, 'pages', $i);
    expect_same(50, count(access_log_page($workflowPdo, [])['rows']));
    expect_true(count(access_log_page($workflowPdo, ['page' => 2])['rows']) > 0);
});
test_case('Legacy off Tokens backfill hashes without changing existing assignments', function () use ($workflowPdo, $workflowToken): void {
    $before = tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken));
    $legacyToken = str_repeat('a', 32);
    save_token($workflowPdo, $legacyToken, 'NORMAL');
    $rows = token_analysis_rows($workflowPdo);
    expect_same(2, table_count($workflowPdo, 'tracking_assignments'));
    expect_same($before, tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken)));
    foreach ($rows as $row) expect_true($row['tracking_group_path'] !== null);
});
test_case('Schema stays v3 and has no plaintext Token columns', function () use ($workflowPdo, $workflowToken): void {
    expect_same(3, (int) $workflowPdo->query('PRAGMA user_version')->fetchColumn());
    foreach (['tokens', 'access_logs', 'tracking_assignments'] as $table) {
        $columns = array_column($workflowPdo->query('PRAGMA table_info(' . $table . ')')->fetchAll(), 'name');
        foreach (['token', 'plaintext', 'token_plaintext'] as $plaintext) expect_true(!in_array($plaintext, $columns, true));
    }
    $encrypted = $workflowPdo->query('SELECT token_encrypted FROM tokens LIMIT 1')->fetchColumn();
    expect_true(!str_contains($encrypted, $workflowToken));
    expect_same(64, strlen($workflowPdo->query('SELECT token_hash FROM tracking_assignments LIMIT 1')->fetchColumn()));
});

foreach (['123456', 'abcdef', 'abc123', 'kuaiyun1', 'abcdefg'] as $password) {
    test_case('Manual password accepts ' . strlen($password) . '-byte ' . $password, function () use ($password): void {
        $hash = password_hash_secure($password);
        expect_true(password_verify($password, $hash));
        expect_true($hash !== $password);
        expect_true(password_get_info($hash)['algoName'] !== 'unknown');
    });
}
test_case('Both password entry points reject five bytes', function () use ($workflowPdo): void {
    expect_exception(static fn () => password_hash_secure('12345'), InvalidArgumentException::class);
    expect_exception(static fn () => change_admin_password($workflowPdo, 1, '123456', '12345'), InvalidArgumentException::class);
});
test_case('Password hashing accepts 1024 bytes and rejects 1025', function (): void {
    $password = str_repeat('a', 1024);
    expect_true(password_verify($password, password_hash_secure($password)));
    expect_exception(static fn () => password_hash_secure($password . 'a'), InvalidArgumentException::class);
});
test_case('Password changes still increment auth version and replace only the secure hash', function () use ($workflowPdo): void {
    $id = create_admin($workflowPdo, 'workflow_admin', '123456');
    expect_same(2, change_admin_password($workflowPdo, $id, '123456', 'abcdef'));
    expect_same(null, authenticate_admin($workflowPdo, 'workflow_admin', '123456'));
    expect_same(2, authenticate_admin($workflowPdo, 'workflow_admin', 'abcdef')['auth_version']);
    expect_exception(static fn () => change_admin_password($workflowPdo, $id, 'wrong', 'abc123'), DomainException::class);
    expect_exception(static fn () => change_admin_password($workflowPdo, $id, 'abcdef', str_repeat('x', 1025)), InvalidArgumentException::class);
});

$yamlSource = <<<'YAML'
proxies:
  - name: label.example.invalid
    type: vless
    server: FIRST.Example.Invalid
    port: 443
    sni: sni.example.invalid
    servername: servername.example.invalid
    reality-opts:
      public-key: reality.example.invalid
  - name: second
    type: trojan
    server: second.example.invalid
    port: 443
dns:
  nameserver: [dns.example.invalid]
YAML;
$vmessSource = 'vmess://' . base64_encode(json_encode(['add' => 'VMESS.Example.Invalid',
    'sni' => 'sni.example.invalid', 'host' => 'web.example.invalid', 'ps' => 'name.example.invalid',
    'port' => '443', 'id' => 'test-id'], JSON_THROW_ON_ERROR));
$uriSource = 'vless://id@URI.Example.Invalid:443?sni=sni.example.invalid&servername=name.example.invalid&pbk=reality.example.invalid#label.example.invalid';
foreach ([
    'YAML complete connection server set' => [$yamlSource, ['first.example.invalid', 'second.example.invalid']],
    'VMess add only' => [$vmessSource, ['vmess.example.invalid']],
    'URI authority only' => [$uriSource, ['uri.example.invalid']],
    'outer Base64 URI' => [base64_encode($uriSource), ['uri.example.invalid']],
    'outer Base64 YAML' => [base64_encode($yamlSource), ['first.example.invalid', 'second.example.invalid']],
    'outer Base64 VMess' => [base64_encode($vmessSource), ['vmess.example.invalid']],
    'IPv4 authority' => ['trojan://pass@192.0.2.1:443?sni=sni.example.invalid', ['192.0.2.1']],
    'IPv6 authority' => ['hy2://pass@[2001:0db8::1]:443#label.example.invalid', ['2001:db8::1']],
    'legacy SS credential and authority' => ['ss://' . base64_encode('method:pass@SS.Example.Invalid:443') . '#name.example.invalid', ['ss.example.invalid']],
    'case-insensitive deduplication' => ["trojan://p@URI.Example.Invalid:443\nvless://x@uri.example.invalid:443", ['uri.example.invalid']],
] as $name => [$body, $expected]) {
    test_case('Source discovery: ' . $name, function () use ($body, $expected): void {
        expect_same($expected, tracking_subscription_source_hosts($body));
    });
}
foreach (['ordinary host.example.invalid string', 'https://web.example.invalid/',
    "proxies:\n  - name: sni.example.invalid\n    sni: tls.example.invalid\n",
    'vmess://' . base64_encode('{"sni":"sni.example.invalid"}'),
    "trojan://p@valid.example.invalid:443\nvless://id@:443"] as $index => $malformed) {
    test_case('Source discovery rejects unsupported or invalid structure ' . $index, function () use ($malformed): void {
        expect_exception(static fn () => tracking_subscription_source_hosts($malformed), TrackingTransformFailure::class);
    });
}
test_case('Discovery and default conversion share structured parsing with strict mapping lookup', function () use ($uriSource): void {
    expect_exception(static fn () => tracking_transform_subscription_body($uriSource, []), TrackingTransformFailure::class);
    expect_exception(static fn () => tracking_transform_subscription_body($uriSource, ['other.example.invalid' => 'target.example.invalid']), TrackingTransformFailure::class);
    $result = tracking_transform_subscription_body($uriSource, ['uri.example.invalid' => 'target.example.invalid']);
    expect_true(str_contains($result['content'], '@target.example.invalid:443'));
    expect_true(str_contains($result['content'], 'sni=sni.example.invalid'));
    expect_true(str_contains($result['content'], 'pbk=reality.example.invalid'));
});

$sourcePdo = open_database($temporaryRoot . '/admin-sources.db');
initialize_database($sourcePdo);
test_case('Preflight source learning syncs all ACTIVE leaves with null targets', function () use ($sourcePdo, $yamlSource): void {
    tracking_set_mode($sourcePdo, 'preflight');
    tracking_sync_source_hosts($sourcePdo, tracking_subscription_source_hosts($yamlSource));
    foreach (tracking_active_leaves($sourcePdo) as $leaf) {
        $rows = tracking_group_mappings($sourcePdo, (int) $leaf['id']);
        expect_same(['first.example.invalid', 'second.example.invalid'], array_column($rows, 'source_host'));
        expect_same([null, null], array_column($rows, 'target_host'));
    }
});
test_case('Learning preserves configured targets and old sources and deduplicates casing', function () use ($sourcePdo): void {
    $leaf = tracking_active_leaves($sourcePdo)[0];
    tracking_save_group_targets($sourcePdo, (int) $leaf['id'], [
        ['source_host' => 'first.example.invalid', 'target_host' => 'keep.example.invalid'],
        ['source_host' => 'second.example.invalid', 'target_host' => 'second-target.example.invalid'],
    ]);
    tracking_sync_source_hosts($sourcePdo, ['FIRST.EXAMPLE.INVALID.', 'new.example.invalid']);
    $rows = tracking_group_mappings($sourcePdo, (int) $leaf['id']);
    expect_same(['first.example.invalid', 'new.example.invalid', 'second.example.invalid'], array_column($rows, 'source_host'));
    expect_same(['keep.example.invalid', null, 'second-target.example.invalid'], array_column($rows, 'target_host'));
});
test_case('Admin target-only save cannot add or remove a discovered source', function () use ($sourcePdo): void {
    $id = (int) tracking_active_leaves($sourcePdo)[0]['id'];
    $rows = tracking_group_mappings($sourcePdo, $id);
    $removed = array_slice($rows, 1);
    expect_exception(static fn () => tracking_save_group_targets($sourcePdo, $id, $removed), DomainException::class);
    $added = [...$rows, ['source_host' => 'forged.example.invalid', 'target_host' => 'target.example.invalid']];
    expect_exception(static fn () => tracking_save_group_targets($sourcePdo, $id, $added), DomainException::class);
    expect_same($rows, tracking_group_mappings($sourcePdo, $id));
});
test_case('Target host backend rejects URL and preserves transaction on failure', function () use ($sourcePdo): void {
    $id = (int) tracking_active_leaves($sourcePdo)[0]['id'];
    $rows = tracking_group_mappings($sourcePdo, $id);
    $invalid = array_map(static fn ($row) => ['source_host' => $row['source_host'], 'target_host' => 'https://invalid.example.invalid'], $rows);
    expect_exception(static fn () => tracking_save_group_targets($sourcePdo, $id, $invalid), InvalidArgumentException::class);
    expect_same($rows, tracking_group_mappings($sourcePdo, $id));
});
test_case('Split DRAFT children inherit every source and no parent target', function () use ($sourcePdo): void {
    $parent = tracking_active_leaves($sourcePdo)[0];
    $sources = array_column(tracking_group_mappings($sourcePdo, (int) $parent['id']), 'source_host');
    $children = tracking_create_split($sourcePdo, (int) $parent['id']);
    foreach ($children as $child) {
        $rows = tracking_group_mappings($sourcePdo, (int) $child['id']);
        expect_same($sources, array_column($rows, 'source_host'));
        expect_same([null, null, null], array_column($rows, 'target_host'));
    }
});
test_case('Sources learned after draft creation also reach pending children', function () use ($sourcePdo): void {
    tracking_sync_source_hosts($sourcePdo, ['late.example.invalid']);
    foreach (tracking_list_groups($sourcePdo) as $group) {
        if ($group['status'] !== 'DRAFT') continue;
        expect_true(in_array('late.example.invalid', array_column($group['mappings'], 'source_host'), true));
    }
});
test_case('Stale mapping form cannot prune a newly learned source', function () use ($sourcePdo): void {
    $id = (int) tracking_active_leaves($sourcePdo)[0]['id'];
    $old = tracking_group_mappings($sourcePdo, $id);
    tracking_sync_source_hosts($sourcePdo, ['concurrent.example.invalid']);
    expect_exception(static fn () => tracking_save_group_targets($sourcePdo, $id, $old), DomainException::class);
    expect_true(in_array('concurrent.example.invalid', array_column(tracking_group_mappings($sourcePdo, $id), 'source_host'), true));
});
test_case('Missing learned targets still block enforced activation', function () use ($sourcePdo): void {
    expect_exception(static fn () => tracking_set_mode($sourcePdo, 'enforced'), DomainException::class);
    expect_same('preflight', tracking_mode($sourcePdo));
});
test_case('Token list detail and log group joins follow recursive activated leaves', function () use ($workflowPdo, $workflowToken): void {
    tracking_sync_source_hosts($workflowPdo, ['origin.example.invalid']);
    $hash = token_hash_value($workflowToken);
    $firstId = tracking_assignment_for_hash($workflowPdo, $hash);
    $oldPath = tracking_group($workflowPdo, $firstId)['path'];
    for ($depth = 0; $depth < 2; $depth++) {
        $parent = tracking_assignment_for_hash($workflowPdo, $hash);
        $children = tracking_create_split($workflowPdo, $parent);
        foreach ($children as $child) {
            tracking_save_group_targets($workflowPdo, (int) $child['id'], [
                ['source_host' => 'origin.example.invalid', 'target_host' => 'child.example.invalid'],
            ]);
        }
        tracking_activate_split($workflowPdo, $parent);
    }
    $newPath = tracking_group($workflowPdo, tracking_assignment_for_hash($workflowPdo, $hash))['path'];
    expect_true(str_starts_with($newPath, $oldPath . '.'));
    expect_same(3, count(explode('.', $newPath)));
    $row = array_values(array_filter(token_analysis_rows($workflowPdo), static fn ($row) => $row['token'] === $workflowToken))[0];
    expect_same($newPath, $row['tracking_group_path']);
    expect_same($newPath, token_detail_data($workflowPdo, (int) $row['id'], '24h')['token']['tracking_group_path']);
    expect_same($newPath, access_log_page($workflowPdo, ['token' => $workflowToken])['rows'][0]['tracking_group_path']);
    expect_same('off', tracking_mode($workflowPdo));
});
test_case('Current group filter returns complete Tokens for the active leaf', function () use ($workflowPdo, $workflowToken): void {
    $id = tracking_assignment_for_hash($workflowPdo, token_hash_value($workflowToken));
    $rows = token_analysis_rows($workflowPdo, 50, $id);
    expect_true(count($rows) >= 1);
    foreach ($rows as $row) expect_same($id, (int) $row['tracking_group_id']);
});
test_case('Analysis caps decrypted Tokens at 50 even for a larger requested limit', function () use ($workflowPdo): void {
    for ($i = 1; $i <= 60; $i++) save_token($workflowPdo, sprintf('%032x', $i), 'NORMAL');
    $rows = token_analysis_rows($workflowPdo, 10000);
    expect_same(50, count($rows));
    foreach ($rows as $row) expect_true($row['tracking_group_path'] !== null);
});

$workflowPdo = null;
$sourcePdo = null;
