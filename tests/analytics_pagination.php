<?php
declare(strict_types=1);

// Isolated v7 data: explicit current assignments, never production data or assignment algorithm changes.
$pagingDb = open_database($temporaryRoot . '/analytics-pagination.db');
initialize_database($pagingDb);
$pagingGroups = array_column($pagingDb->query('SELECT path,id FROM tracking_groups')->fetchAll(), 'id', 'path');
$pagingNow = time();
$pagingDb->beginTransaction();
$insertGroup = $pagingDb->prepare("INSERT INTO tracking_groups(parent_id,child_no,path,status,created_at,updated_at) VALUES (?, ?, ?, 'ACTIVE', ?, ?)");
foreach ([...array_map(static fn ($n) => '3.' . $n, range(1, 11)), '3.1.1', '3.1.2', '3.1.1.1', '3.1.1.2'] as $path) {
    $parts = explode('.', $path); $child = (int) array_pop($parts); $parent = implode('.', $parts);
    $insertGroup->execute([$pagingGroups[$parent], $child, $path, $pagingNow, $pagingNow]);
    $pagingGroups[$path] = (int) $pagingDb->lastInsertId();
}
$assign = $pagingDb->prepare('INSERT INTO tracking_assignments(token_hash,group_id,algorithm_version,assigned_at,updated_at) VALUES (?, ?, ?, ?, ?)');
$stamp = $pagingDb->prepare('UPDATE tokens SET created_at=?,last_seen=? WHERE id=?');
$log = $pagingDb->prepare('INSERT INTO access_logs(token_id,client_ip,user_agent,request_path,status_code,decision,created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
for ($i = 1; $i <= 125; $i++) {
    $plain = sprintf('%032x', $i); $id = save_token($pagingDb, $plain);
    $path = $i <= 105 ? '3.1.1' : ($i <= 110 ? '3.1.2' : ($i <= 115 ? '3.1.1.1' : ($i <= 119 ? '3.10' : ($i <= 123 ? '3.11' : ($i === 124 ? '3.1' : '3.2')))));
    $assign->execute([token_hash_value($plain), $pagingGroups[$path], TRACKING_ALGORITHM_VERSION, $pagingNow, $pagingNow]);
    $seen = $pagingNow - 1000 + $i;
    $stamp->execute([$seen, $i % 2 ? $seen : null, $id]);
    $values = [$id, '192.0.2.' . (1 + $i % 3), 'Client/' . ($i % 2), '/api/v1/test/subscribe', $i % 2 ? 403 : 200, $i % 2 ? 'TOKEN_BLOCKED' : 'PASS', $pagingNow - 200 + $i];
    $log->execute($values);
    if ($i === 1) { $values[6] = $pagingNow - 7200; $log->execute($values); }
}
$log->execute([null, '192.0.2.99', 'Legacy', '/', 404, 'PASS', $pagingNow - 50]);
$pagingDb->commit();

function paging_log_rows(PDO $db, array $filters): array
{
    $rows = [];
    for ($page = 1; $page <= 10; $page++) {
        $batch = access_log_page($db, $filters + ['page' => $page])['rows'];
        array_push($rows, ...$batch);
        if (count($batch) < 50) break;
    }
    return $rows;
}

test_case('Token first page returns newest 50 and next-page metadata', function () use ($pagingDb): void {
    $page = token_analysis_page($pagingDb);
    expect_same(1, $page['page']); expect_same(true, $page['has_next']);
    expect_same(range(125, 76), array_column($page['rows'], 'id'));
});
test_case('Token second page returns next 50', function () use ($pagingDb): void {
    $page = token_analysis_page($pagingDb, ['page' => 2]);
    expect_same(2, $page['page']); expect_same(true, $page['has_next']);
    expect_same(range(75, 26), array_column($page['rows'], 'id'));
});
test_case('Token pages have no overlap and cover all rows', function () use ($pagingDb): void {
    $ids = [];
    for ($page = 1; $page <= 3; $page++) array_push($ids, ...array_column(token_analysis_page($pagingDb, ['page' => $page])['rows'], 'id'));
    expect_same(range(125, 1), $ids); expect_same(125, count(array_unique($ids)));
});
test_case('Token sorting uses created time when last_seen is null', function () use ($pagingDb): void {
    $rows = token_analysis_page($pagingDb)['rows'];
    expect_same(125, $rows[0]['id']); expect_same(124, $rows[1]['id']); expect_same(null, $rows[1]['last_seen']);
});
test_case('Equal Token timestamps have stable descending ID order', function () use ($pagingDb, $pagingNow): void {
    $pagingDb->beginTransaction();
    try {
        $pagingDb->exec('UPDATE tokens SET created_at=' . $pagingNow . ',last_seen=' . $pagingNow);
        expect_same(range(125, 76), array_column(token_analysis_page($pagingDb)['rows'], 'id'));
        expect_same(range(75, 26), array_column(token_analysis_page($pagingDb, ['page' => 2])['rows'], 'id'));
    } finally { $pagingDb->rollBack(); }
});
test_case('Final Token page correctly disables next-page metadata', function () use ($pagingDb): void {
    $page = token_analysis_page($pagingDb, ['page' => 3]);
    expect_same(range(25, 1), array_column($page['rows'], 'id')); expect_same(false, $page['has_next']);
});
test_case('Exactly full last page has no next page', function () use ($pagingDb, $pagingGroups): void {
    $page = token_analysis_page($pagingDb, ['limit' => 5, 'group_id' => $pagingGroups['3.1.2']]);
    expect_same(5, count($page['rows'])); expect_same(false, $page['has_next']);
});
test_case('Token group filter persists over page boundaries without including descendants', function () use ($pagingDb, $pagingGroups): void {
    foreach ([1 => range(105, 56), 2 => range(55, 6), 3 => range(5, 1)] as $page => $ids) {
        $result = token_analysis_page($pagingDb, ['page' => $page, 'group_id' => $pagingGroups['3.1.1']]);
        expect_same($ids, array_column($result['rows'], 'id')); expect_same($page < 3, $result['has_next']);
        foreach ($result['rows'] as $row) expect_same('3.1.1', $row['tracking_group_path']);
    }
});
test_case('Empty Token group is one empty page with no next page', function () use ($pagingDb, $pagingGroups): void {
    $page = token_analysis_page($pagingDb, ['group_id' => $pagingGroups['3.9']]);
    expect_same([], $page['rows']); expect_same(false, $page['has_next']);
});
test_case('Token API-style query strings are accepted without losing group filter', function () use ($pagingDb, $pagingGroups): void {
    $page = token_analysis_page($pagingDb, ['limit' => '50', 'page' => '2', 'group_id' => (string) $pagingGroups['3.1.1']]);
    expect_same(2, $page['page']); expect_same(range(55, 6), array_column($page['rows'], 'id'));
});
test_case('Legacy token_analysis_rows remains a bounded rows-only interface', function () use ($pagingDb): void {
    expect_same(token_analysis_page($pagingDb)['rows'], token_analysis_rows($pagingDb));
    expect_same(50, count(token_analysis_rows($pagingDb, 10000))); expect_same(1, count(token_analysis_rows($pagingDb, 0)));
});
test_case('Token page limit caps at 50 and hides internal fields', function () use ($pagingDb): void {
    $result = token_analysis_page($pagingDb, ['limit' => 10000]); expect_same(50, count($result['rows']));
    foreach ($result['rows'] as $row) {
        expect_true(!array_key_exists('token_encrypted', $row)); expect_true(!array_key_exists('sort_seen', $row));
        expect_same(sprintf('%032x', $row['id']), $row['token']);
    }
});
test_case('Lookahead row is not decrypted or returned', function () use ($pagingDb): void {
    $pagingDb->beginTransaction();
    try {
        $pagingDb->exec("UPDATE tokens SET token_encrypted='invalid cipher in the 51st row' WHERE id=75");
        $result = token_analysis_page($pagingDb); expect_same(50, count($result['rows'])); expect_same(true, $result['has_next']);
    } finally { $pagingDb->rollBack(); }
});
test_case('Token maximum allowed page remains bounded', function () use ($pagingDb): void {
    $page = token_analysis_page($pagingDb, ['page' => '10000']); expect_same(10000, $page['page']); expect_same([], $page['rows']); expect_same(false, $page['has_next']);
});
foreach ([0, -1, 10001, '1.5', 'bad', '1 OR 1=1', PHP_INT_MAX, ['1'], true, 1.5, '+1', ''] as $invalid) {
    test_case('Token rejects invalid page ' . json_encode($invalid), function () use ($pagingDb, $invalid): void {
        expect_exception(static fn () => token_analysis_page($pagingDb, ['page' => $invalid]), InvalidArgumentException::class);
    });
}
foreach (['WHITELIST', 'BLOCKED', 'TEMP_BLOCKED', 'NORMAL'] as $state) {
    test_case('Token ' . $state . ' update preserves page and current group query', function () use ($pagingDb, $pagingGroups, $state): void {
        $filters = ['page' => 2, 'group_id' => $pagingGroups['3.1.1']];
        $before = array_column(token_analysis_page($pagingDb, $filters)['rows'], 'id');
        $pagingDb->beginTransaction();
        try {
            save_token($pagingDb, sprintf('%032x', 55), $state, $state === 'TEMP_BLOCKED' ? time() + 3600 : null);
            $page = token_analysis_page($pagingDb, $filters);
            expect_same(2, $page['page']); expect_same($before, array_column($page['rows'], 'id')); expect_same($state, $page['rows'][0]['state']);
        } finally { $pagingDb->rollBack(); }
    });
}

test_case('Logs with absent or empty group filter keep existing behavior', function () use ($pagingDb): void {
    expect_same(access_log_page($pagingDb, []), access_log_page($pagingDb, ['group_id' => '']));
    expect_same(127, count(paging_log_rows($pagingDb, [])));
});
test_case('Log leaf group selects only its current branch', function () use ($pagingDb, $pagingGroups): void {
    $rows = paging_log_rows($pagingDb, ['group_id' => $pagingGroups['3.1.2']]);
    expect_same(5, count($rows)); expect_same(['3.1.2'], array_values(array_unique(array_column($rows, 'tracking_group_path'))));
});
test_case('Log parent includes exact path and every descendant depth', function () use ($pagingDb, $pagingGroups): void {
    $rows = paging_log_rows($pagingDb, ['group_id' => $pagingGroups['3.1'], 'window' => '1h']);
    expect_same(116, count($rows)); $paths = array_values(array_unique(array_column($rows, 'tracking_group_path'))); sort($paths);
    expect_same(['3.1', '3.1.1', '3.1.1.1', '3.1.2'], $paths);
});
test_case('Log group 3.1 cannot match 3.10 or 3.11', function () use ($pagingDb, $pagingGroups): void {
    foreach (paging_log_rows($pagingDb, ['group_id' => $pagingGroups['3.1']]) as $row) expect_true(!in_array($row['tracking_group_path'], ['3.10', '3.11'], true));
});
test_case('Log leaf selection also includes future descendants', function () use ($pagingDb, $pagingGroups): void {
    $rows = paging_log_rows($pagingDb, ['group_id' => $pagingGroups['3.1.1'], 'window' => '1h']);
    expect_same(110, count($rows)); expect_true(in_array('3.1.1.1', array_column($rows, 'tracking_group_path'), true));
});
foreach ([0, -1, 'bad', '1.5', '1 OR 1=1', ['1'], true, str_repeat('9', 32)] as $invalid) {
    test_case('Logs reject invalid group ' . json_encode($invalid), function () use ($pagingDb, $invalid): void {
        expect_exception(static fn () => access_log_page($pagingDb, ['group_id' => $invalid]), InvalidArgumentException::class);
    });
}
test_case('Logs reject nonexistent group as parameter error', function () use ($pagingDb): void {
    expect_exception(static fn () => access_log_page($pagingDb, ['group_id' => 999999999]), InvalidArgumentException::class);
});
$pagingRawLogs = $pagingDb->query('SELECT l.*,t.token_hash,g.path FROM access_logs l LEFT JOIN tokens t ON t.id=l.token_id LEFT JOIN tracking_assignments a ON a.token_hash=t.token_hash LEFT JOIN tracking_groups g ON g.id=a.group_id ORDER BY l.created_at DESC,l.id DESC')->fetchAll();
foreach ([['token' => sprintf('%032x', 1)], ['ip' => '192.0.2.2'], ['ua' => 'Client/1'], ['status' => '403'], ['decision' => 'TOKEN_BLOCKED'], ['window' => '1h'],
    ['token' => sprintf('%032x', 1), 'ip' => '192.0.2.2', 'ua' => 'Client/1', 'status' => '403', 'decision' => 'TOKEN_BLOCKED', 'window' => '1h']] as $filters) {
    test_case('Log group combines with ' . implode('/', array_keys($filters)), function () use ($pagingDb, $pagingGroups, $pagingRawLogs, $filters): void {
        $expected = array_filter($pagingRawLogs, static function ($row) use ($filters): bool {
            if (!in_array($row['path'], ['3.1', '3.1.1', '3.1.1.1', '3.1.2'], true) || $row['created_at'] < time() - time_window($filters['window'] ?? '24h')) return false;
            foreach (['ip' => 'client_ip', 'ua' => 'user_agent', 'status' => 'status_code', 'decision' => 'decision'] as $input => $column) if (isset($filters[$input]) && (string) $row[$column] !== $filters[$input]) return false;
            return !isset($filters['token']) || $row['token_hash'] === token_hash_value($filters['token']);
        });
        expect_true(count($expected) > 0);
        expect_same(array_values(array_column($expected, 'id')), array_column(paging_log_rows($pagingDb, $filters + ['group_id' => $pagingGroups['3.1']]), 'id'));
    });
}
test_case('Log page two keeps group filter and has no overlap', function () use ($pagingDb, $pagingGroups): void {
    $first = access_log_page($pagingDb, ['group_id' => (string) $pagingGroups['3.1']]);
    $second = access_log_page($pagingDb, ['group_id' => (string) $pagingGroups['3.1'], 'page' => 2]);
    expect_same(50, count($second['rows'])); expect_same(2, $second['page']);
    expect_same([], array_values(array_intersect(array_column($first['rows'], 'id'), array_column($second['rows'], 'id'))));
    foreach ($second['rows'] as $row) expect_true(in_array($row['tracking_group_path'], ['3.1', '3.1.1', '3.1.1.1', '3.1.2'], true));
});
test_case('Historical logs display and filter by the current assignment after movement', function () use ($pagingDb, $pagingGroups): void {
    $pagingDb->beginTransaction();
    try {
        $q = $pagingDb->prepare('UPDATE tracking_assignments SET group_id=? WHERE token_hash=?'); $q->execute([$pagingGroups['3.10'], token_hash_value(sprintf('%032x', 1))]);
        expect_same([], access_log_page($pagingDb, ['token' => sprintf('%032x', 1), 'group_id' => $pagingGroups['3.1']])['rows']);
        $rows = access_log_page($pagingDb, ['token' => sprintf('%032x', 1), 'group_id' => $pagingGroups['3.10']])['rows'];
        expect_same(2, count($rows)); foreach ($rows as $row) expect_same('3.10', $row['tracking_group_path']);
    } finally { $pagingDb->rollBack(); }
});
test_case('Pagination and group queries preserve schema, log data and assignments', function () use ($pagingDb, $pagingGroups): void {
    $schema = $pagingDb->query('SELECT name,sql FROM sqlite_master ORDER BY name')->fetchAll();
    $logs = $pagingDb->query('SELECT * FROM access_logs ORDER BY id')->fetchAll();
    $assignments = $pagingDb->query('SELECT * FROM tracking_assignments ORDER BY token_hash')->fetchAll();
    token_analysis_page($pagingDb, ['page' => 2]); access_log_page($pagingDb, ['group_id' => $pagingGroups['3.1']]);
    expect_same(7, (int) $pagingDb->query('PRAGMA user_version')->fetchColumn()); expect_same($schema, $pagingDb->query('SELECT name,sql FROM sqlite_master ORDER BY name')->fetchAll());
    expect_same($logs, $pagingDb->query('SELECT * FROM access_logs ORDER BY id')->fetchAll()); expect_same($assignments, $pagingDb->query('SELECT * FROM tracking_assignments ORDER BY token_hash')->fetchAll());
    expect_same([], $pagingDb->query('PRAGMA foreign_key_check')->fetchAll()); expect_same(['ok'], $pagingDb->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));
});
$pagingDb = null;
