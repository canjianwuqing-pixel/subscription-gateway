<?php

declare(strict_types=1);

function flexible_split_fixture(): array
{
    [$db, $parent] = mapping_json_fixture();
    foreach (tracking_active_leaves($db) as $leaf) tracking_save_group_targets($db, (int) $leaf['id'], [
        ['source_host' => 'na001.example.com', 'target_host' => 'parent-' . $leaf['path'] . '.example.com'],
    ]);
    for ($i = 0; $i < 120; $i++) tracking_assignment_for_hash($db, hash('sha256', 'flexible-' . $i));
    return [$db, $parent];
}
function flexible_fill_children(PDO $db, int $parent): array
{
    $children = tracking_children($db, $parent, 'DRAFT');
    foreach ($children as $child) {
        $rows = array_map(static fn ($row) => ['source_host' => $row['source_host'],
            'target_host' => 'child-' . $child['id'] . '.example.com'], tracking_group_mappings($db, (int) $child['id']));
        tracking_save_group_targets($db, (int) $child['id'], $rows);
    }
    return $children;
}
function flexible_assignments(PDO $db): array
{
    return $db->query('SELECT * FROM tracking_assignments ORDER BY token_hash')->fetchAll();
}

/** Test-only import of a split created by the previous N=2..20 release.
 * Never use the new creation/activation API to construct historical data.
 */
function historical_split_fixture(PDO $db, int $parent, int $count): array
{
    $path = tracking_group($db, $parent)['path'];
    $insert = $db->prepare("INSERT INTO tracking_groups (parent_id,child_no,path,status,created_at,updated_at) VALUES (:parent,:no,:path,'DRAFT',1,1)");
    $mapping = $db->prepare('INSERT INTO tracking_entry_mappings (group_id,source_host,target_host,created_at,updated_at) VALUES (:id,:source,NULL,1,1)');
    foreach (range(1, $count) as $no) {
        $insert->execute([':parent' => $parent, ':no' => $no, ':path' => $path . '.' . $no]);
        $id = (int) $db->lastInsertId();
        foreach (tracking_group_mappings($db, $parent) as $row) $mapping->execute([':id' => $id, ':source' => $row['source_host']]);
    }
    return tracking_children($db, $parent, 'DRAFT');
}
function historical_activate_fixture(PDO $db, int $parent): int
{
    $children = tracking_children($db, $parent, 'DRAFT');
    $statement = $db->prepare("UPDATE tracking_groups SET status='ACTIVE' WHERE parent_id=:parent AND status='DRAFT'");
    $statement->execute([':parent' => $parent]);
    $move = $db->prepare('UPDATE tracking_assignments SET group_id=:child WHERE token_hash=:hash');
    $moved = 0;
    foreach (flexible_assignments($db) as $row) {
        if ((int) $row['group_id'] !== $parent) continue;
        $no = tracking_child_number($row['token_hash'], $parent, count($children));
        $move->execute([':child' => (int) $children[$no - 1]['id'], ':hash' => $row['token_hash']]);
        $moved++;
    }
    $db->exec('UPDATE tracking_groups SET split_at=1 WHERE id=' . $parent);
    return $moved;
}

foreach ([2, 3, 4, 20] as $count) {
    test_case(($count === 2 ? 'New binary split' : 'Historical ACTIVE ' . $count . '-child split') . ' keeps other branches unchanged', function () use ($count): void {
        [$db, $parent] = flexible_split_fixture();
        $before = flexible_assignments($db);
        $children = $count === 2 ? tracking_create_split($db, $parent) : historical_split_fixture($db, $parent, $count);
        expect_same($count, count($children));
        expect_same(range(1, $count), array_map('intval', array_column($children, 'child_no')));
        expect_same(array_map(fn ($i) => '1.' . $i, range(1, $count)), array_column($children, 'path'));
        expect_same($before, flexible_assignments($db));
        flexible_fill_children($db, $parent);
        if ($count === 2) expect_same(2, count(tracking_validate_split($db, $parent)));
        else expect_exception(fn () => tracking_validate_split($db, $parent), DomainException::class);
        $expectedMoved = count(array_filter($before, fn ($row) => (int) $row['group_id'] === $parent));
        expect_same($expectedMoved, $count === 2 ? tracking_activate_split($db, $parent) : historical_activate_fixture($db, $parent));
        $after = array_column(flexible_assignments($db), null, 'token_hash');
        foreach ($before as $row) {
            if ((int) $row['group_id'] === $parent) {
                $no = tracking_child_number($row['token_hash'], $parent, $count);
                expect_same((int) $children[$no - 1]['id'], (int) $after[$row['token_hash']]['group_id']);
                expect_same((int) $after[$row['token_hash']]['group_id'], tracking_assignment_for_hash($db, $row['token_hash']));
            } else expect_same($row, $after[$row['token_hash']], 'Unrelated assignment changed');
        }
        expect_exception(fn () => tracking_create_split($db, $parent, 2), DomainException::class);
        expect_exception(fn () => tracking_cancel_split($db, $parent), DomainException::class);
        expect_exception(fn () => tracking_delete_draft_group($db, (int) $children[0]['id']), DomainException::class);
    });
}
foreach ([1, 21, 0, -1, 3.5, '4', true, null, 3, 4, 20, '2', 2.0] as $index => $count) {
    test_case('Backend rejects invalid child_count ' . $index, function () use ($count): void {
        expect_exception(fn () => validate_tracking_child_count($count), InvalidArgumentException::class);
        if (is_int($count)) {
            [$db, $parent] = flexible_split_fixture();
            expect_exception(fn () => tracking_create_split($db, $parent, $count), InvalidArgumentException::class);
            expect_same([], tracking_children($db, $parent, 'DRAFT'));
        }
    });
}
test_case('N=3 HMAC matches the original algorithm for fixed parents and hashes', function (): void {
    foreach ([1, 2, 7, 12345] as $parent) {
        for ($i = 0; $i < 1000; $i++) {
            $hash = hash('sha256', 'legacy-compatibility-' . $i);
            $digest = hash_hmac('sha256', 'parent:' . $parent . "\0" . $hash, tracking_group_key(), true);
            $old = unpack('Nvalue', substr($digest, 0, 4))['value'] % 3 + 1;
            expect_same($old, tracking_child_number($hash, $parent, 3));
            expect_same($old, tracking_child_number($hash, $parent));
        }
    }
});
foreach ([2, 4, 5, 20] as $count) {
    test_case('Dynamic HMAC is stable and independently salted by parent for N=' . $count, function () use ($count): void {
        $different = false;
        for ($i = 0; $i < 100; $i++) {
            $hash = hash('sha256', 'stable-n-' . $i);
            $n = tracking_child_number($hash, 2, $count);
            expect_same($n, tracking_child_number($hash, 2, $count));
            expect_true($n >= 1 && $n <= $count);
            if ($n !== tracking_child_number($hash, 3, $count)) $different = true;
        }
        expect_true($different);
    });
}
test_case('Runtime supports binary then historical 4 and 5 children with independent counts', function (): void {
    [$db, $parent] = flexible_split_fixture();
    foreach ([2, 4, 5] as $count) {
        $children = $count === 2 ? tracking_create_split($db, $parent) : historical_split_fixture($db, $parent, $count);
        flexible_fill_children($db, $parent);
        if ($count === 2) tracking_activate_split($db, $parent);
        else historical_activate_fixture($db, $parent);
        expect_same($count, count(tracking_children($db, $parent)));
        $parent = (int) $children[$count === 4 ? 2 : 1]['id'];
    }
    expect_same('1.2.3.2', tracking_group($db, $parent)['path']);
    for ($i = 0; $i < 100; $i++) {
        $hash = hash('sha256', 'new-recursive-' . $i);
        $id = tracking_assignment_for_hash($db, $hash);
        expect_true(tracking_group_is_active_leaf($db, $id));
        expect_same($id, tracking_descend_to_leaf($db, $hash, 1));
    }
});
foreach ([0, 1, 3] as $deletedIndex) {
    test_case('Delete DRAFT index ' . $deletedIndex . ' renumbers paths and preserves mappings and assignments', function () use ($deletedIndex): void {
        [$db, $parent] = flexible_split_fixture();
        $children = historical_split_fixture($db, $parent, 4);
        flexible_fill_children($db, $parent);
        $before = flexible_assignments($db);
        $maps = [];
        foreach ($children as $child) $maps[$child['id']] = tracking_group_mappings($db, (int) $child['id']);
        $deleted = (int) $children[$deletedIndex]['id'];
        tracking_delete_draft_group($db, $deleted);
        $remaining = tracking_children($db, $parent, 'DRAFT');
        expect_same([1, 2, 3], array_map('intval', array_column($remaining, 'child_no')));
        expect_same(['1.1', '1.2', '1.3'], array_column($remaining, 'path'));
        foreach ($remaining as $child) expect_same($maps[$child['id']], tracking_group_mappings($db, (int) $child['id']));
        expect_same([], tracking_group_mappings($db, $deleted));
        expect_same($before, flexible_assignments($db));
        expect_same([], $db->query('PRAGMA foreign_key_check')->fetchAll());
    });
}
test_case('Cancel pending split preserves parent mappings all assignments and other branches', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $children = historical_split_fixture($db, $parent, 4);
    flexible_fill_children($db, $parent);
    $other = (int) tracking_active_leaves($db)[1]['id'];
    tracking_create_split($db, $other, 2);
    $otherBefore = tracking_children($db, $other, 'DRAFT');
    $parentBefore = tracking_group($db, $parent);
    $mapsBefore = tracking_group_mappings($db, $parent);
    $before = flexible_assignments($db);
    tracking_cancel_split($db, $parent);
    expect_same([], tracking_children($db, $parent, 'DRAFT'));
    foreach ($children as $child) expect_same([], tracking_group_mappings($db, (int) $child['id']));
    expect_same($parentBefore, tracking_group($db, $parent));
    expect_same($mapsBefore, tracking_group_mappings($db, $parent));
    expect_same($before, flexible_assignments($db));
    expect_same($otherBefore, tracking_children($db, $other, 'DRAFT'));
    expect_true(tracking_group_is_active_leaf($db, $parent));
    expect_same(2, count(tracking_create_split($db, $parent)));
});
foreach (['ACTIVE', 'ARCHIVED', 'assignment', 'child'] as $reason) {
    test_case('Unsafe DRAFT deletion is rejected for ' . $reason, function () use ($reason): void {
        [$db, $parent] = flexible_split_fixture();
        $children = tracking_create_split($db, $parent, 2);
        $id = (int) $children[0]['id'];
        if (in_array($reason, ['ACTIVE', 'ARCHIVED'], true)) {
            $statement = $db->prepare('UPDATE tracking_groups SET status = :status WHERE id = :id');
            $statement->execute([':status' => $reason, ':id' => $id]);
        } elseif ($reason === 'assignment') {
            $statement = $db->prepare('UPDATE tracking_assignments SET group_id = :id WHERE token_hash = :hash');
            $statement->execute([':id' => $id, ':hash' => flexible_assignments($db)[0]['token_hash']]);
        } else {
            $statement = $db->prepare("INSERT INTO tracking_groups (parent_id,child_no,path,status,created_at,updated_at) VALUES (:id,1,'1.1.1','DRAFT',1,1)");
            $statement->execute([':id' => $id]);
        }
        $groups = $db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll();
        $assignments = flexible_assignments($db);
        expect_exception(fn () => tracking_delete_draft_group($db, $id), DomainException::class);
        expect_exception(fn () => tracking_cancel_split($db, $parent), DomainException::class);
        expect_same($groups, $db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll());
        expect_same($assignments, flexible_assignments($db));
    });
}
test_case('One remaining DRAFT cannot activate and deleting the last allows recreation', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $children = tracking_create_split($db, $parent, 2);
    flexible_fill_children($db, $parent);
    tracking_delete_draft_group($db, (int) $children[0]['id']);
    expect_exception(fn () => tracking_activate_split($db, $parent), DomainException::class);
    tracking_delete_draft_group($db, (int) $children[1]['id']);
    expect_same([], tracking_children($db, $parent, 'DRAFT'));
    expect_same(2, count(tracking_create_split($db, $parent, 2)));
});
foreach (['empty target', 'missing source', 'non-contiguous'] as $reason) {
    test_case('Binary split activation still rejects ' . $reason, function () use ($reason): void {
        [$db, $parent] = flexible_split_fixture();
        $children = tracking_create_split($db, $parent);
        if ($reason !== 'empty target') flexible_fill_children($db, $parent);
        $id = (int) $children[0]['id'];
        if ($reason === 'missing source') $db->exec('DELETE FROM tracking_entry_mappings WHERE group_id = ' . $id);
        if ($reason === 'non-contiguous') $db->exec("UPDATE tracking_groups SET child_no = 9, path = '1.9' WHERE id = " . $id);
        $before = flexible_assignments($db);
        expect_exception(fn () => tracking_activate_split($db, $parent), DomainException::class);
        expect_same($before, flexible_assignments($db));
    });
}
foreach (['one child', 'gap'] as $reason) {
    test_case('Corrupt ACTIVE topology ' . $reason . ' fails without guessing another branch', function () use ($reason): void {
        [$db, $parent] = flexible_split_fixture();
        $children = tracking_create_split($db, $parent, 2);
        flexible_fill_children($db, $parent);
        tracking_activate_split($db, $parent);
        $id = (int) $children[1]['id'];
        $db->exec($reason === 'gap' ? "UPDATE tracking_groups SET child_no = 9, path = '1.9' WHERE id = " . $id
            : "UPDATE tracking_groups SET status = 'ARCHIVED' WHERE id = " . $id);
        $row = flexible_assignments($db)[0];
        $statement = $db->prepare('UPDATE tracking_assignments SET group_id = :id WHERE token_hash = :hash');
        $statement->execute([':id' => $parent, ':hash' => $row['token_hash']]);
        $before = flexible_assignments($db);
        expect_exception(fn () => tracking_descend_to_leaf($db, $row['token_hash'], $parent), RuntimeException::class);
        expect_exception(fn () => tracking_assignment_for_hash($db, $row['token_hash']), RuntimeException::class);
        expect_same($before, flexible_assignments($db));
    });
}
test_case('Source discovery reaches all dynamically sized pending children after deletion', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $children = historical_split_fixture($db, $parent, 4);
    tracking_delete_draft_group($db, (int) $children[1]['id']);
    tracking_sync_source_hosts($db, ['new.example.com']);
    foreach (array_merge(tracking_active_leaves($db), tracking_children($db, $parent, 'DRAFT')) as $group) {
        expect_true(in_array('new.example.com', array_column(tracking_group_mappings($db, (int) $group['id']), 'source_host'), true));
    }
});
