<?php

declare(strict_types=1);

function binary_active_fixture(int $count = 2): array
{
    [$db, $parent] = flexible_split_fixture();
    $children = $count === 2 ? tracking_create_split($db, $parent) : historical_split_fixture($db, $parent, $count);
    flexible_fill_children($db, $parent);
    $before = flexible_assignments($db);
    if ($count === 2) tracking_activate_split($db, $parent);
    else historical_activate_fixture($db, $parent);
    return [$db, $parent, $children, $before];
}
function binary_snapshot(PDO $db): array
{
    $snapshot = [];
    foreach (['tracking_groups', 'tracking_assignments', 'tracking_entry_mappings', 'tracking_transform_events', 'settings'] as $table) {
        $snapshot[$table] = $db->query('SELECT * FROM ' . $table . ' ORDER BY 1')->fetchAll();
    }
    return $snapshot;
}
function binary_fill_group(PDO $db, int $id, string $target = 'complete.example.com'): void
{
    tracking_save_group_mappings($db, $id, array_map(static fn ($row) => [
        'source_host' => $row['source_host'], 'target_host' => $target,
    ], tracking_group_mappings($db, $id)));
}

foreach ([null, 2] as $count) {
    test_case('New split creates exactly two children ' . ($count === null ? 'by default' : 'with explicit 2'), function () use ($count): void {
        [$db, $parent] = flexible_split_fixture();
        $before = flexible_assignments($db);
        $children = $count === null ? tracking_create_split($db, $parent) : tracking_create_split($db, $parent, $count);
        expect_same(['1.1', '1.2'], array_column($children, 'path'));
        expect_same([1, 2], array_column($children, 'child_no'));
        expect_same($before, flexible_assignments($db));
    });
}
test_case('Every former new child_count 3 through 20 is rejected without creating rows', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $before = binary_snapshot($db);
    foreach (range(3, 20) as $count) expect_exception(fn () => tracking_create_split($db, $parent, $count), InvalidArgumentException::class);
    expect_same($before, binary_snapshot($db));
    expect_same(2, validate_tracking_child_count(2));
});
test_case('v4 initialization does not change existing root groups or assignments', function (): void {
    [$db] = flexible_split_fixture();
    $before = binary_snapshot($db);
    initialize_database($db);
    expect_same(7, (int) $db->query('PRAGMA user_version')->fetchColumn());
    expect_same($before, binary_snapshot($db));
    expect_same(['1', '2', '3'], array_column(tracking_children($db, 1), 'path'));
});
foreach ([3, 4, 20] as $count) {
    test_case('Historical DRAFT ' . $count . ' is retained and editable but cannot activate', function () use ($count): void {
        [$db, $parent] = flexible_split_fixture();
        $children = historical_split_fixture($db, $parent, $count);
        $before = binary_snapshot($db);
        initialize_database($db);
        tracking_list_groups($db);
        expect_same($before, binary_snapshot($db));
        flexible_fill_children($db, $parent);
        $filled = binary_snapshot($db);
        expect_exception(fn () => tracking_activate_split($db, $parent), DomainException::class);
        expect_same($filled, binary_snapshot($db));
        tracking_cancel_split($db, $parent);
        expect_same([], tracking_children($db, $parent, 'DRAFT'));
        expect_same($before['tracking_assignments'], flexible_assignments($db));
        expect_same(2, count(tracking_create_split($db, $parent)));
    });
    test_case('Historical ACTIVE ' . $count . ' survives initialization and repeated lookups byte-for-byte', function () use ($count): void {
        [$db] = binary_active_fixture($count);
        $before = binary_snapshot($db);
        initialize_database($db);
        foreach ($before['tracking_assignments'] as $row) {
            expect_same((int) $row['group_id'], tracking_assignment_for_hash($db, $row['token_hash']));
            expect_same((int) $row['group_id'], tracking_descend_to_leaf($db, $row['token_hash'], 1));
        }
        expect_same($before, binary_snapshot($db));
    });
}

$undoChecks = [
    'moves every direct child Token to the direct parent' => function ($db, $parent, $children, $before, $moved): void {
        expect_same(count(array_filter($before, fn ($r) => (int) $r['group_id'] === $parent)), $moved);
        $after = array_column(flexible_assignments($db), null, 'token_hash');
        foreach ($before as $row) if ((int) $row['group_id'] === $parent) expect_same($parent, (int) $after[$row['token_hash']]['group_id']);
        foreach ($children as $child) expect_same(0, (int) $db->query('SELECT COUNT(*) FROM tracking_assignments WHERE group_id=' . $child['id'])->fetchColumn());
    },
    'does not touch siblings including timestamps and algorithm version' => function ($db, $parent, $children, $before): void {
        $after = array_column(flexible_assignments($db), null, 'token_hash');
        foreach ($before as $row) if ((int) $row['group_id'] !== $parent) expect_same($row, $after[$row['token_hash']]);
    },
    'restores ACTIVE leaf semantics' => function ($db, $parent): void {
        expect_true(tracking_group_is_active_leaf($db, $parent));
        expect_same('ACTIVE', tracking_group($db, $parent)['status']);
        expect_same([], tracking_children($db, $parent));
    },
    'keeps existing lookups at the parent without further assignment writes' => function ($db, $parent, $children, $before): void {
        $after = flexible_assignments($db);
        foreach ($before as $row) if ((int) $row['group_id'] === $parent) expect_same($parent, tracking_assignment_for_hash($db, $row['token_hash']));
        expect_same($after, flexible_assignments($db));
    },
    'never descends into ARCHIVED children for new Tokens' => function ($db, $parent): void {
        $found = 0;
        for ($i = 0; $i < 100; $i++) {
            $hash = hash('sha256', 'after-undo-' . $i);
            $rootChild = tracking_child_number($hash, 1, 3);
            $id = tracking_assignment_for_hash($db, $hash);
            expect_same($rootChild + 1, $id);
            if ($id === $parent) $found++;
        }
        expect_true($found > 0);
    },
    'uses the retained parent mapping for subscription conversion' => function ($db, $parent): void {
        $result = tracking_transform_subscription_body('trojan://secret@na001.example.com:443#name', tracking_effective_mapping($db, $parent));
        expect_true(str_contains($result['content'], '@parent-1.example.com:443'));
    },
    'retains original historical IDs paths ordinals creation and split times' => function ($db, $parent, $children): void {
        foreach ($children as $child) {
            $archived = tracking_group($db, (int) $child['id']);
            expect_same('ARCHIVED', $archived['status']);
            foreach (['id', 'parent_id', 'child_no', 'path', 'created_at', 'split_at'] as $key) expect_same($child[$key], $archived[$key]);
            expect_true(tracking_group_mappings($db, (int) $child['id']) !== []);
        }
    },
    'keeps schema and foreign-key integrity intact' => function ($db): void {
        expect_same(7, (int) $db->query('PRAGMA user_version')->fetchColumn());
        expect_same([], $db->query('PRAGMA foreign_key_check')->fetchAll());
        expect_same(['ok'], $db->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));
    },
    'hides archived history from the current administration tree' => function ($db, $parent): void {
        $groups = tracking_list_groups($db);
        expect_same(['1', '2', '3'], array_column($groups, 'path'));
        foreach ($groups as $group) expect_same('ACTIVE', $group['status']);
    },
];
foreach ($undoChecks as $label => $check) {
    test_case('ACTIVE undo ' . $label, function () use ($check): void {
        [$db, $parent, $children, $before] = binary_active_fixture();
        $moved = tracking_undo_split($db, $parent);
        $check($db, $parent, $children, $before, $moved);
    });
}
foreach ([3, 4, 20] as $count) {
    test_case('Historical ACTIVE ' . $count . ' can undo safely and re-split into two', function () use ($count): void {
        [$db, $parent, $old, $before] = binary_active_fixture($count);
        tracking_undo_split($db, $parent);
        $new = tracking_create_split($db, $parent);
        expect_same(['1.1', '1.2'], array_column($new, 'path'));
        expect_same($count, count(tracking_children($db, $parent, 'ARCHIVED')));
        flexible_fill_children($db, $parent);
        tracking_activate_split($db, $parent);
        $after = array_column(flexible_assignments($db), null, 'token_hash');
        foreach ($before as $row) if ((int) $row['group_id'] !== $parent) expect_same($row, $after[$row['token_hash']]);
    });
}
foreach (['null target', 'missing source', 'new source'] as $reason) {
    test_case('Enforced undo rejects incomplete retained parent mapping: ' . $reason, function () use ($reason): void {
        [$db, $parent] = binary_active_fixture();
        if ($reason === 'new source') {
            tracking_sync_source_hosts($db, ['new.example.com']);
            foreach (tracking_active_leaves($db) as $leaf) binary_fill_group($db, (int) $leaf['id']);
        } else $db->exec(($reason === 'null target' ? 'UPDATE tracking_entry_mappings SET target_host=NULL WHERE group_id=' : 'DELETE FROM tracking_entry_mappings WHERE group_id=') . $parent);
        tracking_set_mode($db, 'enforced');
        $before = binary_snapshot($db);
        try { tracking_undo_split($db, $parent); throw new RuntimeException('Undo unexpectedly succeeded'); }
        catch (DomainException $error) { expect_same('父组当前没有可用映射，请配置至少1个当前目标入口后再撤销拆分。', $error->getMessage()); }
        expect_same($before, binary_snapshot($db));
    });
}
test_case('Parent mapping can be completed while split without changing effective children', function (): void {
    [$db, $parent, $children] = binary_active_fixture();
    tracking_sync_source_hosts($db, ['new.example.com']);
    foreach (tracking_active_leaves($db) as $leaf) binary_fill_group($db, (int) $leaf['id']);
    tracking_set_mode($db, 'enforced');
    $before = flexible_assignments($db);
    $childMaps = array_map(fn ($child) => tracking_group_mappings($db, (int) $child['id']), $children);
    binary_fill_group($db, $parent, 'restored.example.com');
    expect_same($before, flexible_assignments($db));
    expect_same($childMaps, array_map(fn ($child) => tracking_group_mappings($db, (int) $child['id']), $children));
    tracking_undo_split($db, $parent);
    expect_same(['na001.example.com' => 'restored.example.com', 'new.example.com' => 'restored.example.com'], tracking_effective_mapping($db, $parent));
});
foreach (['ACTIVE', 'DRAFT'] as $status) {
    test_case('Undo rejects deeper ' . $status . ' descendants atomically', function () use ($status): void {
        [$db, $parent, $children] = binary_active_fixture();
        $nested = (int) $children[0]['id'];
        tracking_create_split($db, $nested);
        if ($status === 'ACTIVE') { flexible_fill_children($db, $nested); tracking_activate_split($db, $nested); }
        $before = binary_snapshot($db);
        expect_exception(fn () => tracking_undo_split($db, $parent), DomainException::class);
        expect_same($before, binary_snapshot($db));
    });
}
test_case('Bottom-up undo permits re-splitting all depths while retaining nested history', function (): void {
    [$db, $parent, $children] = binary_active_fixture();
    $nested = (int) $children[0]['id'];
    tracking_create_split($db, $nested);
    flexible_fill_children($db, $nested);
    tracking_activate_split($db, $nested);
    tracking_undo_split($db, $nested);
    tracking_undo_split($db, $parent);
    $new = tracking_create_split($db, $parent);
    flexible_fill_children($db, $parent);
    tracking_activate_split($db, $parent);
    tracking_create_split($db, (int) $new[0]['id']);
    expect_same(['1.1.1', '1.1.2'], array_column(tracking_children($db, (int) $new[0]['id'], 'DRAFT'), 'path'));
    expect_same(4, (int) $db->query("SELECT COUNT(*) FROM tracking_groups WHERE status='ARCHIVED'")->fetchColumn());
    expect_same([], $db->query('PRAGMA foreign_key_check')->fetchAll());
});
foreach (['assignment', 'archive', 'global validation'] as $point) {
    test_case('Undo failure at ' . $point . ' rolls back all changes', function () use ($point): void {
        [$db, $parent, $children] = binary_active_fixture();
        if ($point === 'assignment') $db->exec("CREATE TRIGGER abort_undo BEFORE UPDATE OF group_id ON tracking_assignments WHEN NEW.group_id=$parent BEGIN SELECT RAISE(ABORT,'test failure'); END");
        elseif ($point === 'archive') $db->exec("CREATE TRIGGER abort_undo BEFORE UPDATE OF status ON tracking_groups WHEN NEW.status='ARCHIVED' AND NEW.id=" . $children[1]['id'] . " BEGIN SELECT RAISE(ABORT,'test failure'); END");
        else {
            tracking_set_mode($db, 'enforced');
            $db->exec("CREATE TRIGGER break_sibling AFTER UPDATE OF status ON tracking_groups WHEN NEW.status='ARCHIVED' BEGIN UPDATE tracking_entry_mappings SET target_host=NULL WHERE group_id=3; END");
        }
        $before = binary_snapshot($db);
        expect_exception(fn () => tracking_undo_split($db, $parent), $point === 'global validation' ? DomainException::class : PDOException::class);
        expect_same($before, binary_snapshot($db));
    });
}
foreach ([1, 2, 3, 4] as $id) {
    test_case('Root or permanent main group ' . $id . ' cannot be deleted', function () use ($id): void {
        [$db] = flexible_split_fixture();
        $before = binary_snapshot($db);
        expect_exception(fn () => tracking_delete_draft_group($db, $id), DomainException::class);
        expect_same($before, binary_snapshot($db));
    });
}
test_case('Even a main group marked DRAFT cannot be deleted', function (): void {
    [$db] = flexible_split_fixture();
    $db->exec("UPDATE tracking_groups SET status='DRAFT' WHERE id=2");
    expect_exception(fn () => tracking_delete_draft_group($db, 2), DomainException::class);
});
test_case('ACTIVE child with zero Tokens cannot be individually deleted', function (): void {
    [$db, $parent, $children] = binary_active_fixture();
    $db->exec('UPDATE tracking_assignments SET group_id=' . $parent . ' WHERE group_id=' . $children[0]['id']);
    $before = binary_snapshot($db);
    expect_exception(fn () => tracking_delete_draft_group($db, (int) $children[0]['id']), DomainException::class);
    expect_same($before, binary_snapshot($db));
});
test_case('Root split undo is forbidden and cannot archive permanent 1/2/3', function (): void {
    [$db] = flexible_split_fixture();
    $before = binary_snapshot($db);
    expect_exception(fn () => tracking_undo_split($db, 1), DomainException::class);
    expect_same($before, binary_snapshot($db));
});
test_case('Re-splitting preserves history mappings events creation timestamps and parent IDs', function (): void {
    [$db, $parent, $old] = binary_active_fixture();
    tracking_record_transform_event($db, (int) $old[0]['id'], 'enforced', 'URI', 'SUCCESS');
    tracking_undo_split($db, $parent);
    $before = binary_snapshot($db);
    $new = tracking_create_split($db, $parent);
    expect_same(['1.1', '1.2'], array_column($new, 'path'));
    expect_true(min(array_column($new, 'id')) > max(array_column($old, 'id')));
    foreach ($old as $child) {
        $row = tracking_group($db, (int) $child['id']);
        expect_same('@archived/' . $child['id'] . '/' . $child['path'], $row['path']);
        expect_true($row['child_no'] > 20);
        expect_same($child['parent_id'], $row['parent_id']);
        expect_same($child['created_at'], $row['created_at']);
    }
    expect_same($before['tracking_transform_events'], $db->query('SELECT * FROM tracking_transform_events ORDER BY 1')->fetchAll());
    foreach ($before['tracking_entry_mappings'] as $row) {
        $stmt = $db->prepare('SELECT * FROM tracking_entry_mappings WHERE id=:id'); $stmt->execute([':id' => $row['id']]);
        expect_same($row, $stmt->fetch());
    }
});
test_case('Re-activation hashes only current parent Tokens and leaves all sibling rows untouched', function (): void {
    [$db, $parent] = binary_active_fixture();
    tracking_undo_split($db, $parent);
    $before = flexible_assignments($db);
    $new = tracking_create_split($db, $parent);
    flexible_fill_children($db, $parent);
    tracking_activate_split($db, $parent);
    $after = array_column(flexible_assignments($db), null, 'token_hash');
    foreach ($before as $row) {
        if ((int) $row['group_id'] !== $parent) expect_same($row, $after[$row['token_hash']]);
        else expect_same((int) $new[tracking_child_number($row['token_hash'], $parent, 2) - 1]['id'], (int) $after[$row['token_hash']]['group_id']);
    }
});
test_case('Repeated undo re-split delete and cancel cycles have no slot conflicts', function (): void {
    [$db, $parent] = binary_active_fixture();
    for ($i = 0; $i < 4; $i++) {
        tracking_undo_split($db, $parent);
        $before = flexible_assignments($db);
        $draft = tracking_create_split($db, $parent);
        tracking_delete_draft_group($db, (int) $draft[0]['id']);
        expect_same(['1.1'], array_column(tracking_children($db, $parent, 'DRAFT'), 'path'));
        expect_exception(fn () => tracking_activate_split($db, $parent), DomainException::class);
        tracking_cancel_split($db, $parent);
        expect_same($before, flexible_assignments($db));
        tracking_create_split($db, $parent);
        flexible_fill_children($db, $parent);
        tracking_activate_split($db, $parent);
    }
    expect_same(8, count(tracking_children($db, $parent, 'ARCHIVED')));
    expect_same([], $db->query('PRAGMA foreign_key_check')->fetchAll());
    expect_same(['ok'], $db->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));
});
test_case('Re-split failure rolls back historical path retirement', function (): void {
    [$db, $parent] = binary_active_fixture();
    tracking_undo_split($db, $parent);
    $db->exec("CREATE TRIGGER abort_split BEFORE INSERT ON tracking_groups WHEN NEW.status='DRAFT' BEGIN SELECT RAISE(ABORT,'test failure'); END");
    $before = binary_snapshot($db);
    expect_exception(fn () => tracking_create_split($db, $parent), PDOException::class);
    expect_same($before, binary_snapshot($db));
});
