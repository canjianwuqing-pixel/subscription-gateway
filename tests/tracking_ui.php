<?php

declare(strict_types=1);

$trackingUiSource = file_get_contents($root . '/sgw/admin/src/dashboard.php');
foreach (['映射状态', '已完成', '未完成', '未配置', 'mapping-done', 'mapping-partial', 'mapping-missing',
    '入口映射未完成', '无法启用正式模式', '还有', '个目标入口未填写', '至少需要2个子组才能激活',
    '删除待配置子组', '取消待配置拆分', 'trackingSplitPreview', "{child_count}", "count.oninput=update", 'paddingLeft'] as $feature) {
    test_case('Tracking UI exposes ' . $feature, function () use ($trackingUiSource, $feature): void {
        expect_true(str_contains($trackingUiSource, $feature), $feature);
    });
}
test_case('Tracking UI deletion and cancellation are gated on DRAFT and pending leaf states', function () use ($trackingUiSource): void {
    expect_true(str_contains($trackingUiSource, "if(g.status==='DRAFT')add(actions,btn('删除'"));
    expect_true(str_contains($trackingUiSource, 'if(leaf&&g.has_draft_children)'));
    expect_true(str_contains($trackingUiSource, "if(group.status==='ACTIVE'&&group.has_active_children)return{text:'已拆分'"));
    expect_true(str_contains($trackingUiSource, "if(leaves.some(g=>!trackingMappingState(g).complete))"));
});
test_case('Tracking UI retains reusable modals and has no browser prompt confirm or alert', function () use ($trackingUiSource): void {
    expect_same(0, preg_match('/\b(?:prompt|confirm|alert)\s*\(/', $trackingUiSource));
    expect_true(str_contains($trackingUiSource, 'openDialog({title:'));
    expect_true(str_contains($trackingUiSource, "input.classList.toggle('mapping-empty',empty)"));
});
test_case('Tracking API reports 6/6 4/6 and 0/6 independently of assignment join multiplicity', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $sources = array_map(fn ($n) => 'source-' . $n . '.example.com', range(1, 5));
    tracking_sync_source_hosts($db, $sources);
    $rows = array_map(fn ($row) => ['source_host' => $row['source_host'], 'target_host' => 'complete.example.com'], tracking_group_mappings($db, $parent));
    tracking_save_group_targets($db, $parent, $rows);
    $children = tracking_create_split($db, $parent, 2);
    $draft = (int) $children[0]['id'];
    foreach ($rows as $index => &$row) if ($index >= 4) $row['target_host'] = '';
    unset($row);
    tracking_save_group_targets($db, $draft, $rows);
    $groups = array_column(tracking_list_groups($db), null, 'id');
    expect_same(6, $groups[$parent]['mapping_count']);
    expect_same(6, $groups[$parent]['mapping_filled_count']);
    expect_same(6, $groups[$draft]['mapping_count']);
    expect_same(4, $groups[$draft]['mapping_filled_count']);
    expect_same(6, $groups[(int) $children[1]['id']]['mapping_count']);
    expect_same(0, $groups[(int) $children[1]['id']]['mapping_filled_count']);
});
