<?php

declare(strict_types=1);

$trackingUiSource = file_get_contents($root . '/sgw/admin/src/dashboard.php');
foreach (['映射状态', '已完成', '部分可用', '无可用映射', 'mapping-done', 'mapping-partial', 'mapping-missing',
    '当前入口映射提示', '无法启用正式模式', '还有', '个入口未配置', '二分拆分必须完整保留2个子组',
    '删除待配置子组', '取消待配置拆分', 'trackingSplitPreview', 'trackingDraftWarning', 'trackingCanUndo', 'paddingLeft',
    '撤销拆分', 'undo-split', '旧待配置拆分', '父组当前没有可用映射', '请先撤销或处理下级拆分', '其它主组及兄弟分支不受影响',
    '原入口管理', '+ 添加原入口', '修改原入口', '删除原入口', '恢复原入口', '疑似失效', '已失效', '手动删除',
    '当前最新订阅未检测到此入口，仍可保存', '节点会过滤', '至少需要1个当前可用目标入口', 'trackingSplitTime'] as $feature) {
    test_case('Tracking UI exposes ' . $feature, function () use ($trackingUiSource, $feature): void {
        expect_true(str_contains($trackingUiSource, $feature), $feature);
    });
}
test_case('Tracking UI deletion and cancellation are gated on DRAFT and pending leaf states', function () use ($trackingUiSource): void {
    expect_true(str_contains($trackingUiSource, "if(g.status==='DRAFT'&&g.path.includes('.'))add(actions,btn('删除'"));
    expect_true(str_contains($trackingUiSource, 'if(leaf&&g.has_draft_children)'));
    expect_true(str_contains($trackingUiSource, "if(group.status==='ACTIVE'&&group.has_active_children)return{text:'已拆分'"));
    expect_true(str_contains($trackingUiSource, "if(leaves.some(g=>!trackingMappingState(g).usable))"));
});
test_case('New split UI has fixed two-child preview and no count input or dynamic creation hint', function () use ($trackingUiSource): void {
    expect_true(str_contains($trackingUiSource, "function trackingSplitPreview(path){return[path+'.1',path+'.2']}"));
    expect_true(!str_contains($trackingUiSource, "field('子组数量'"));
    expect_true(!str_contains($trackingUiSource, '2-20'));
    expect_true(!str_contains($trackingUiSource, '{child_count}'));
});
test_case('Tracking UI retains reusable modals and has no browser prompt confirm or alert', function () use ($trackingUiSource): void {
    expect_same(0, preg_match('/\b(?:prompt|confirm|alert)\s*\(/', $trackingUiSource));
    expect_true(str_contains($trackingUiSource, 'openDialog({title:'));
    expect_true(str_contains($trackingUiSource, "input.classList.toggle('mapping-empty',empty)"));
});
test_case('Tracking API reports 6/6 4/6 and 0/6 independently of assignment join multiplicity', function (): void {
    [$db, $parent] = flexible_split_fixture();
    $sources = array_map(fn ($n) => 'source-' . $n . '.example.com', range(1, 5));
    tracking_sync_source_hosts($db, ['na001.example.com', ...$sources]);
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
