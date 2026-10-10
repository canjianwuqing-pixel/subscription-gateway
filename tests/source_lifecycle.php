<?php
declare(strict_types=1);

function source_hosts(int $count = 6): array
{
    return array_map(static fn ($n) => 'na' . sprintf('%03d', $n) . '.example.com', range(1, $count));
}
function source_fixture(int $mapped = 5): array
{
    [$db, $parent] = mapping_json_fixture(source_hosts());
    foreach (tracking_active_leaves($db) as $leaf) {
        $rows = [];
        foreach (source_hosts() as $index => $host) $rows[] = ['source_host' => $host,
            'target_host' => $index < $mapped ? 'group-' . $leaf['path'] . '.example.com' : ''];
        tracking_save_group_targets($db, (int) $leaf['id'], $rows);
    }
    return [$db, $parent];
}
function source_state_snapshot(PDO $db): array
{
    $tables = binary_snapshot($db);
    foreach (['tracking_sources','tracking_source_snapshots'] as $table) $tables[$table] = $db->query('SELECT * FROM ' . $table . ' ORDER BY 1')->fetchAll();
    return $tables;
}
function source_body(array $hosts): string
{
    return implode("\n", array_map(static fn ($host) => 'trojan://password@' . $host . ':443#node', $hosts)) . "\n";
}

$sourceSnapshotChecks = [
    'first complete observation has exactly six current sources' => function ($db): void { expect_same(6, tracking_source_stats($db)['current']); },
    'next five-source snapshot immediately reports five' => function ($db): void { tracking_sync_source_hosts($db, source_hosts(5)); expect_same(5, tracking_source_stats($db)['current']); },
    'missing source becomes suspect after one successful observation' => function ($db): void { tracking_sync_source_hosts($db, source_hosts(5)); expect_same('SUSPECT', tracking_source($db, source_hosts()[5])['state']); expect_same(1, (int) tracking_source($db, source_hosts()[5])['missing_count']); },
    'three fast omissions are not permanent invalidation' => function ($db): void { for ($i=0;$i<3;$i++) tracking_sync_source_hosts($db, source_hosts(5)); expect_same('SUSPECT', tracking_source($db, source_hosts()[5])['state']); },
    'time alone without three omissions is not permanent invalidation' => function ($db): void { tracking_sync_source_hosts($db, source_hosts(5), time()+601); expect_same('SUSPECT', tracking_source($db, source_hosts()[5])['state']); },
    'three omissions and ten minutes mark inactive' => function ($db): void { for ($i=0;$i<3;$i++) tracking_sync_source_hosts($db, source_hosts(5), time()+601); expect_same('INACTIVE', tracking_source($db, source_hosts()[5])['state']); expect_same(5, tracking_source_stats($db)['current']); },
    'inactive automatic source recovers and clears its missing count' => function ($db): void { for ($i=0;$i<3;$i++) tracking_sync_source_hosts($db, source_hosts(5), time()+601); tracking_sync_source_hosts($db, source_hosts(), time()+602); $s=tracking_source($db, source_hosts()[5]); expect_same('CURRENT',$s['state']); expect_same(0,(int)$s['missing_count']); expect_same(6,tracking_source_stats($db)['current']); },
    'first seen is retained when a source recovers' => function ($db): void { $first=tracking_source($db,source_hosts()[5])['first_seen_at']; tracking_sync_source_hosts($db,source_hosts(5)); tracking_sync_source_hosts($db,source_hosts(),time()+602); expect_same($first,tracking_source($db,source_hosts()[5])['first_seen_at']); },
    'manual unseen backups do not inflate current counts' => function ($db): void { tracking_add_source($db,'backup.example.com'); expect_same(6,tracking_source_stats($db)['current']); expect_same(1,tracking_source_stats($db)['manual_unseen']); },
    'deleted source is excluded even when present in latest snapshot' => function ($db): void { tracking_delete_source($db,source_hosts()[0]); tracking_sync_source_hosts($db,source_hosts()); expect_same(5,tracking_source_stats($db)['current']); expect_same('DELETED',tracking_source($db,source_hosts()[0])['state']); expect_same(1,(int)array_column(tracking_list_sources($db),null,'source_host')[source_hosts()[0]]['in_latest']); },
    'current completion uses five of six not all catalog entries' => function ($db,$parent): void { for($i=0;$i<20;$i++)tracking_add_source($db,'backup'.$i.'.example.com'); $g=array_column(tracking_list_groups($db),null,'id')[$parent]; expect_same(6,$g['mapping_count']);expect_same(5,$g['mapping_filled_count']);expect_same(26,count(tracking_list_sources($db))); },
    'source snapshot does not reassign Tokens or change group IDs' => function ($db): void { $groups=$db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll(); $assign=flexible_assignments($db);tracking_sync_source_hosts($db,source_hosts(5));expect_same($groups,$db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll());expect_same($assign,flexible_assignments($db)); },
];
foreach ($sourceSnapshotChecks as $label=>$check) test_case('Source snapshot: '.$label,function()use($check):void{[$db,$parent]=source_fixture();$check($db,$parent);});

foreach (['unknown'=>'not a subscription', 'unknown protocol'=>'anytls://password@na001.example.com:443',
    'malformed'=>'trojan://', 'invalid Base64'=>'AAAAA===', 'broken YAML'=>"proxies: [broken"] as $label=>$body) {
    test_case('Failed '.$label.' parse cannot mutate lifecycle or missing counts',function()use($body):void{
        [$db,$parent]=source_fixture();$before=source_state_snapshot($db);
        expect_exception(fn()=>tracking_process_subscription($db,$parent,$body),TrackingTransformFailure::class);
        expect_same($before,source_state_snapshot($db));
    });
}
foreach (['backup.example.com','192.0.2.20','2001:db8::20'] as $host) {
    test_case('Manual add accepts unseen '.$host.' and synchronizes active parents and drafts',function()use($host):void{
        [$db,$parent]=source_fixture();$children=tracking_create_split($db,$parent);$source=tracking_add_source($db,$host);
        expect_same('MANUAL',$source['origin']);expect_same('UNSEEN',$source['state']);expect_same(0,(int)$source['ever_seen']);
        foreach(array_merge(tracking_active_leaves($db),$children)as$group)expect_true(in_array($host,array_column(tracking_group_mappings($db,(int)$group['id']),'source_host'),true));
        expect_same(6,tracking_source_stats($db)['current']);
    });
}
test_case('One hundred manually prepared sources never manufacture output nodes',function():void{
    [$db,$parent]=source_fixture();for($i=0;$i<100;$i++)tracking_add_source($db,'backup'.$i.'.example.com');
    $result=tracking_process_subscription($db,$parent,source_body(source_hosts()));
    expect_same(6,$result['total_nodes']);expect_same(5,$result['emitted_nodes']);expect_same(1,$result['skipped_nodes']);
    expect_true(!str_contains($result['content'],'backup'));expect_same(6,tracking_source_stats($db)['current']);
});
foreach (['https://example.com','example.com:443','/path','bad host','example.com?query=1','user@example.com',"bad\nhost","host.example.com\n","bad\0host",'example.com\\path'] as $index=>$host) {
    test_case('Manual source operations reject unsafe format '.$index.' atomically',function()use($host):void{
        [$db]=source_fixture();$before=source_state_snapshot($db);
        expect_exception(fn()=>tracking_add_source($db,$host),InvalidArgumentException::class);
        expect_exception(fn()=>tracking_rename_source($db,source_hosts()[0],$host),InvalidArgumentException::class);
        expect_same($before,source_state_snapshot($db));
    });
}
test_case('Rename unseen destination preserves every current group target and tombstones old host',function():void{
    [$db,$parent]=source_fixture();$before=[];foreach(tracking_active_leaves($db)as$leaf)$before[$leaf['id']]=tracking_available_mapping($db,(int)$leaf['id'])[source_hosts()[0]];
    $new=tracking_rename_source($db,source_hosts()[0],'new.example.com');expect_same('UNSEEN',$new['state']);
    expect_same('DELETED',tracking_source($db,source_hosts()[0])['state']);
    foreach($before as$id=>$target){$rows=array_column(tracking_group_mappings($db,(int)$id),null,'source_host');expect_same($target,$rows['new.example.com']['target_host']);expect_same($target,$rows[source_hosts()[0]]['target_host']);}
    tracking_sync_source_hosts($db,source_hosts());expect_same('DELETED',tracking_source($db,source_hosts()[0])['state']);
    $result=tracking_process_subscription($db,$parent,source_body(source_hosts()));expect_same(4,$result['emitted_nodes']);
    expect_true(!str_contains($result['content'],'@'.source_hosts()[0].':'));
    tracking_sync_source_hosts($db,['new.example.com']);$result=tracking_process_subscription($db,$parent,source_body(['new.example.com']));expect_same(1,$result['emitted_nodes']);
});
test_case('Rename conflict cannot overwrite different group targets',function():void{
    [$db]=source_fixture();$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_rename_source($db,source_hosts()[0],source_hosts()[1]),DomainException::class);
    expect_same($before,source_state_snapshot($db));
});
test_case('Rename also rejects uncataloged pre-existing mapping conflicts',function():void{
    [$db,$parent]=source_fixture();
    $insert=$db->prepare('INSERT INTO tracking_entry_mappings(group_id,source_host,target_host,created_at,updated_at) VALUES (:group,:source,:target,1,1)');
    $insert->execute([':group'=>$parent,':source'=>'orphan.example.com',':target'=>'different.example.com']);
    $before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_rename_source($db,source_hosts()[0],'orphan.example.com'),DomainException::class);
    expect_same($before,source_state_snapshot($db));
});
test_case('Manual add maintains retained ACTIVE parents effective leaves and nested DRAFT mappings',function():void{
    [$db,$parent]=source_fixture();$children=tracking_create_split($db,$parent);flexible_fill_children($db,$parent);tracking_activate_split($db,$parent);
    tracking_create_split($db,(int)$children[0]['id']);tracking_add_source($db,'prepared.example.com');
    foreach(tracking_list_groups($db)as$group){
        if($group['path']==='root'||!in_array($group['status'],['ACTIVE','DRAFT'],true))continue;
        $rows=array_column(tracking_group_mappings($db,(int)$group['id']),null,'source_host');
        expect_true(array_key_exists('prepared.example.com',$rows));expect_same(null,$rows['prepared.example.com']['target_host']);
    }
});
test_case('Duplicate add is explicit and transactionally safe',function():void{
    [$db]=source_fixture();$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_add_source($db,strtoupper(source_hosts()[0])),DomainException::class);expect_same($before,source_state_snapshot($db));
});
test_case('Deleting a current in-use source is allowed even in enforced mode',function():void{
    [$db,$parent]=source_fixture();tracking_set_mode($db,'enforced');$targets=tracking_group_mappings($db,$parent);
    tracking_delete_source($db,source_hosts()[0]);expect_same($targets,tracking_group_mappings($db,$parent));
    $result=tracking_process_subscription($db,$parent,source_body(source_hosts()));expect_same('PARTIAL_SUCCESS',$result['outcome']);expect_same(4,$result['emitted_nodes']);
    tracking_restore_source($db,source_hosts()[0]);expect_same('CURRENT',tracking_source($db,source_hosts()[0])['state']);expect_same($targets,tracking_group_mappings($db,$parent));
});
test_case('Restoring absent historical source retains targets but is not counted current',function():void{
    [$db]=source_fixture();tracking_delete_source($db,source_hosts()[0]);tracking_sync_source_hosts($db,array_slice(source_hosts(),1));
    tracking_restore_source($db,source_hosts()[0]);expect_same('SUSPECT',tracking_source($db,source_hosts()[0])['state']);expect_same(5,tracking_source_stats($db)['current']);
});
test_case('Explicit re-add of tombstone restores it without resetting existing targets',function():void{
    [$db,$parent]=source_fixture();$before=tracking_group_mappings($db,$parent);tracking_delete_source($db,source_hosts()[0]);tracking_add_source($db,source_hosts()[0]);
    expect_same('CURRENT',tracking_source($db,source_hosts()[0])['state']);expect_same($before,tracking_group_mappings($db,$parent));
});
test_case('Snapshot mapping failure rolls back catalog snapshot and lifecycle together',function():void{
    [$db]=source_fixture();$db->exec("CREATE TRIGGER fail_source BEFORE INSERT ON tracking_entry_mappings WHEN NEW.source_host='new.example.com' BEGIN SELECT RAISE(ABORT,'test failure'); END");
    $before=source_state_snapshot($db);expect_exception(fn()=>tracking_sync_source_hosts($db,['new.example.com']),PDOException::class);expect_same($before,source_state_snapshot($db));
});
test_case('Manual rename failure rolls back tombstone and all target transfers',function():void{
    [$db]=source_fixture();$db->exec("CREATE TRIGGER fail_rename BEFORE UPDATE OF target_host ON tracking_entry_mappings BEGIN SELECT RAISE(ABORT,'test failure'); END");
    $before=source_state_snapshot($db);expect_exception(fn()=>tracking_rename_source($db,source_hosts()[0],'new.example.com'),PDOException::class);expect_same($before,source_state_snapshot($db));
});
test_case('Catalog safety cap rejects new automatic and manual hosts without partial state',function():void{
    [$db]=source_fixture();$insert=$db->prepare("INSERT INTO tracking_sources(source_host,origin,state,created_at,updated_at) VALUES (:host,'MANUAL','UNSEEN',1,1)");
    for($i=0;$i<994;$i++)$insert->execute([':host'=>'capacity'.$i.'.example.com']);$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_add_source($db,'overflow.example.com'),DomainException::class);
    expect_exception(fn()=>tracking_sync_source_hosts($db,['overflow.example.com']),DomainException::class);
    expect_same($before,source_state_snapshot($db));
});
