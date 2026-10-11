<?php
declare(strict_types=1);

function purge_history_fixture(): array
{
    [$db,$parent]=source_fixture();
    for($i=0;$i<12;$i++)tracking_assignment_for_hash($db,hash('sha256','purge-token-'.$i));
    tracking_create_split($db,$parent);flexible_fill_children($db,$parent);tracking_activate_split($db,$parent);
    tracking_undo_split($db,$parent);tracking_create_split($db,$parent);
    return[$db,$parent];
}
function purge_current_rows(PDO $db,int $group): array
{
    $current=array_column(array_filter(tracking_list_sources($db),fn($s)=>$s['state']==='CURRENT'&&(int)$s['in_latest']===1),'source_host');
    return array_values(array_filter(tracking_group_mappings($db,$group),fn($row)=>in_array($row['source_host'],$current,true)));
}

foreach(['CURRENT','SUSPECT','INACTIVE','UNSEEN']as$state){
    foreach(['catalog removed','all group targets removed','unrelated data preserved']as$check){
        test_case('Physical source delete '.$state.': '.$check,function()use($state,$check):void{
            [$db,$parent]=purge_history_fixture();$host=source_hosts()[0];
            $stmt=$db->prepare('UPDATE tracking_sources SET state=:state WHERE source_host=:host');$stmt->execute([':state'=>$state,':host'=>$host]);
            $before=source_state_snapshot($db);tracking_delete_source($db,strtoupper($host).'.');
            if($check==='catalog removed'){
                expect_exception(fn()=>tracking_source($db,$host),TrackingSourceNotFound::class);
                expect_true(!in_array($host,array_column(tracking_list_sources($db),'source_host'),true));
            }elseif($check==='all group targets removed'){
                foreach($db->query('SELECT id FROM tracking_groups')->fetchAll(PDO::FETCH_COLUMN)as$id)
                    expect_true(!in_array($host,array_column(tracking_group_mappings($db,(int)$id),'source_host'),true));
                expect_true((int)$db->query("SELECT COUNT(*) FROM tracking_groups WHERE status='ARCHIVED'")->fetchColumn()>0);
            }else{
                $after=source_state_snapshot($db);
                foreach(['tracking_groups','tracking_assignments','tracking_transform_events','tracking_source_snapshots','settings']as$table)expect_same($before[$table],$after[$table]);
                expect_same(array_values(array_filter($before['tracking_entry_mappings'],fn($row)=>$row['source_host']!==$host)),$after['tracking_entry_mappings']);
                expect_same(array_values(array_filter($before['tracking_sources'],fn($row)=>$row['source_host']!==$host)),$after['tracking_sources']);
            }
        });
    }
}
test_case('Deleting a latest in-use source immediately reduces current count and denominator',function():void{
    [$db,$parent]=source_fixture();tracking_set_mode($db,'enforced');tracking_delete_source($db,source_hosts()[0]);
    expect_same(5,tracking_source_stats($db)['current']);$group=array_column(tracking_list_groups($db),null,'id')[$parent];
    expect_same(5,$group['mapping_count']);expect_same(4,$group['mapping_filled_count']);
});
test_case('Deleting nonexistent source has a dedicated not-found error without side effects',function():void{
    [$db]=source_fixture();$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_delete_source($db,'absent.example.com'),TrackingSourceNotFound::class);expect_same($before,source_state_snapshot($db));
});
foreach(['https://example.com','example.com:443','/path',"bad\nhost"]as$index=>$host){
    test_case('Delete rejects illegal host '.$index.' without changing state',function()use($host):void{
        [$db]=source_fixture();$before=source_state_snapshot($db);expect_exception(fn()=>tracking_delete_source($db,$host),InvalidArgumentException::class);expect_same($before,source_state_snapshot($db));
    });
}
foreach(['catalog','mapping']as$stage){
    test_case('Physical delete '.$stage.' failure rolls back all mappings and source rows',function()use($stage):void{
        [$db]=source_fixture();$table=$stage==='catalog'?'tracking_sources':'tracking_entry_mappings';
        $db->exec('CREATE TRIGGER purge_fail BEFORE DELETE ON '.$table." BEGIN SELECT RAISE(ABORT,'purge failure'); END");
        $before=source_state_snapshot($db);expect_exception(fn()=>tracking_delete_source($db,source_hosts()[0]),PDOException::class);expect_same($before,source_state_snapshot($db));
    });
}
foreach(['fresh automatic record','every maintained group null target','old target never restored','partial pipeline still succeeds']as$check){
    test_case('Deleted source relearning: '.$check,function()use($check):void{
        [$db,$parent]=purge_history_fixture();$host=source_hosts()[0];$old=tracking_source($db,$host);tracking_delete_source($db,$host);
        $result=tracking_process_subscription($db,$parent,source_body(source_hosts()));$source=tracking_source($db,$host);
        if($check==='fresh automatic record'){
            expect_same('AUTO',$source['origin']);expect_same('CURRENT',$source['state']);expect_same(0,(int)$source['missing_count']);
            expect_true((int)$source['first_snapshot_id']>(int)$old['first_snapshot_id']);expect_same(6,tracking_source_stats($db)['current']);
        }elseif($check==='every maintained group null target'){
            foreach(tracking_list_groups($db)as$group){$rows=array_column($group['mappings'],null,'source_host');expect_true(isset($rows[$host]));expect_same(null,$rows[$host]['target_host']);}
        }elseif($check==='old target never restored'){
            $query=$db->prepare('SELECT target_host FROM tracking_entry_mappings WHERE source_host=:host');$query->execute([':host'=>$host]);
            foreach($query as$row)expect_same(null,$row['target_host']);
            foreach($db->query("SELECT id FROM tracking_groups WHERE status='ARCHIVED'")->fetchAll(PDO::FETCH_COLUMN)as$id)
                expect_true(!in_array($host,array_column(tracking_group_mappings($db,(int)$id),'source_host'),true));
        }else{
            expect_same('PARTIAL_SUCCESS',$result['outcome']);expect_same(4,$result['emitted_nodes']);expect_same(2,$result['skipped_nodes']);
            expect_true(!str_contains($result['content'],'@'.$host.':'));
        }
    });
}
test_case('Deleting the last usable source remains allowed and runtime returns no usable nodes',function():void{
    [$db,$parent]=source_fixture(1);tracking_set_mode($db,'enforced');tracking_delete_source($db,source_hosts()[0]);
    try{tracking_process_subscription($db,$parent,source_body(source_hosts()));throw new RuntimeException('Empty subscription succeeded');}
    catch(TrackingTransformFailure$error){expect_same('NO_USABLE_NODES',$error->reason);expect_same(0,$error->counts['emitted_nodes']);expect_same(6,$error->counts['skipped_nodes']);}
});
test_case('Automatic inactivity preserves targets and automatic reappearance can reuse them',function():void{
    [$db,$parent]=source_fixture();$host=source_hosts()[0];$rows=tracking_group_mappings($db,$parent);
    for($i=0;$i<3;$i++)tracking_sync_source_hosts($db,array_slice(source_hosts(),1),time()+601);
    expect_same('INACTIVE',tracking_source($db,$host)['state']);expect_same($rows,tracking_group_mappings($db,$parent));
    $result=tracking_process_subscription($db,$parent,source_body(source_hosts()));expect_same(5,$result['emitted_nodes']);expect_same('CURRENT',tracking_source($db,$host)['state']);
});
test_case('Editing current mappings updates only visible rows and preserves hidden rows byte-for-byte',function():void{
    [$db,$parent]=source_fixture();tracking_add_source($db,'backup.example.com');tracking_sync_source_hosts($db,[source_hosts()[0]]);
    $before=tracking_group_mappings($db,$parent);tracking_save_group_targets($db,$parent,[['source_host'=>source_hosts()[0],'target_host'=>'changed.example.com']]);
    $after=tracking_group_mappings($db,$parent);expect_same(array_values(array_filter($before,fn($r)=>$r['source_host']!==source_hosts()[0])),array_values(array_filter($after,fn($r)=>$r['source_host']!==source_hosts()[0])));
    expect_same('changed.example.com',array_column($after,null,'source_host')[source_hosts()[0]]['target_host']);
    $group=array_column(tracking_list_groups($db),null,'id')[$parent];expect_same(1,$group['mapping_count']);expect_same(1,$group['mapping_filled_count']);
});
foreach(['unknown','SUSPECT','INACTIVE','UNSEEN','stale CURRENT']as$kind){
    test_case('Current mapping API refuses '.$kind.' source injection',function()use($kind):void{
        [$db,$parent]=source_fixture();$host='backup.example.com';
        if($kind!=='unknown'){
            tracking_add_source($db,$host);$state=$kind==='stale CURRENT'?'CURRENT':$kind;
            $stmt=$db->prepare('UPDATE tracking_sources SET state=:state WHERE source_host=:host');$stmt->execute([':state'=>$state,':host'=>$host]);
        }
        $before=source_state_snapshot($db);$rows=purge_current_rows($db,$parent);$rows[]=['source_host'=>$host,'target_host'=>'forged.example.com'];
        expect_exception(fn()=>tracking_save_group_targets($db,$parent,$rows),DomainException::class);expect_same($before,source_state_snapshot($db));
    });
}
test_case('Current mapping form stale after a delete cannot recreate the removed source',function():void{
    [$db,$parent]=source_fixture();$rows=purge_current_rows($db,$parent);tracking_delete_source($db,source_hosts()[0]);$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_save_group_targets($db,$parent,$rows),DomainException::class);expect_same($before,source_state_snapshot($db));
});
test_case('Rename transfers archived ACTIVE and DRAFT mapping IDs and targets without a tombstone',function():void{
    [$db,$parent]=purge_history_fixture();$old=source_hosts()[0];$before=$db->query("SELECT id,group_id,target_host,created_at FROM tracking_entry_mappings WHERE source_host='".$old."' ORDER BY id")->fetchAll();
    $groups=$db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll();$assignments=flexible_assignments($db);
    tracking_rename_source($db,$old,'renamed.example.com');
    expect_same($before,$db->query("SELECT id,group_id,target_host,created_at FROM tracking_entry_mappings WHERE source_host='renamed.example.com' ORDER BY id")->fetchAll());
    expect_exception(fn()=>tracking_source($db,$old),TrackingSourceNotFound::class);expect_same('UNSEEN',tracking_source($db,'renamed.example.com')['state']);
    expect_same($groups,$db->query('SELECT * FROM tracking_groups ORDER BY id')->fetchAll());expect_same($assignments,flexible_assignments($db));
    tracking_sync_source_hosts($db,source_hosts());expect_same('AUTO',tracking_source($db,$old)['origin']);
    foreach(tracking_list_groups($db)as$group)expect_same(null,array_column($group['mappings'],null,'source_host')[$old]['target_host']);
});
test_case('UI and API expose no source restore workflow',function()use($root):void{
    $ui=file_get_contents($root.'/sgw/admin/src/dashboard.php');$api=file_get_contents($root.'/sgw/admin/src/api.php');
    expect_true(!str_contains($ui,'DELETED'));expect_true(!str_contains($ui,'恢复原入口'));expect_true(!str_contains($ui,'/restore'));
    expect_true(!str_contains($api,'/restore'));expect_true(!function_exists('tracking_restore_source'));
});
