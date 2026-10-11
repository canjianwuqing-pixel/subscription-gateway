<?php
declare(strict_types=1);

function schema_v4_fixture(): PDO
{
    [$db,$parent,$children]=binary_active_fixture();
    $nested=(int)$children[0]['id'];tracking_create_split($db,$nested);flexible_fill_children($db,$nested);tracking_activate_split($db,$nested);
    tracking_undo_split($db,$nested);tracking_create_split($db,$nested);
    tracking_record_transform_event($db,$nested,'enforced','URI','SUCCESS');
    tracking_record_transform_event($db,null,'preflight','UNKNOWN','UNKNOWN_FORMAT');
    create_admin($db,'v4_admin','schema-v4-test-password');save_token($db,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','WHITELIST');
    add_ip_rule($db,'198.51.100.0/24','BLACKLIST');add_ua_rule($db,'V4Client','WHITELIST');
    $db->exec("INSERT INTO access_logs(client_ip,user_agent,request_path,status_code,created_at) VALUES ('198.51.100.1','V4Client','/api/v1/test/subscribe',200,1)");
    schema_remove_v5_fixture($db);return$db;
}
$v4Fixture=schema_v4_fixture();$v4Before=[];
foreach(['tracking_groups','tracking_assignments','tracking_entry_mappings','tracking_transform_events','tokens','access_logs','ip_rules','ua_rules','settings','admins']as$table)$v4Before[$table]=$v4Fixture->query('SELECT * FROM '.$table.' ORDER BY 1')->fetchAll();
test_case('Actual v4 schema upgrades atomically through v5 to v6 and remains idempotent',function()use($v4Fixture):void{
    expect_same(4,(int)$v4Fixture->query('PRAGMA user_version')->fetchColumn());initialize_database($v4Fixture);
    expect_same(7,(int)$v4Fixture->query('PRAGMA user_version')->fetchColumn());$before=source_state_snapshot($v4Fixture);initialize_database($v4Fixture);expect_same($before,source_state_snapshot($v4Fixture));
});
foreach(array_keys($v4Before)as$table){
    test_case('v4 to v5 preserves every original row and column of '.$table,function()use($v4Fixture,$v4Before,$table):void{
        $columns=$table==='tracking_transform_events'?'id,group_id,mode,format,outcome,created_at':'*';
        expect_same($v4Before[$table],$v4Fixture->query('SELECT '.$columns.' FROM '.$table.' ORDER BY 1')->fetchAll());
    });
}
test_case('v5 conservatively imports distinct mapped hosts as current without invented history invalidation',function()use($v4Fixture,$v4Before):void{
    $expected=array_values(array_unique(array_column($v4Before['tracking_entry_mappings'],'source_host')));sort($expected);
    $sources=tracking_list_sources($v4Fixture);expect_same($expected,array_column($sources,'source_host'));
    foreach($sources as$source){expect_same('AUTO',$source['origin']);expect_same('CURRENT',$source['state']);expect_same(1,(int)$source['ever_seen']);expect_same(0,(int)$source['missing_count']);expect_true((int)$source['last_seen_at']>0);}
});
test_case('v5 retains permanent roots binary topology and every old assignment lookup',function()use($v4Fixture,$v4Before):void{
    expect_same(['1','2','3'],array_column(tracking_children($v4Fixture,1),'path'));
    foreach($v4Before['tracking_assignments']as$row)expect_same((int)$row['group_id'],tracking_assignment_for_hash($v4Fixture,$row['token_hash']));
    expect_same($v4Before['tracking_assignments'],flexible_assignments($v4Fixture));
});
test_case('v5 event node counts initialize to zero without rewriting legacy events',function()use($v4Fixture):void{
    foreach($v4Fixture->query('SELECT total_nodes,emitted_nodes,skipped_nodes FROM tracking_transform_events')as$row)expect_same(['total_nodes'=>0,'emitted_nodes'=>0,'skipped_nodes'=>0],$row);
});
test_case('Fresh and migrated v5 pass foreign keys and integrity checks',function()use($v4Fixture):void{
    [$fresh]=source_fixture();foreach([$fresh,$v4Fixture]as$db){expect_same(7,(int)$db->query('PRAGMA user_version')->fetchColumn());expect_same(1,(int)$db->query('PRAGMA foreign_keys')->fetchColumn());expect_same([],$db->query('PRAGMA foreign_key_check')->fetchAll());expect_same(['ok'],$db->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));}
});
foreach(['catalog conflict','event column conflict','orphan assignment']as$reason){
    test_case('v5 migration failure '.$reason.' rolls back all schema and original data',function()use($reason):void{
        $db=schema_v4_fixture();
        if($reason==='catalog conflict')$db->exec('CREATE TABLE tracking_sources(conflict TEXT)');
        elseif($reason==='event column conflict')$db->exec('ALTER TABLE tracking_transform_events ADD COLUMN total_nodes INTEGER');
        else{$db->exec('PRAGMA foreign_keys=OFF');$db->exec('UPDATE tracking_assignments SET group_id=99999 WHERE token_hash=(SELECT token_hash FROM tracking_assignments LIMIT 1)');$db->exec('PRAGMA foreign_keys=ON');}
        $tables=binary_snapshot($db);$schema=$db->query("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name")->fetchAll();
        expect_exception(fn()=>initialize_database($db),$reason==='orphan assignment'?RuntimeException::class:PDOException::class);
        expect_same(4,(int)$db->query('PRAGMA user_version')->fetchColumn());expect_same($tables,binary_snapshot($db));expect_same($schema,$db->query("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name")->fetchAll());expect_same(1,(int)$db->query('PRAGMA foreign_keys')->fetchColumn());
    });
}
$v4Fixture=null;
