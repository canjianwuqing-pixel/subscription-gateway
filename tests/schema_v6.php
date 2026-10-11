<?php
declare(strict_types=1);

function schema_v5_purge_fixture(): PDO
{
    [$db,$parent]=purge_history_fixture();tracking_add_source($db,'manual.example.com');
    $db->exec("UPDATE tracking_sources SET state='SUSPECT' WHERE source_host='na003.example.com'");
    $db->exec("UPDATE tracking_sources SET state='INACTIVE' WHERE source_host='na004.example.com'");
    create_admin($db,'v5_admin','schema-v5-password');save_token($db,'cccccccccccccccccccccccccccccccc','NORMAL');
    add_ip_rule($db,'192.0.2.0/24','BLACKLIST');add_ua_rule($db,'V5Client','WHITELIST');
    $db->exec("INSERT INTO access_logs(client_ip,user_agent,request_path,status_code,created_at) VALUES ('192.0.2.1','V5Client','/api/v1/test/subscribe',200,1)");
    tracking_record_transform_event($db,$parent,'enforced','URI','PARTIAL_SUCCESS',['total_nodes'=>6,'emitted_nodes'=>5,'skipped_nodes'=>1]);
    schema_v5_sources_fixture($db);
    $db->exec("UPDATE tracking_sources SET state='DELETED',deleted_at=123 WHERE source_host IN ('na001.example.com','na002.example.com')");
    return$db;
}
function schema_v6_snapshot(PDO $db): array
{
    $out=[];foreach(['tracking_groups','tracking_assignments','tracking_entry_mappings','tracking_sources','tracking_source_snapshots','tracking_transform_events','tokens','access_logs','settings','ip_rules','ua_rules','admins']as$table)
        $out[$table]=$db->query('SELECT * FROM '.$table.' ORDER BY 1')->fetchAll();
    return$out;
}
$v5Purge=schema_v5_purge_fixture();$v5PurgeBefore=schema_v6_snapshot($v5Purge);
test_case('Actual v5 DELETED data upgrades to v6 and initialization is idempotent',function()use($v5Purge):void{
    expect_same(5,(int)$v5Purge->query('PRAGMA user_version')->fetchColumn());initialize_database($v5Purge);
    expect_same(6,(int)$v5Purge->query('PRAGMA user_version')->fetchColumn());$before=schema_v6_snapshot($v5Purge);initialize_database($v5Purge);expect_same($before,schema_v6_snapshot($v5Purge));
});
foreach(['tracking_sources','tracking_entry_mappings']as$table){
    test_case('v6 migration purges old deleted hosts from '.$table.' including all archived targets',function()use($v5Purge,$v5PurgeBefore,$table):void{
        $expected=array_values(array_filter($v5PurgeBefore[$table],fn($r)=>!in_array($r['source_host'],['na001.example.com','na002.example.com'],true)));
        expect_same($expected,$v5Purge->query('SELECT * FROM '.$table.' ORDER BY 1')->fetchAll());
    });
}
foreach(['tracking_groups','tracking_assignments','tracking_source_snapshots','tracking_transform_events','tokens','access_logs','settings','ip_rules','ua_rules','admins']as$table){
    test_case('v5 to v6 preserves every row and column of '.$table,function()use($v5Purge,$v5PurgeBefore,$table):void{
        expect_same($v5PurgeBefore[$table],$v5Purge->query('SELECT * FROM '.$table.' ORDER BY 1')->fetchAll());
    });
}
test_case('Fresh and migrated v6 accept only four source states and pass SQLite integrity',function()use($v5Purge):void{
    [$fresh]=source_fixture();foreach([$fresh,$v5Purge]as$db){
        expect_same(6,(int)$db->query('PRAGMA user_version')->fetchColumn());expect_same([],$db->query('PRAGMA foreign_key_check')->fetchAll());
        expect_same(['ok'],$db->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));expect_same(1,(int)$db->query('PRAGMA foreign_keys')->fetchColumn());
        expect_exception(fn()=>$db->exec("UPDATE tracking_sources SET state='DELETED'"),PDOException::class);
    }
});
test_case('Purged legacy source is relearned as AUTO with no legacy target resurrection',function()use($v5Purge):void{
    tracking_sync_source_hosts($v5Purge,source_hosts());expect_same('AUTO',tracking_source($v5Purge,'na001.example.com')['origin']);
    foreach(tracking_list_groups($v5Purge)as$group){$rows=array_column($group['mappings'],null,'source_host');expect_same(null,$rows['na001.example.com']['target_host']);}
});
foreach(['mapping delete failure','table conflict','orphan assignment']as$reason){
    test_case('v6 migration '.$reason.' fully rolls back tombstone purge and table rebuild',function()use($reason):void{
        $db=schema_v5_purge_fixture();
        if($reason==='mapping delete failure')$db->exec("CREATE TRIGGER reject_purge BEFORE DELETE ON tracking_entry_mappings BEGIN SELECT RAISE(ABORT,'migration failure'); END");
        elseif($reason==='table conflict')$db->exec('CREATE TABLE tracking_sources_v6(conflict TEXT)');
        else{$db->exec('PRAGMA foreign_keys=OFF');$db->exec('UPDATE tracking_assignments SET group_id=999999 WHERE token_hash=(SELECT token_hash FROM tracking_assignments LIMIT 1)');$db->exec('PRAGMA foreign_keys=ON');}
        $before=schema_v6_snapshot($db);$schema=$db->query("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index','trigger') ORDER BY name")->fetchAll();
        expect_exception(fn()=>initialize_database($db),$reason==='orphan assignment'?RuntimeException::class:PDOException::class);
        expect_same(5,(int)$db->query('PRAGMA user_version')->fetchColumn());expect_same($before,schema_v6_snapshot($db));
        expect_same($schema,$db->query("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index','trigger') ORDER BY name")->fetchAll());expect_same(1,(int)$db->query('PRAGMA foreign_keys')->fetchColumn());
    });
}
$v5Purge=null;
