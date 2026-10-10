<?php
declare(strict_types=1);

$partialMapping = array_fill_keys(array_slice(source_hosts(),0,5),'private.example.com');
$partialNotes = "  剩余流量：88GB  \r\n官网：https://example.com\n# 公告\r\n\r\n";
foreach (['vless','trojan','hysteria2','hy2','tuic','ss','vmess'] as $protocol) {
    test_case('Partial '.$protocol.' removes entire unmapped nodes and retains all mapped credentials and metadata',function()use($protocol,$partialMapping,$partialNotes):void{
        $lines=[];
        foreach(source_hosts()as$host){
            if($protocol==='vmess')$line='vmess://'.base64_encode(json_encode(['add'=>$host,'ps'=>'node','id'=>'uuid','port'=>'443','sni'=>'sni.example.com'],JSON_THROW_ON_ERROR));
            else $line=$protocol.'://password@'.$host.':443?sni=sni.example.com&pbk=key&sid=01&flow=keep#node';
            $lines[]=$line;
        }
        $body=$partialNotes.implode("\r\n",$lines)."\r\n";$result=tracking_transform_subscription_body($body,$partialMapping);
        expect_same(6,$result['total_nodes']);expect_same(5,$result['emitted_nodes']);expect_same(1,$result['skipped_nodes']);expect_same('PARTIAL_SUCCESS',$result['outcome']);
        expect_true(str_starts_with($result['content'],$partialNotes));expect_true(!str_contains($result['content'],$lines[5]));
        expect_same(['private.example.com'],tracking_subscription_source_hosts($result['content']));
        if($protocol!=='vmess')expect_same($partialNotes.str_replace(array_map(fn($h)=>'@'.$h.':',array_slice(source_hosts(),0,5)),'@private.example.com:',implode("\r\n",array_slice($lines,0,5)))."\r\n",$result['content']);
        else foreach(array_slice(explode("\r\n",substr($result['content'],strlen($partialNotes))),0,5)as$line){$doc=json_decode(tracking_decode_base64(substr($line,8),'VMESS')['decoded'],true,32,JSON_THROW_ON_ERROR);expect_same('uuid',$doc['id']);expect_same('sni.example.com',$doc['sni']);}
    });
}
test_case('Legacy Shadowsocks Base64 authority is removed as a whole when unmapped',function()use($partialMapping):void{
    $keep='ss://'.rtrim(base64_encode('aes-256-gcm:password@na001.example.com:8388'),'=').'#Keep';
    $skip='ss://'.rtrim(base64_encode('aes-256-gcm:password@na006.example.com:8388'),'=').'#Skip';
    $result=tracking_transform_subscription_body($keep."\n".$skip."\n",$partialMapping);expect_same(1,$result['emitted_nodes']);expect_true(!str_contains($result['content'],'#Skip'));
});
foreach ([['urlsafe'=>false,'padded'=>true],['urlsafe'=>false,'padded'=>false],['urlsafe'=>true,'padded'=>true],['urlsafe'=>true,'padded'=>false]] as $index=>$meta) {
    test_case('Partial outer Base64 retains alphabet padding metadata and counts '.$index,function()use($meta,$partialMapping,$partialNotes):void{
        $plain=$partialNotes.source_body(source_hosts());$encoded=tracking_encode_base64($plain,$meta);$detected=tracking_decode_base64($encoded,'BASE64');
        $result=tracking_transform_subscription_body(" \r\n".$encoded."\n ",$partialMapping);
        $expected=tracking_transform_subscription_body($plain,$partialMapping)['content'];
        expect_same(" \r\n".tracking_encode_base64($expected,$detected)."\n ",$result['content']);
        expect_same('BASE64',$result['format']);expect_same(6,$result['total_nodes']);expect_same(5,$result['emitted_nodes']);expect_same(1,$result['skipped_nodes']);
    });
}
foreach([false,true]as$base64){
    test_case('All nodes filtered never returns metadata-only or empty success '.(int)$base64,function()use($base64,$partialNotes):void{
        $body=$partialNotes.source_body(source_hosts());if($base64)$body=base64_encode($body);
        try{tracking_transform_subscription_body($body,[]);throw new RuntimeException('Empty subscription succeeded');}
        catch(TrackingTransformFailure$error){expect_same('NO_USABLE_NODES',$error->reason);expect_same(['total_nodes'=>6,'emitted_nodes'=>0,'skipped_nodes'=>6],$error->counts);}
    });
}
foreach(['anytls','socks5','wireguard','unknown']as$scheme){
    test_case('Unknown '.$scheme.' is never silently skipped even with zero mappings',function()use($scheme):void{
        try{tracking_transform_subscription_body(source_body(source_hosts()).$scheme.'://secret@na006.example.com:443',[]);throw new RuntimeException('Unknown protocol accepted');}
        catch(TrackingTransformFailure$error){expect_same('UNKNOWN_FORMAT',$error->reason);}
    });
}

function partial_yaml_fixture(): array
{
    return ['proxies'=>[
        ['name'=>'Mapped','type'=>'vless','server'=>'na001.example.com','port'=>443,'uuid'=>'uuid','sni'=>'sni.example.com','reality-opts'=>['public-key'=>'key','short-id'=>'01']],
        ['name'=>'Unmapped','type'=>'trojan','server'=>'na006.example.com','port'=>443,'password'=>'secret'],
    ],'proxy-groups'=>[
        ['name'=>'Select','type'=>'select','proxies'=>['Mapped','Unmapped','DIRECT','REJECT']],
        ['name'=>'Fallback','type'=>'select','proxies'=>['Select','Unmapped','DIRECT']],
    ],'rules'=>['MATCH,Select']];
}
test_case('YAML partial filter removes proxies and references while preserving builtins groups and other fields',function()use($partialMapping):void{
    $doc=partial_yaml_fixture();$result=tracking_transform_subscription_body(yaml_emit($doc),$partialMapping);$out=yaml_parse($result['content']);
    expect_same(1,count($out['proxies']));expect_same(['Mapped','DIRECT','REJECT'],$out['proxy-groups'][0]['proxies']);
    expect_same(['Select','DIRECT'],$out['proxy-groups'][1]['proxies']);expect_same($doc['rules'],$out['rules']);
    $expected=$doc['proxies'][0];$expected['server']='private.example.com';expect_same($expected,$out['proxies'][0]);
    expect_same(['private.example.com'],tracking_subscription_source_hosts($result['content']));
    expect_same('PARTIAL_SUCCESS',$result['outcome']);expect_same(2,$result['total_nodes']);expect_same(1,$result['emitted_nodes']);expect_same(1,$result['skipped_nodes']);
});
test_case('YAML all proxies filtered raises NO_USABLE_NODES not invalid empty group success',function():void{
    try{tracking_transform_subscription_body(yaml_emit(partial_yaml_fixture()),[]);throw new RuntimeException('Empty YAML succeeded');}
    catch(TrackingTransformFailure$error){expect_same('NO_USABLE_NODES',$error->reason);expect_same(0,$error->counts['emitted_nodes']);expect_same(2,$error->counts['skipped_nodes']);}
});
foreach(['empty group','dangling','duplicate name','cycle','provider dynamic','unknown type']as$reason){
    test_case('Unsafe YAML '.$reason.' fails closed and does not update snapshots',function()use($reason,$partialMapping):void{
        $doc=partial_yaml_fixture();
        if($reason==='empty group')$doc['proxy-groups'][0]['proxies']=['Unmapped'];
        if($reason==='dangling')$doc['proxy-groups'][0]['proxies'][]='DoesNotExist';
        if($reason==='duplicate name')$doc['proxies'][1]['name']='Mapped';
        if($reason==='cycle')$doc['proxy-groups'][0]['proxies'][]='Fallback';
        if($reason==='provider dynamic')$doc['proxy-groups'][0]['use']=['remote'];
        if($reason==='unknown type')$doc['proxies'][1]['type']='anytls';
        [$db,$parent]=source_fixture();$before=source_state_snapshot($db);
        expect_exception(fn()=>tracking_process_subscription($db,$parent,yaml_emit($doc)),TrackingTransformFailure::class);
        expect_same($before,source_state_snapshot($db));
    });
}
test_case('Partial events count as success and persist only safe numeric telemetry',function():void{
    [$db,$parent]=source_fixture();$result=tracking_process_subscription($db,$parent,source_body(source_hosts()));
    tracking_record_transform_event($db,$parent,'enforced',$result['format'],$result['outcome'],$result);
    $stats=tracking_transform_stats($db);expect_same(1,$stats['successes']);expect_same(1,$stats['partial_successes']);expect_same(0,$stats['failures']);expect_same(1,$stats['skipped_nodes']);
    $row=$db->query('SELECT * FROM tracking_transform_events ORDER BY id DESC LIMIT 1')->fetch();expect_same(6,(int)$row['total_nodes']);expect_same(5,(int)$row['emitted_nodes']);
    expect_true(!str_contains(json_encode($row,JSON_THROW_ON_ERROR),'password'));
});
test_case('No usable nodes still commits complete source observation and counts its event as failure',function():void{
    [$db,$parent]=source_fixture(0);
    try{tracking_process_subscription($db,$parent,source_body(source_hosts(5)));throw new RuntimeException('Empty result succeeded');}
    catch(TrackingTransformFailure$error){tracking_record_transform_event($db,$parent,'enforced',$error->format,$error->reason,$error->counts);}
    expect_same(5,tracking_source_stats($db)['current']);$stats=tracking_transform_stats($db);expect_same(1,$stats['failures']);expect_same(1,$stats['no_usable_nodes']);expect_same(5,$stats['skipped_nodes']);
});
foreach([1,4,5]as$mapped){
    test_case('Enforced accepts '.$mapped.'/6 and partial node output',function()use($mapped):void{
        [$db,$parent]=source_fixture($mapped);tracking_set_mode($db,'enforced');$result=tracking_process_subscription($db,$parent,source_body(source_hosts()));
        expect_same($mapped,$result['emitted_nodes']);expect_same('PARTIAL_SUCCESS',$result['outcome']);
    });
}
test_case('Enforced enabling rejects zero current target but permits manually prepared backups to be saved',function():void{
    [$db,$parent]=source_fixture(0);tracking_add_source($db,'backup.example.com');binary_fill_group($db,$parent);
    // Other actual leaf groups still have zero current target.
    expect_exception(fn()=>tracking_set_mode($db,'enforced'),DomainException::class);
});
test_case('Binary DRAFT partial mappings activate without changing split algorithm',function():void{
    [$db,$parent]=source_fixture();$children=tracking_create_split($db,$parent);
    foreach($children as$child){$rows=array_map(fn($host)=>['source_host'=>$host,'target_host'=>$host===source_hosts()[0]?'child.example.com':''],source_hosts());tracking_save_group_targets($db,(int)$child['id'],$rows);}
    tracking_set_mode($db,'enforced');expect_same(2,count(tracking_validate_split($db,$parent)));tracking_activate_split($db,$parent);
    foreach($children as$child)expect_same(1,count(tracking_effective_mapping($db,(int)$child['id'])));
});
test_case('Binary DRAFT with zero current target cannot activate',function():void{
    [$db,$parent]=source_fixture();tracking_create_split($db,$parent);$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_activate_split($db,$parent),DomainException::class);expect_same($before,source_state_snapshot($db));
});
test_case('Undo allows a partial parent with one current mapping and preserves historical split time',function():void{
    [$db,$parent]=source_fixture(1);$children=tracking_create_split($db,$parent);flexible_fill_children($db,$parent);tracking_activate_split($db,$parent);tracking_set_mode($db,'enforced');
    $time=tracking_group($db,$parent)['split_at'];tracking_undo_split($db,$parent);expect_same($time,tracking_group($db,$parent)['split_at']);expect_same(1,count(tracking_effective_mapping($db,$parent)));
});
test_case('Enforced undo rejects a zero-current-target parent transactionally',function():void{
    [$db,$parent]=source_fixture(0);$children=tracking_create_split($db,$parent);flexible_fill_children($db,$parent);tracking_activate_split($db,$parent);
    foreach(tracking_active_leaves($db)as$leaf)binary_fill_group($db,(int)$leaf['id']);tracking_set_mode($db,'enforced');$before=source_state_snapshot($db);
    expect_exception(fn()=>tracking_undo_split($db,$parent),DomainException::class);expect_same($before,source_state_snapshot($db));
});
