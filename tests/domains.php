<?php
declare(strict_types=1);

const DOMAIN_TEST_SECRET='known_Cloudflare_secret_DO_NOT_PERSIST_9876';
function domain_test_client(string $token,string $method,string $path):array
{
    if($token==='invalid_secret') throw new RuntimeException(DOMAIN_TEST_SECRET);
    $id=substr($path,6);
    return ['success'=>true,'result'=>['id'=>$id,'name'=>$id===str_repeat('b',32)?'other.org':'example.net']];
}
function domain_fixture():PDO
{
    global $temporaryRoot;
    $dir=$temporaryRoot.'/domain-'.bin2hex(random_bytes(5)); mkdir($dir,0750);
    mkdir($dir.'/control',0750); mkdir($dir.'/certs',0750);
    putenv('DOMAIN_CERT_DIR='.$dir.'/certs'); putenv('CONTROL_DIR='.$dir.'/control');
    $db=open_database($dir.'/db.sqlite'); initialize_database($db); return $db;
}
function domain_profile_fixture(PDO $db,string $zone='a',string $token=DOMAIN_TEST_SECRET):int
{
    return cloudflare_save_profile($db,['name'=>'测试凭据','zone_id'=>str_repeat($zone,32),'token'=>$token],null,'domain_test_client');
}
function domain_alias_fixture(PDO $db,string $fqdn='a.example.net'):int
{
    return domain_add($db,['fqdn'=>$fqdn,'token'=>DOMAIN_TEST_SECRET,'zone_id'=>str_repeat('a',32)],'domain_test_client');
}
function domain_test_issuer(array $row,string $dir,array $profile):void
{
    global $temporaryRoot;
    $cache=$temporaryRoot.'/cert-cache-'.hash('sha256',$row['fqdn']);
    if(!is_dir($cache)) { mkdir($cache,0700);
        domain_command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','60','-subj','/CN='.$row['fqdn'],
            '-addext','subjectAltName=DNS:'.$row['fqdn'],'-keyout',$cache.'/privkey.pem','-out',$cache.'/fullchain.pem']);
    }
    foreach(['fullchain.pem','privkey.pem']as$file) { copy($cache.'/'.$file,$dir.'/'.$file);chmod($dir.'/'.$file,0640); }
}
function domain_test_publish(PDO $db,array $job,string $text):bool { atomic_control_write(control_directory().'/domains.conf',$text);return true; }
function domain_ready_fixture(PDO $db,string $fqdn='a.example.net'):int
{
    $id=domain_alias_fixture($db,$fqdn);domain_process_one($db,'domain_test_issuer','domain_test_publish');expect_same('ACTIVE',domain_row($db,$id)['status']);return$id;
}
function domain_job(PDO $db,int $id):array { $q=$db->prepare('SELECT * FROM certificate_jobs WHERE domain_id=?');$q->execute([$id]);return$q->fetch(); }

test_case('v7 fresh primary is ACTIVE, host-managed and unique',function(){
    $db=domain_fixture();$row=domain_list($db)[0];expect_same(7,(int)$db->query('PRAGMA user_version')->fetchColumn());
    expect_same('gateway.test',$row['fqdn']);expect_same('PRIMARY',$row['role']);expect_same('ACTIVE',$row['status']);expect_same('/ssl/active',$row['certificate_path']);
    expect_exception(fn()=>$db->exec("INSERT INTO gateway_domains(fqdn,role,status,certificate_path,created_at,updated_at) VALUES ('second.test','PRIMARY','ACTIVE','/ssl/active',1,1)"),PDOException::class);
});
[$migrated]=$migrationFixture=source_fixture();save_token($migrated,str_repeat('d',32),'BLOCKED');create_admin($migrated,'v6_admin','safe-migration-password');
add_ip_rule($migrated,'198.51.100.0/24','BLACKLIST');add_ua_rule($migrated,'V6Client','BLACKLIST');tracking_assignment_for_hash($migrated,token_hash_value(str_repeat('d',32)));
schema_remove_v7_fixture($migrated);$migrated->exec('PRAGMA user_version=6');$oldRows=schema_v6_snapshot($migrated);
test_case('real v6 upgrades to v7 and creates primary without regrouping',function()use($migrated){initialize_database($migrated);expect_same(7,(int)$migrated->query('PRAGMA user_version')->fetchColumn());expect_same('gateway.test',domain_list($migrated)[0]['fqdn']);});
foreach(array_keys($oldRows)as$table)test_case('v6 to v7 preserves all rows and columns: '.$table,function()use($migrated,$oldRows,$table){expect_same($oldRows[$table],$migrated->query('SELECT * FROM '.$table.' ORDER BY 1')->fetchAll());});
test_case('v7 foreign keys integrity and idempotency',function()use($migrated){$before=schema_v6_snapshot($migrated);initialize_database($migrated);expect_same($before,schema_v6_snapshot($migrated));expect_same([],$migrated->query('PRAGMA foreign_key_check')->fetchAll());expect_same(['ok'],$migrated->query('PRAGMA integrity_check')->fetchAll(PDO::FETCH_COLUMN));});
test_case('v7 migration conflict rolls back every table and version',function(){ $db=domain_fixture();schema_remove_v7_fixture($db);$db->exec('PRAGMA user_version=6; CREATE TABLE cloudflare_credentials(conflict TEXT)');$schema=$db->query('SELECT name,sql FROM sqlite_master ORDER BY name')->fetchAll();$rows=schema_v6_snapshot($db);expect_exception(fn()=>initialize_database($db),PDOException::class);expect_same(6,(int)$db->query('PRAGMA user_version')->fetchColumn());expect_same($schema,$db->query('SELECT name,sql FROM sqlite_master ORDER BY name')->fetchAll());expect_same($rows,schema_v6_snapshot($db));expect_same(1,(int)$db->query('PRAGMA foreign_keys')->fetchColumn()); });

test_case('CF profile ciphertext decrypts with independent AAD only',function(){ $db=domain_fixture();$id=domain_profile_fixture($db);$row=cloudflare_profile($db,$id);expect_same(DOMAIN_TEST_SECRET,cloudflare_decrypt($row['token_encrypted']));expect_true(!str_contains($row['token_encrypted'],DOMAIN_TEST_SECRET));expect_exception(fn()=>decrypt_token($row['token_encrypted']),RuntimeException::class);expect_exception(fn()=>cloudflare_decrypt(encrypt_token(DOMAIN_TEST_SECRET)),RuntimeException::class); });
foreach(['database','API GET','domain GET','HTML','logs','control','certs','acme']as$location)test_case('CF plaintext absent from '.$location,function()use($location){$db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,'domain_test_issuer','domain_test_publish');$text=match($location){'database'=>json_encode($db->query('SELECT * FROM cloudflare_credentials')->fetchAll()),'API GET'=>json_encode(cloudflare_profiles($db)),'domain GET'=>json_encode(domain_list($db)),'HTML'=>(string)file_get_contents(__DIR__.'/../sgw/admin/src/dashboard.php'),default=>''};if(in_array($location,['control','certs','acme'],true)){ $root=$location==='control'?control_directory():domain_cert_root();foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS))as$file)if($file->isFile())$text.=(string)file_get_contents($file->getPathname()); }expect_true(!str_contains($text,DOMAIN_TEST_SECRET));if($location==='API GET'){expect_true(!str_contains($text,'token_encrypted'));expect_true(str_contains($text,'token_configured'));} });
test_case('CF blank edit preserves secret and replacement updates last4',function(){ $db=domain_fixture();$id=domain_profile_fixture($db);cloudflare_save_profile($db,['token'=>'','name'=>'changed'],$id,'domain_test_client');expect_same(DOMAIN_TEST_SECRET,cloudflare_decrypt(cloudflare_profile($db,$id)['token_encrypted']));cloudflare_save_profile($db,['token'=>'replacement_secret_1234'],$id,'domain_test_client');expect_same('replacement_secret_1234',cloudflare_decrypt(cloudflare_profile($db,$id)['token_encrypted']));expect_same('1234',cloudflare_profiles($db)[0]['token_last4']); });
test_case('CF same zone and token reuse single profile',function(){ $db=domain_fixture();$id=domain_profile_fixture($db);expect_same($id,domain_profile_fixture($db));domain_alias_fixture($db);domain_alias_fixture($db,'b.example.net');expect_same(1,(int)$db->query('SELECT COUNT(*) FROM cloudflare_credentials')->fetchColumn()); });
test_case('CF unused profile physically deletes ciphertext',function(){ $db=domain_fixture();$id=domain_profile_fixture($db);cloudflare_delete_profile($db,$id);expect_same([],cloudflare_profiles($db)); });
test_case('CF referenced profile deletion reports alias count',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);$profile=(int)domain_row($db,$id)['credential_id'];try{cloudflare_delete_profile($db,$profile);throw new LogicException('not rejected');}catch(InvalidArgumentException $e){expect_true(str_contains($e->getMessage(),'1'));} });
test_case('CF failed tests store only safe summary',function(){ $db=domain_fixture();$id=domain_profile_fixture($db);$fail=fn()=>throw new RuntimeException(DOMAIN_TEST_SECRET);$r=cloudflare_test_profile($db,$id,$fail);expect_same(false,$r['tested']);expect_true(!str_contains(json_encode(cloudflare_profiles($db)),DOMAIN_TEST_SECRET)); });
test_case('CF profile zone change cannot strand existing aliases',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);expect_exception(fn()=>cloudflare_save_profile($db,['zone_id'=>str_repeat('b',32)],(int)domain_row($db,$id)['credential_id'],'domain_test_client'),InvalidArgumentException::class); });
foreach(['a.example.net'=>true,'example.net'=>true,'notexample.net'=>false,'a.example.net.evil.org'=>false,'other.org'=>false]as$fqdn=>$expected)test_case('CF label boundary '.$fqdn,function()use($fqdn,$expected){expect_same($expected,domain_in_zone($fqdn,'example.net'));});
foreach(['https://a.example.net','a.example.net:443','a.example.net/path','a.example.net?x=1','user@a.example.net','-bad.example.net','a..example.net',str_repeat('a',64).'.example.net','127.0.0.1',str_repeat('a.',127).'net']as$invalid)test_case('FQDN rejects '.$invalid,function()use($invalid){expect_exception(fn()=>domain_fqdn($invalid),InvalidArgumentException::class);});
test_case('FQDN lowercase normalization',fn()=>expect_same('a.example.net',domain_fqdn(' A.Example.NET ')));
test_case('Zone ID rejects injection and wrong length',function(){foreach(['abc','../../test',str_repeat('z',32)]as$id)expect_exception(fn()=>cloudflare_zone_id($id),InvalidArgumentException::class);});
test_case('Inline domain/token/zone creates async PENDING job',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);expect_same('PENDING',domain_row($db,$id)['status']);expect_same('PENDING',domain_job($db,$id)['state']);expect_same(1,count(cloudflare_profiles($db))); });
test_case('Different CF accounts and zones coexist',function(){ $db=domain_fixture();domain_alias_fixture($db);$profile=domain_profile_fixture($db,'b','other_account_secret_5678');$id=domain_add($db,['fqdn'=>'node.other.org','credential_id'=>$profile],'domain_test_client');expect_same($profile,(int)domain_row($db,$id)['credential_id']);expect_same(2,count(cloudflare_profiles($db))); });
test_case('Existing profile accepts matching zone and rejects mismatch',function(){ $db=domain_fixture();$profile=domain_profile_fixture($db);domain_add($db,['fqdn'=>'a.example.net','credential_id'=>$profile],'domain_test_client');expect_exception(fn()=>domain_add($db,['fqdn'=>'a.other.org','credential_id'=>$profile],'domain_test_client'),InvalidArgumentException::class); });
test_case('Duplicate and primary aliases reject before CF requests',function(){ $db=domain_fixture();domain_alias_fixture($db);$network=fn()=>throw new LogicException('should not call');foreach(['a.example.net','gateway.test']as$fqdn)expect_exception(fn()=>domain_add($db,['fqdn'=>$fqdn],$network),InvalidArgumentException::class); });
test_case('Backend enforces 100 aliases',function(){ $db=domain_fixture();$profile=domain_profile_fixture($db);$q=$db->prepare("INSERT INTO gateway_domains(fqdn,role,status,credential_id,certificate_path,created_at,updated_at) VALUES (?,'ALIAS','ERROR',?,'unused',1,1)");for($i=0;$i<100;$i++)$q->execute(['d'.$i.'.example.net',$profile]);expect_exception(fn()=>domain_alias_fixture($db),InvalidArgumentException::class); });
test_case('Certificate success activates only the issued alias',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);expect_same('DONE',domain_job($db,$id)['state']);expect_true((int)domain_row($db,$id)['expires_at']>time());expect_true(is_link(domain_directory($id).'/active'));expect_same('ACTIVE',domain_list($db)[0]['status']); });
test_case('Failed alias leaves primary and other alias unchanged',function(){ $db=domain_fixture();$a=domain_ready_fixture($db);$before=domain_active($a);$config=file_get_contents(control_directory().'/domains.conf');$b=domain_alias_fixture($db,'b.example.net');domain_process_one($db,fn()=>throw new RuntimeException(DOMAIN_TEST_SECRET),'domain_test_publish');expect_same('ERROR',domain_row($db,$b)['status']);expect_same('ACTIVE',domain_row($db,$a)['status']);expect_same($before,domain_active($a));expect_same($config,file_get_contents(control_directory().'/domains.conf'));expect_true(!str_contains(domain_row($db,$b)['last_error'],DOMAIN_TEST_SECRET)); });
test_case('ERROR manual retry immediately overrides backoff',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,fn()=>throw new RuntimeException(),'domain_test_publish');expect_true((int)domain_job($db,$id)['next_retry_at']>time());domain_action($db,$id,'RETRY');expect_same(0,(int)domain_job($db,$id)['next_retry_at']);domain_process_one($db,'domain_test_issuer','domain_test_publish');expect_same('ACTIVE',domain_row($db,$id)['status']); });
test_case('Primary deletion forbidden by API and SQLite trigger',function(){ $db=domain_fixture();$id=(int)domain_list($db)[0]['id'];expect_exception(fn()=>domain_action($db,$id,'REMOVE'),InvalidArgumentException::class);expect_exception(fn()=>$db->exec('DELETE FROM gateway_domains WHERE id='.$id),PDOException::class); });
test_case('Alias delete ACK precedes DB and certificate cleanup',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);domain_action($db,$id,'REMOVE');expect_same('REMOVING',domain_row($db,$id)['status']);domain_process_one($db,null,function($db,$job,$text)use($id){expect_same('REMOVING',domain_row($db,$id)['status']);expect_true(is_link(domain_directory($id).'/active'));expect_true(!str_contains($text,'a.example.net'));return domain_test_publish($db,$job,$text);});expect_exception(fn()=>domain_row($db,$id),InvalidArgumentException::class);expect_true(!is_dir(domain_cert_root().'/'.$id)); });
test_case('Delete reload failure restores ACTIVE with old certificate',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$old=domain_active($id);domain_action($db,$id,'REMOVE');domain_process_one($db,null,fn()=>false);expect_same('ACTIVE',domain_row($db,$id)['status']);expect_same($old,domain_active($id)); });
test_case('New alias nginx test/reload failure never becomes ACTIVE',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,'domain_test_issuer',fn()=>false);expect_same('ERROR',domain_row($db,$id)['status']);expect_same(null,domain_active($id)); });
test_case('Renew switches independent release only after validation',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$old=domain_active($id);domain_action($db,$id,'RETRY');domain_process_one($db,'domain_test_issuer','domain_test_publish');expect_true($old!==domain_active($id));expect_same('ACTIVE',domain_row($db,$id)['status']); });
test_case('Renew reload failure restores old symlink and other aliases',function(){ $db=domain_fixture();$a=domain_ready_fixture($db);$b=domain_ready_fixture($db,'b.example.net');$old=domain_active($a);$other=domain_active($b);domain_action($db,$a,'RETRY');$calls=0;domain_process_one($db,'domain_test_issuer',function()use(&$calls){$calls++;return $calls>1;});expect_same($old,domain_active($a));expect_same($other,domain_active($b));expect_same('ACTIVE',domain_row($db,$a)['status']);expect_same(2,$calls); });
test_case('Wrong SAN refuses activation',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,function($row,$dir,$p){$row['fqdn']='wrong.example.net';domain_test_issuer($row,$dir,$p);},'domain_test_publish');expect_same('ERROR',domain_row($db,$id)['status']);expect_same(null,domain_active($id)); });
test_case('Malformed PEM refuses activation',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,function($row,$dir){file_put_contents($dir.'/fullchain.pem','bad');file_put_contents($dir.'/privkey.pem','bad');},'domain_test_publish');expect_same('ERROR',domain_row($db,$id)['status']); });
test_case('Mismatched certificate/private key refuses activation',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);domain_process_one($db,function($row,$dir,$p){domain_test_issuer($row,$dir,$p);$row['fqdn']='wrong.example.net';$tmp=$dir.'/wrong';mkdir($tmp);domain_test_issuer($row,$tmp,$p);copy($tmp.'/privkey.pem',$dir.'/privkey.pem');},'domain_test_publish');expect_same('ERROR',domain_row($db,$id)['status']); });
test_case('Certificate path traversal and symlink escape rejected',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);expect_exception(fn()=>domain_release_path($id,'../../ssl/active'),RuntimeException::class);expect_exception(fn()=>domain_directory(0),RuntimeException::class);$path=domain_directory($id);symlink('/tmp',$path.'/active');expect_exception(fn()=>domain_active($id),RuntimeException::class); });
test_case('Not-near-expiry certificate does not renew daily',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$db->exec('UPDATE gateway_domains SET next_check_at=0');domain_schedule($db,time());expect_same('DONE',domain_job($db,$id)['state']); });
test_case('30 day threshold schedules a renew',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$db->exec('UPDATE gateway_domains SET next_check_at=0,expires_at='.(time()+30*86400));domain_schedule($db,time());expect_same('PENDING',domain_job($db,$id)['state']);expect_same('RENEW',domain_job($db,$id)['operation']); });
test_case('Retry backs off and does not call ACME every poll',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);$calls=0;$fail=function()use(&$calls){$calls++;throw new RuntimeException();};$now=time();domain_process_one($db,$fail,'domain_test_publish',$now);expect_same($now+300,(int)domain_job($db,$id)['next_retry_at']);expect_same(false,domain_process_one($db,$fail,'domain_test_publish',$now+1));domain_process_one($db,$fail,'domain_test_publish',$now+300);expect_same($now+900,(int)domain_job($db,$id)['next_retry_at']);expect_same(2,$calls); });
test_case('Restart RUNNING issue safely resumes without another issuance',function(){ $db=domain_fixture();$id=domain_alias_fixture($db);$calls=0;$issue=function(...$args)use(&$calls){$calls++;domain_test_issuer(...$args);};domain_process_one($db,$issue,fn()=>throw new DomainPublishPending());expect_same('RUNNING',domain_job($db,$id)['state']);domain_process_one($db,$issue,'domain_test_publish');expect_same('ACTIVE',domain_row($db,$id)['status']);expect_same(1,$calls); });
test_case('Primary sync preserves aliases and refuses collision',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$old=domain_row($db,$id);domain_sync_primary($db,'new.gateway.test');expect_same($old,domain_row($db,$id));expect_same('new.gateway.test',domain_list($db)[0]['fqdn']);expect_exception(fn()=>domain_sync_primary($db,'a.example.net'),InvalidArgumentException::class); });
test_case('Alias SNI candidate shares exact Gateway locations and no token or upstream data',function(){ $db=domain_fixture();$id=domain_ready_fixture($db);$text=domain_candidate($db,$id,'RENEW');expect_true(str_contains($text,'include /etc/nginx/gateway-locations.conf;'));expect_true(str_contains($text,'/domain-certs/'.$id.'/active/privkey.pem'));expect_true(!str_contains($text,DOMAIN_TEST_SECRET));expect_true(!str_contains($text,'proxy_pass')); });
test_case('Adding alias never changes Token assignments or business settings',function(){ [$db]=source_fixture();$before=schema_v6_snapshot($db);domain_alias_fixture($db);expect_same($before,schema_v6_snapshot($db)); });
test_case('Post-ACK delete cleanup failure never resurrects an ACTIVE alias',function(){
    $db=domain_fixture();$id=domain_ready_fixture($db);domain_action($db,$id,'REMOVE');
    $locked=domain_directory($id).'/locked';mkdir($locked,0700);file_put_contents($locked.'/file','fixture');chmod($locked,0000);
    domain_process_one($db,null,'domain_test_publish');
    expect_same('REMOVING',domain_row($db,$id)['status']);expect_same('RUNNING',domain_job($db,$id)['state']);
    expect_true(!str_contains((string)file_get_contents(control_directory().'/domains.conf'),'a.example.net'));
    chmod($locked,0700);$db->exec('UPDATE certificate_jobs SET next_retry_at=0');
    domain_process_one($db,null,'domain_test_publish');expect_exception(fn()=>domain_row($db,$id),InvalidArgumentException::class);
});
putenv('CONTROL_DIR');putenv('DOMAIN_CERT_DIR');
