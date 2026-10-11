<?php
declare(strict_types=1);
require_once __DIR__ . '/publish.php';
require_once __DIR__ . '/cloudflare.php';

const DOMAIN_ALIAS_LIMIT = 100;
const DOMAIN_RENEW_SECONDS = 30 * 86400;
class DomainPublishPending extends RuntimeException {}

function domain_row(PDO $pdo, int $id): array
{
    $q=$pdo->prepare('SELECT * FROM gateway_domains WHERE id=?'); $q->execute([$id]);
    $row=$q->fetch(); if(!$row) throw new InvalidArgumentException('入口域名不存在'); return $row;
}

function domain_list(PDO $pdo): array
{
    $rows=$pdo->query('SELECT d.*,c.name AS credential_name,j.operation,j.attempts,j.next_retry_at FROM gateway_domains d LEFT JOIN cloudflare_credentials c ON c.id=d.credential_id LEFT JOIN certificate_jobs j ON j.domain_id=d.id ORDER BY d.id')->fetchAll();
    foreach($rows as &$row) if($row['role']==='PRIMARY') {
        $cert=@openssl_x509_parse((string)@file_get_contents('/ssl/active/fullchain.pem'));
        $row['expires_at']=is_array($cert)?($cert['validTo_time_t']??null):null;
    }
    return $rows;
}

function domain_queue(PDO $pdo, array $row, string $operation): void
{
    $q=$pdo->prepare("SELECT state FROM certificate_jobs WHERE domain_id=?"); $q->execute([$row['id']]);
    if(in_array($q->fetchColumn(),['PENDING','RUNNING'],true)) throw new InvalidArgumentException('该域名的证书任务正在进行，请稍后重试');
    $q=$pdo->prepare("INSERT INTO certificate_jobs(domain_id,operation,state,previous_status,created_at,updated_at) VALUES (?,?,'PENDING',?,?,?) ON CONFLICT(domain_id) DO UPDATE SET operation=excluded.operation,state='PENDING',previous_status=excluded.previous_status,attempts=0,next_retry_at=0,last_error=NULL,release=NULL,previous_release=NULL,request_id=NULL,request_sha=NULL,updated_at=excluded.updated_at");
    $q->execute([$row['id'],$operation,$row['status'],time(),time()]);
}

function domain_add(PDO $pdo, array $body, ?callable $client=null): int
{
    $fqdn=domain_fqdn((string)($body['fqdn']??''));
    // Validate inexpensive limits before contacting Cloudflare; recheck under the write lock.
    domain_add_guard($pdo,$fqdn);
    $profileId=(int)($body['credential_id']??0);
    if($profileId>0) {
        $profile=cloudflare_profile($pdo,$profileId);
        $token=cloudflare_decrypt($profile['token_encrypted']);
        $zone=cloudflare_zone($token,$profile['zone_id'],$client);
    } else {
        $token=trim((string)($body['token']??''));
        $zone=cloudflare_zone($token,(string)($body['zone_id']??''),$client);
    }
    if(str_contains($fqdn,strtolower($token))) throw new InvalidArgumentException('入口域名不可包含 API Token');
    if(!domain_in_zone($fqdn,$zone)) throw new InvalidArgumentException('备用域名不属于该 Cloudflare Zone');
    $validatedZoneId=$profileId>0?$profile['zone_id']:cloudflare_zone_id((string)$body['zone_id']);
    // Do not hold SQLite's global writer lock during a second network validation.
    $validatedClient=static fn()=>['success'=>true,'result'=>['id'=>$validatedZoneId,'name'=>$zone]];
    return write_transaction($pdo,static function()use($pdo,$body,$profileId,$fqdn,$validatedClient):int{
        domain_add_guard($pdo,$fqdn);
        $id=$profileId>0?$profileId:cloudflare_save_profile($pdo,$body,null,$validatedClient);
        if(!domain_in_zone($fqdn,cloudflare_profile($pdo,$id)['zone_name'])) throw new InvalidArgumentException('备用域名不属于该 Cloudflare Zone');
        $q=$pdo->prepare("INSERT INTO gateway_domains(fqdn,role,status,credential_id,certificate_path,created_at,updated_at) VALUES (?,'ALIAS','PENDING',?,'',?,?)");
        $q->execute([$fqdn,$id,time(),time()]); $domainId=(int)$pdo->lastInsertId();
        $pdo->prepare('UPDATE gateway_domains SET certificate_path=? WHERE id=?')->execute(['/domain-certs/'.$domainId.'/active',$domainId]);
        domain_queue($pdo,domain_row($pdo,$domainId),'ISSUE'); return $domainId;
    });
}

function domain_add_guard(PDO $pdo,string $fqdn):void
{
    $q=$pdo->prepare('SELECT id FROM gateway_domains WHERE fqdn=?'); $q->execute([$fqdn]);
    if($q->fetchColumn()!==false) throw new InvalidArgumentException('该域名已存在（主域名或备用域名）');
    if((int)$pdo->query("SELECT COUNT(*) FROM gateway_domains WHERE role='ALIAS'")->fetchColumn()>=DOMAIN_ALIAS_LIMIT) throw new InvalidArgumentException('最多允许 100 个备用入口域名');
}

function domain_action(PDO $pdo,int $id,string $action):void
{
    write_transaction($pdo,static function()use($pdo,$id,$action):void{
        $row=domain_row($pdo,$id);
        if($row['role']!=='ALIAS') throw new InvalidArgumentException('主域名只能使用 setup.sh 管理，不能从后台删除或签发');
        $operation=$action==='REMOVE'?'REMOVE':($row['status']==='ACTIVE'?'RENEW':'ISSUE');
        domain_queue($pdo,$row,$operation);
        if($operation==='REMOVE') $pdo->prepare("UPDATE gateway_domains SET status='REMOVING',updated_at=? WHERE id=?")->execute([time(),$id]);
        elseif($row['status']!=='ACTIVE') $pdo->prepare("UPDATE gateway_domains SET status='PENDING',last_error=NULL,updated_at=? WHERE id=?")->execute([time(),$id]);
    });
}

function domain_sync_primary(PDO $pdo,string $fqdn):void
{
    $fqdn=domain_fqdn($fqdn);
    write_transaction($pdo,static function()use($pdo,$fqdn):void{
        $q=$pdo->prepare("SELECT id FROM gateway_domains WHERE role='ALIAS' AND fqdn=?"); $q->execute([$fqdn]);
        if($q->fetchColumn()!==false) throw new InvalidArgumentException('新主域名已作为备用域名使用');
        $q=$pdo->prepare("UPDATE gateway_domains SET fqdn=?,updated_at=? WHERE role='PRIMARY'"); $q->execute([$fqdn,time()]);
        if($q->rowCount()!==1) throw new RuntimeException('主域名记录同步失败');
    });
}

function domain_cert_root():string { return (string)(getenv('DOMAIN_CERT_DIR')?:'/domain-certs'); }

/** Only numeric IDs and validated relative releases. Never follow user-controlled directory symlinks. */
function domain_safe_dir(string $path):void
{
    if(is_link($path)) throw new RuntimeException('不安全的证书目录');
    if(!is_dir($path) && !mkdir($path,0750)) throw new RuntimeException('证书目录创建失败');
    if(!chmod($path,0750)) throw new RuntimeException('证书目录权限设置失败');
}

function domain_directory(int $id):string
{
    if($id<1) throw new RuntimeException('不安全的域名编号');
    $root=domain_cert_root();
    // Require a canonical mount root, including its ancestors, not a symlink alias.
    $cursor=$root; while($cursor!==dirname($cursor)) { if(is_link($cursor)) throw new RuntimeException('不安全的证书目录'); $cursor=dirname($cursor); }
    domain_safe_dir($root); domain_safe_dir($root.'/'.$id); domain_safe_dir($root.'/'.$id.'/releases');
    return $root.'/'.$id;
}

function domain_release_path(int $id,string $release):string
{
    if(!preg_match('#^releases/[0-9a-f]{32}$#D',$release)) throw new RuntimeException('不安全的证书版本');
    $dir=domain_directory($id).'/'.$release;
    if(is_link($dir)) throw new RuntimeException('不安全的证书版本');
    return $dir;
}

function domain_active(int $id):?string
{
    $path=domain_directory($id).'/active';
    if(!file_exists($path) && !is_link($path)) return null;
    if(!is_link($path)) throw new RuntimeException('不安全的证书链接');
    $release=readlink($path); if(!is_string($release)) throw new RuntimeException('证书链接读取失败');
    domain_release_path($id,$release); return $release;
}

function domain_activate(int $id,?string $release):void
{
    $path=domain_directory($id).'/active';
    domain_active($id);
    if($release===null) { if(is_link($path)) unlink($path); return; }
    $dir=domain_release_path($id,$release);
    if(!is_dir($dir)) throw new RuntimeException('证书版本不存在');
    $next=$path.'.'.bin2hex(random_bytes(8));
    if(!symlink($release,$next) || !rename($next,$path)) throw new RuntimeException('证书切换失败');
    clearstatcache();
}

function domain_command(array $args,array $env=[]):void
{
    $process=proc_open($args,[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']],$pipes,null,$env?:null);
    if(!is_resource($process)) throw new RuntimeException('Certificate command failed');
    $deadline=time()+900;
    do { $status=proc_get_status($process); if(!$status['running']) break;
        if(time()>$deadline) { proc_terminate($process); proc_close($process); throw new RuntimeException('Certificate command timed out'); }
        usleep(200000);
    }while(true);
    $exit=$status['exitcode']; proc_close($process);
    if($exit!==0) throw new RuntimeException('Certificate command failed');
}

function domain_validate_certificate(string $dir,string $fqdn):int
{
    foreach(['fullchain.pem','privkey.pem']as$file) if(!is_file($dir.'/'.$file)||is_link($dir.'/'.$file)) throw new RuntimeException('Certificate validation failed');
    $pem=(string)file_get_contents($dir.'/fullchain.pem'); $key=openssl_pkey_get_private((string)file_get_contents($dir.'/privkey.pem'));
    $cert=openssl_x509_read($pem); $info=$cert?openssl_x509_parse($cert):false;
    if(!$key||!$cert||!openssl_x509_check_private_key($cert,$key)||!is_array($info)
        ||($info['validFrom_time_t']??PHP_INT_MAX)>time()+300||($info['validTo_time_t']??0)<time()+86400
        ||!str_contains((string)($info['extensions']['subjectAltName']??''),'DNS:')) throw new RuntimeException('Certificate validation failed');
    $covered=false;
    foreach(explode(',',(string)$info['extensions']['subjectAltName'])as$san) {
        $san=strtolower(trim($san)); if(!str_starts_with($san,'dns:')) continue;
        $name=substr($san,4);
        if($name===$fqdn || (str_starts_with($name,'*.') && substr($fqdn,strpos($fqdn,'.')+1)===substr($name,2))) $covered=true;
    }
    if(!$covered) throw new RuntimeException('Certificate hostname mismatch');
    domain_command(['openssl','x509','-in',$dir.'/fullchain.pem','-noout','-checkhost',$fqdn]);
    return (int)$info['validTo_time_t'];
}

function domain_remove_tree(string $path):void
{
    // Callers pass only already-validated per-ID or generated temporary paths. Symlinks are unlinked, never followed.
    if(is_link($path)||is_file($path)) { if(!unlink($path)) throw new RuntimeException('证书清理失败'); return; }
    if(!is_dir($path)) return;
    foreach(new FilesystemIterator($path,FilesystemIterator::SKIP_DOTS)as$file) domain_remove_tree($file->getPathname());
    if(!rmdir($path)) throw new RuntimeException('证书清理失败');
}

function domain_copy_account(string $source,string $target):void
{
    if(!is_dir($source)||is_link($source)) return;
    domain_safe_dir($target);
    foreach(new FilesystemIterator($source,FilesystemIterator::SKIP_DOTS)as$file) {
        if($file->isLink()) throw new RuntimeException('不安全的 ACME 账户目录');
        if($file->isDir()) { domain_copy_account($file->getPathname(),$target.'/'.$file->getFilename()); continue; }
        // The official CA account directory contains keys, registration JSON and ca.conf only.
        if(!in_array($file->getFilename(),['account.key','account.json','ca.conf'],true)) continue;
        $data=(string)file_get_contents($file->getPathname());
        if($file->getFilename()==='ca.conf') {
            $data=implode("\n",array_filter(explode("\n",$data),static fn($s)=>preg_match('/^(ACCOUNT_URL|ACCOUNT_EMAIL|ACCOUNT_THUMBPRINT|CA_KEY_HASH|CA_EAB_KEY_ID|CA_EAB_HMAC_KEY)=/',$s)))."\n";
        }
        atomic_control_write($target.'/'.$file->getFilename(),$data); chmod($target.'/'.$file->getFilename(),0600);
    }
}

function domain_issue_certificate(array $row,string $dir,array $profile):void
{
    $base=domain_directory((int)$row['id']);
    domain_safe_dir($base.'/acme');
    $tmp=sys_get_temp_dir().'/sgw-acme-'.bin2hex(random_bytes(16)); mkdir($tmp,0700);
    $token=cloudflare_decrypt($profile['token_encrypted']);
    try {
        domain_copy_account($base.'/acme/ca',$tmp.'/ca');
        $env=['PATH'=>(string)getenv('PATH'),'HOME'=>$tmp,'CF_Token'=>$token,'CF_Zone_ID'=>$profile['zone_id'],
            'SGW_CF_ZONE_NAME'=>$profile['zone_name'],'SGW_CERT_TEST_MODE'=>(string)getenv('SGW_CERT_TEST_MODE'),
            'SGW_CF_TEST_URL'=>(string)getenv('SGW_CF_TEST_URL')];
        if(getenv('SGW_CERT_TEST_MODE')==='1' && getenv('SGW_ACME_TEST_RUNNER')) {
            domain_command([(string)getenv('SGW_ACME_TEST_RUNNER'),$row['fqdn'],$dir,$tmp],$env);
        } else {
            domain_command(['/opt/acme/acme.sh','--home','/opt/acme','--config-home',$tmp,'--cert-home',$tmp.'/domains',
                '--issue','--server','letsencrypt','--dns','dns_sgw_cf','--keylength','ec-256','-d',$row['fqdn'],'--force'],$env);
            $issued=$tmp.'/domains/'.$row['fqdn'].'_ecc';
            if(!copy($issued.'/fullchain.cer',$dir.'/fullchain.pem')||!copy($issued.'/'.$row['fqdn'].'.key',$dir.'/privkey.pem')) throw new RuntimeException('Certificate install failed');
        }
    } finally {
        // Copy ONLY secret-free account state, even after a failed issue. No domain config or logs persist.
        try { domain_copy_account($tmp.'/ca',$base.'/acme/ca'); }
        finally { sodium_memzero($token); domain_remove_tree($tmp); }
    }
    chmod($dir.'/fullchain.pem',0640); chmod($dir.'/privkey.pem',0640);
}

function domain_candidate(PDO $pdo,int $id,string $operation):string
{
    $rows=$pdo->query("SELECT id,fqdn,status FROM gateway_domains WHERE role='ALIAS' ORDER BY id")->fetchAll();
    $text="# Managed alias servers; primary certificate remains host-managed.\n";
    foreach($rows as $row) {
        if((int)$row['id']===$id ? $operation==='REMOVE' : !in_array($row['status'],['ACTIVE','REMOVING'],true)) continue;
        $fqdn=domain_fqdn($row['fqdn']); $domainId=(int)$row['id'];
        $text.="server {\n    listen 8443 ssl;\n    server_name {$fqdn};\n    ssl_certificate /domain-certs/{$domainId}/active/fullchain.pem;\n    ssl_certificate_key /domain-certs/{$domainId}/active/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    include /etc/nginx/gateway-locations.conf;\n}\n";
    }
    return $text;
}

/** Request journal precedes the atomic file publication. A timeout remains RUNNING; never roll back a possibly late ACK. */
function domain_publish(PDO $pdo,array $job,string $candidate):bool
{
    $directory=control_directory(); $sha=hash('sha256',$candidate); $id=$job['request_id'];
    if(!$id||$job['request_sha']!==$sha) {
        $id=bin2hex(random_bytes(16));
        $pdo->prepare('UPDATE certificate_jobs SET request_id=?,request_sha=? WHERE domain_id=?')->execute([$id,$sha,$job['domain_id']]);
    }
    $version=(int)$job['domain_id'];
    $result=matching_publish_result($directory.'/domain-result.json',$id,$version,$sha);
    if($result!==null) return $result['ok'];
    atomic_control_write($directory.'/domain-candidate.conf',$candidate);
    atomic_control_write($directory.'/domain-request.json',json_encode(['id'=>$id,'version'=>$version,'sha256'=>$sha],JSON_THROW_ON_ERROR)."\n");
    $deadline=microtime(true)+PUBLISH_TIMEOUT_SECONDS;
    do {
        $result=matching_publish_result($directory.'/domain-result.json',$id,$version,$sha);
        if($result!==null) return $result['ok'];
        usleep(100000);
    }while(microtime(true)<$deadline);
    throw new DomainPublishPending('Gateway acknowledgment pending');
}

function domain_schedule(PDO $pdo,int $now):void
{
    write_transaction($pdo,static function()use($pdo,$now):void{
        $q=$pdo->prepare("SELECT d.* FROM gateway_domains d LEFT JOIN certificate_jobs j ON j.domain_id=d.id WHERE d.role='ALIAS' AND d.status='ACTIVE' AND d.next_check_at<=? AND (j.state IS NULL OR j.state='DONE')"); $q->execute([$now]);
        foreach($q->fetchAll()as$row) {
            if((int)$row['expires_at']-$now<=DOMAIN_RENEW_SECONDS) domain_queue($pdo,$row,'RENEW');
            $pdo->prepare('UPDATE gateway_domains SET next_check_at=? WHERE id=?')->execute([$now+86400,$row['id']]);
        }
    });
}

/** One worker owns the global file lock. Injectable callables are only used by direct unit tests. */
function domain_process_one(PDO $pdo,?callable $issuer=null,?callable $publisher=null,?int $now=null):bool
{
    $now??=time(); domain_schedule($pdo,$now);
    $q=$pdo->prepare("SELECT * FROM certificate_jobs WHERE state IN ('PENDING','RUNNING','RETRY') AND next_retry_at<=? ORDER BY CASE state WHEN 'RUNNING' THEN 0 ELSE 1 END,updated_at,domain_id LIMIT 1"); $q->execute([$now]); $job=$q->fetch();
    if(!$job) return false;
    $id=(int)$job['domain_id']; $row=domain_row($pdo,$id); $renew=$job['operation']==='RENEW';
    $pdo->prepare("UPDATE certificate_jobs SET state='RUNNING',updated_at=? WHERE domain_id=?")->execute([$now,$id]);
    $expires=null;
    try {
        if($job['operation']!=='REMOVE') {
            if(!$job['release']) {
                $release='releases/'.bin2hex(random_bytes(16)); $dir=domain_release_path($id,$release); domain_safe_dir($dir);
                ($issuer??'domain_issue_certificate')($row,$dir,cloudflare_profile($pdo,(int)$row['credential_id']));
                $expires=domain_validate_certificate($dir,$row['fqdn']);
                $previous=domain_active($id);
                $pdo->prepare('UPDATE certificate_jobs SET release=?,previous_release=? WHERE domain_id=?')->execute([$release,$previous,$id]);
                $job['release']=$release; $job['previous_release']=$previous;
            } else $expires=domain_validate_certificate(domain_release_path($id,$job['release']),$row['fqdn']);
            domain_activate($id,$job['release']);
        }
        $candidate=domain_candidate($pdo,$id,$job['operation']);
        if(!(($publisher??'domain_publish')($pdo,$job,$candidate))) throw new RuntimeException('Gateway reload failed');
        if($job['operation']==='REMOVE') {
            // Nginx has acknowledged removal. Cleanup first; crash retries are idempotent.
            try { domain_remove_tree(domain_directory($id)); }
            catch(Throwable) {
                // Removal is already committed in Nginx. A filesystem cleanup failure must
                // NOT resurrect ACTIVE in SQLite without restoring the removed server.
                $pdo->prepare("UPDATE certificate_jobs SET next_retry_at=?,last_error='证书清理待重试',updated_at=? WHERE domain_id=?")->execute([$now+300,$now,$id]);
                $pdo->prepare("UPDATE gateway_domains SET last_error='入口已移除，证书清理待重试' WHERE id=?")->execute([$id]);
                return true;
            }
            $pdo->prepare("DELETE FROM gateway_domains WHERE id=? AND role='ALIAS'")->execute([$id]);
        } else write_transaction($pdo,static function()use($pdo,$id,$expires,$now):void{
            $pdo->prepare("UPDATE gateway_domains SET status='ACTIVE',expires_at=?,last_error=NULL,next_check_at=?,updated_at=? WHERE id=?")->execute([$expires,$now+86400,$now,$id]);
            $pdo->prepare("UPDATE certificate_jobs SET state='DONE',attempts=0,last_error=NULL,updated_at=? WHERE domain_id=?")->execute([$now,$id]);
        });
    } catch(DomainPublishPending) { return true; }
    catch(Throwable) {
        $message=$job['operation']==='REMOVE'?'入口域名删除失败，旧入口已保留':($renew?'证书续签失败，旧证书已保留':'证书申请或 Gateway 发布失败，请检查凭据、证书和网关');
        if($job['release']) {
            domain_activate($id,$job['previous_release']);
            // On failed renew, Nginx still serves the old loaded certificate; explicitly reload the restored link.
            if($renew) {
                $restore=$job; $restore['request_id']=null; $restore['request_sha']=null;
                try { ($publisher??'domain_publish')($pdo,$restore,domain_candidate($pdo,$id,'RENEW')); } catch(Throwable) { /* next retry repeats validation/reload */ }
            }
        }
        $attempts=(int)$job['attempts']+1; $retry=$now+min(86400,300*(2**min($attempts-1,8)));
        $status=$job['operation']==='REMOVE'?$job['previous_status']:($renew?'ACTIVE':'ERROR');
        write_transaction($pdo,static function()use($pdo,$id,$message,$status,$attempts,$retry,$now,$job):void{
            $pdo->prepare('UPDATE gateway_domains SET status=?,last_error=?,updated_at=? WHERE id=?')->execute([$status,$message,$now,$id]);
            $pdo->prepare("UPDATE certificate_jobs SET state=?,attempts=?,next_retry_at=?,last_error=?,release=NULL,previous_release=NULL,request_id=NULL,request_sha=NULL,updated_at=? WHERE domain_id=?")
                ->execute([$job['operation']==='REMOVE'?'DONE':'RETRY',$attempts,$retry,$message,$now,$id]);
        });
    }
    return true;
}

function domain_installation_check(PDO $pdo):array
{
    if((int)$pdo->query('PRAGMA user_version')->fetchColumn()!==DATABASE_SCHEMA_VERSION) throw new RuntimeException('Domain schema mismatch');
    $primary=$pdo->query("SELECT * FROM gateway_domains WHERE role='PRIMARY'")->fetch();
    if(!$primary||$primary['fqdn']!==domain_fqdn(env_required('GATEWAY_DOMAIN'))||$primary['certificate_path']!=='/ssl/active') throw new RuntimeException('Primary domain mismatch');
    $rows=$pdo->query("SELECT * FROM gateway_domains WHERE role='ALIAS' AND status='ACTIVE'")->fetchAll();
    foreach($rows as$row) {
        $base=domain_cert_root().'/'.(int)$row['id'];
        foreach([domain_cert_root(),$base,$base.'/releases']as$path) {
            if(!is_dir($path)||is_link($path)||(fileperms($path)&0027)!==0) throw new RuntimeException('Alias certificate permissions invalid');
        }
        $release=domain_active((int)$row['id']); if($release===null) throw new RuntimeException('Alias certificate missing');
        $dir=domain_release_path((int)$row['id'],$release); domain_validate_certificate($dir,$row['fqdn']);
        foreach([$dir,$dir.'/privkey.pem',$dir.'/fullchain.pem']as$path) if((fileperms($path)&0027)!==0) throw new RuntimeException('Alias certificate permissions invalid');
    }
    $config=control_directory().'/domains.conf';
    if(!is_file($config)||is_link($config)) throw new RuntimeException('Domain configuration missing');
    $text=(string)file_get_contents($config);
    foreach($rows as$row) if(!str_contains($text,'server_name '.$row['fqdn'].';')) throw new RuntimeException('Domain configuration pending');
    return ['schema'=>DATABASE_SCHEMA_VERSION,'active_aliases'=>count($rows)];
}
