<?php
declare(strict_types=1);
require_once __DIR__.'/cloudflare.php';
if(PHP_SAPI!=='cli') { http_response_code(404); exit; }
try {
    $action=$argv[1]??''; $name=$argv[2]??''; $value=$argv[3]??'';
    $zone=domain_fqdn((string)getenv('SGW_CF_ZONE_NAME'));
    $id=cloudflare_zone_id((string)getenv('CF_Zone_ID'));
    if(!str_starts_with($name,'_acme-challenge.')||!domain_in_zone(domain_fqdn(substr($name,16)),$zone)
        ||!preg_match('/^[A-Za-z0-9_-]{20,256}$/D',$value)) throw new RuntimeException('Invalid challenge');
    $token=(string)getenv('CF_Token');
    if($action==='add') cloudflare_request($token,'POST','zones/'.$id.'/dns_records',['type'=>'TXT','name'=>$name,'content'=>$value,'ttl'=>120]);
    elseif($action==='remove') {
        $rows=cloudflare_request($token,'GET','zones/'.$id.'/dns_records?type=TXT&name='.rawurlencode($name).'&content='.rawurlencode($value));
        foreach($rows['result']??[]as$row) if(($row['type']??'')==='TXT'&&($row['name']??'')===$name&&($row['content']??'')===$value&&preg_match('/^[0-9a-f]{32}$/D',(string)($row['id']??''))) {
            cloudflare_request($token,'DELETE','zones/'.$id.'/dns_records/'.$row['id']);
        }
    } else throw new RuntimeException('Invalid action');
} catch(Throwable) { fwrite(STDERR,"DNS challenge failed\n"); exit(1); }
