<?php
declare(strict_types=1);
require_once __DIR__ . '/domain_certificates.php';
if(PHP_SAPI!=='cli') { http_response_code(404); exit; }
umask(0027);
$lock=fopen(control_directory().'/certificate-worker.lock','c+');
if(!$lock||!flock($lock,LOCK_EX|LOCK_NB)) exit(1);
// No leases/timeouts steal this process lock during a long ACME request. OS releases it on crash.
$pdo=app_db();
while(true) {
    atomic_control_write(control_directory().'/certificate-worker.ready',(string)time());
    if(!is_file(control_directory().'/certificate-maintenance')) domain_process_one($pdo);
    sleep(2);
}
