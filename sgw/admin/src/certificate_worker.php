<?php
declare(strict_types=1);
require_once __DIR__ . '/domain_certificates.php';
if(PHP_SAPI!=='cli') { http_response_code(404); exit; }

/** One iteration, also exercised directly by contention tests. Never retain a failed PDO in app_db's static cache. */
function certificate_worker_iteration(?PDO &$pdo,?callable $processor=null,?callable $connect=null):bool
{
    try {
        if(!$pdo) {
            $pdo=$connect ? $connect() : open_database((string)app_config()['database_path']);
            initialize_database($pdo);
        }
        atomic_control_write(control_directory().'/certificate-worker.ready',(string)time());
        if(!is_file(control_directory().'/certificate-maintenance')) ($processor??'domain_process_one')($pdo);
        return true;
    } catch(Throwable $error) {
        error_log('Certificate worker iteration failed: '.(sqlite_is_busy($error)?'SQLITE_BUSY_OR_LOCKED':$error::class));
        if($error instanceof PDOException) {
            if($pdo) { try { $pdo->exec('ROLLBACK'); } catch(Throwable) {} }
            $pdo=null; // Sole worker-owned connection; the next iteration opens a fresh one.
        }
        return false;
    }
}

// Loading the iteration helper in CLI tests must not start another worker or acquire its lock.
if(realpath((string)($_SERVER['SCRIPT_FILENAME']??''))!==__FILE__) return;
umask(0027);
$lock=fopen(control_directory().'/certificate-worker.lock','c+');
if(!$lock||!flock($lock,LOCK_EX|LOCK_NB)) exit(1);
// No leases/timeouts steal this process lock during a long ACME request. OS releases it on crash.
$pdo=null;
while(true) {
    certificate_worker_iteration($pdo);
    sleep(2);
}
