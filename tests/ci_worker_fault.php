<?php
declare(strict_types=1);
require '/app/src/domain_certificates.php';
umask(0027);
$mode = $argv[1] ?? '';
if ($mode === 'queue') {
    $db = app_db(); $token = trim((string) stream_get_contents(STDIN));
    $profile = cloudflare_save_profile($db, ['name' => 'Worker contention CI', 'token' => $token, 'zone_id' => str_repeat('a', 32)]);
    $a = domain_add($db, ['fqdn' => 'lock-error.example.net', 'credential_id' => $profile]);
    $b = domain_add($db, ['fqdn' => 'after-lock.example.net', 'credential_id' => $profile]);
    $db->prepare("UPDATE certificate_jobs SET state='RUNNING' WHERE domain_id=?")->execute([$a]);
    sodium_memzero($token); echo json_encode(['a' => $a, 'b' => $b]);
} elseif ($mode === 'hold') {
    $db = open_database((string) app_config()['database_path']); $deadline = microtime(true) + 30;
    while (!is_file('/control/ci-issue-recovery-ready')) { if (microtime(true) > $deadline) exit(2); usleep(10000); clearstatcache(); }
    $db->exec('BEGIN IMMEDIATE'); file_put_contents('/control/ci-sqlite-locked', 'locked');
    while (!is_file('/control/ci-release-sqlite')) { if (microtime(true) > $deadline) { $db->exec('ROLLBACK'); exit(3); } usleep(10000); clearstatcache(); }
    $db->exec('COMMIT');
} elseif ($mode === 'states') {
    $db = new PDO('sqlite:' . app_config()['database_path'], null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $q = $db->prepare('SELECT state FROM certificate_jobs WHERE domain_id=?');
    $q->execute([(int) $argv[2]]); $a = $q->fetchColumn(); $q->execute([(int) $argv[3]]);
    echo json_encode(['a' => $a, 'b' => $q->fetchColumn()]);
} else exit(1);
