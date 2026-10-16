<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/sgw/admin/src/db.php';
umask(0077);
$db = open_database($argv[1]);
$db->exec('BEGIN IMMEDIATE');
file_put_contents($argv[2], 'locked');
$deadline = microtime(true) + 30;
while (!is_file($argv[3])) {
    if (microtime(true) >= $deadline) { $db->exec('ROLLBACK'); exit(2); }
    usleep(10000); clearstatcache(true, $argv[3]);
}
$db->exec('COMMIT');
echo 'RELEASED';
