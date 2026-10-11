<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';
try {
    app_db()->query('SELECT 1')->fetchColumn();
    $pid=trim((string)@file_get_contents('/run/certificate-worker.pid'));
    if(!ctype_digit($pid)||!is_dir('/proc/'.$pid)||!is_file('/control/certificate-worker.ready')) throw new RuntimeException('Certificate worker unavailable');
    header('Content-Type: text/plain');
    echo 'ok';
} catch (Throwable $error) {
    error_log('Health check failed: ' . $error::class);
    http_response_code(503);
}
