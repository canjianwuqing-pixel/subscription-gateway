<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';
try {
    app_db()->query('SELECT 1')->fetchColumn();
    header('Content-Type: text/plain');
    echo 'ok';
} catch (Throwable $error) {
    error_log('Health check failed: ' . $error::class);
    http_response_code(503);
}
