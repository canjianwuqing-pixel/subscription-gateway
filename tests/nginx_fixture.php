<?php

declare(strict_types=1);

require dirname(__DIR__) . '/sgw/admin/src/compiler.php';

if ($argc !== 6 || !is_file($argv[2]) || !is_file($argv[4]) || !is_file($argv[5])
    || !in_array($argv[3], ['active', 'zero-burst', 'fail-closed'], true)) {
    fwrite(STDERR, "Usage: php nginx_fixture.php <temporary-directory> <mime.types> <mode> <certificate> <key>\n");
    exit(2);
}
$directory = $argv[1];
if (!is_dir($directory) || !is_writable($directory)) {
    throw new RuntimeException('Temporary fixture directory is unavailable');
}
$directory = str_replace('\\', '/', realpath($directory));
$mime = str_replace('\\', '/', realpath($argv[2]));
mkdir($directory . '/generated', 0700);
mkdir($directory . '/logs', 0700);
$pdo = open_database($directory . '/fixture.db');
initialize_database($pdo);
setting_set($pdo, 'upstream_url', 'http://127.0.0.1:12345');
save_token($pdo, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'BLOCKED');
add_ip_rule($pdo, '192.0.2.0/24', 'BLACKLIST');
add_ua_rule($pdo, 'Client.*?[]()\\";', 'BLACKLIST');
if ($argv[3] === 'zero-burst') {
    save_rate_settings($pdo, true, 20, 0);
}
$rules = $argv[3] === 'fail-closed' ? <<<'RULES'
map "" $gateway_ready { default 0; }
map "" $gateway_upstream { default ""; }
map "" $gateway_upstream_host { default ""; }
map "" $tracking_mode { default "off"; }
map "" $gateway_subscription_upstream { default ""; }
map "" $gateway_subscription_host { default ""; }
map "" $gateway_subscription_ssl_name { default ""; }
map "" $tracking_internal_mode { default ""; }
map "" $tracking_internal_client_ip { default ""; }
map "" $tracking_internal_token { default ""; }
map "" $token_valid { default 0; }
map "" $token_query_duplicate { default 0; }
map "" $token_query_unsafe { default 0; }
map "" $token_event_loggable { default 0; }
log_format token_events escape=json '{"time":$msec,"token":"","ip":"$remote_addr","ua":"$http_user_agent","status":$status,"path":"$uri","policy":"$log_decision"}';
map "" $policy_block { default 0; }
map "" $policy_reason { default FAIL_CLOSED; }
map "" $log_decision { default FAIL_CLOSED; }
map "" $rate_key { default ""; }
limit_req_zone $rate_key zone=subscription_rate:10m rate=1r/m;
limit_req zone=subscription_rate nodelay;
limit_req_status 429;
RULES : compile_gateway_rules($pdo)['rules'];
file_put_contents($directory . '/generated/rules.conf', $rules);
file_put_contents($directory . '/generated/real_ip.conf',
    "set_real_ip_from 192.0.2.0/24;\nreal_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n");
$config = (string) file_get_contents(dirname(__DIR__) . '/sgw/gateway/nginx.conf');
$config = str_replace([
    '/run/nginx.pid',
    '/var/log/nginx/error.log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/token-events.log',
    '/etc/nginx/mime.types',
    '/etc/nginx/generated/real_ip.conf',
    '/etc/nginx/generated/rules.conf',
    '/ssl/active/fullchain.pem',
    '/ssl/active/privkey.pem',
    '/etc/ssl/cert.pem',
    '__DNS_RESOLVER__',
    '__GATEWAY_DOMAIN__',
], [
    $directory . '/nginx.pid',
    $directory . '/logs/error.log',
    $directory . '/logs/access.log',
    $directory . '/logs/token-events.log',
    $mime,
    $directory . '/generated/real_ip.conf',
    $directory . '/generated/rules.conf',
    str_replace('\\', '/', realpath($argv[4])),
    str_replace('\\', '/', realpath($argv[5])),
    str_replace('\\', '/', realpath($argv[4])),
    '127.0.0.1',
    'test.example.test',
], $config);
file_put_contents($directory . '/nginx.conf', $config);
// The Admin TLS configuration is checked separately with the same temporary certificate.
$admin = (string) file_get_contents(dirname(__DIR__) . '/sgw/admin/nginx.conf');
$admin = str_replace([
    '/ssl/active/fullchain.pem',
    '/ssl/active/privkey.pem',
    'include fastcgi_params;',
], [
    str_replace('\\', '/', realpath($argv[4])),
    str_replace('\\', '/', realpath($argv[5])),
    'include ' . str_replace('\\', '/', realpath(dirname($argv[2]) . '/fastcgi_params')) . ';',
], $admin);
file_put_contents($directory . '/admin.conf', "events {}\nhttp {\n" . $admin . "\n}\n");
echo $directory . '/nginx.conf', PHP_EOL;
