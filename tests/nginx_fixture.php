<?php

declare(strict_types=1);

require dirname(__DIR__) . '/sgw/admin/src/compiler.php';

if ($argc !== 4 || !is_file($argv[2]) || !in_array($argv[3], ['active', 'zero-burst', 'fail-closed'], true)) {
    fwrite(STDERR, "Usage: php nginx_fixture.php <temporary-directory> <mime.types> <active|zero-burst|fail-closed>\n");
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
map "" $token_valid { default 0; }
map "" $policy_block { default 0; }
map "" $policy_reason { default FAIL_CLOSED; }
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
    '/etc/nginx/mime.types',
    '/etc/nginx/generated/real_ip.conf',
    '/etc/nginx/generated/rules.conf',
    '__DNS_RESOLVER__',
], [
    $directory . '/nginx.pid',
    $directory . '/logs/error.log',
    $directory . '/logs/access.log',
    $mime,
    $directory . '/generated/real_ip.conf',
    $directory . '/generated/rules.conf',
    '127.0.0.1',
], $config);
file_put_contents($directory . '/nginx.conf', $config);
echo $directory . '/nginx.conf', PHP_EOL;
