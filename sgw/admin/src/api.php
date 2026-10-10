<?php

declare(strict_types=1);

require_once __DIR__ . '/publish.php';
require_once __DIR__ . '/analytics.php';

const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_SECONDS = 600;

final class HttpError extends RuntimeException
{
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}

function session_cookie_options(): array
{
    $config = app_config();
    return [
        'lifetime' => 0,
        'path' => '/' . $config['admin_secret_path'] . '/',
        'secure' => (bool) $config['session_cookie_secure'],
        'httponly' => true,
        'samesite' => 'Strict',
    ];
}

function start_admin_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $config = app_config();
    session_name((string) $config['session_name']);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    session_set_cookie_params(session_cookie_options());
    if (!session_start()) {
        throw new RuntimeException('Unable to start administrator session');
    }
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(string $provided): bool
{
    $expected = $_SESSION['csrf_token'] ?? '';
    return is_string($expected) && $expected !== '' && hash_equals($expected, $provided);
}

function require_csrf(): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? '');
    if (!is_string($provided) || !verify_csrf_token($provided)) {
        throw new HttpError(403, 'CSRF validation failed');
    }
    validate_origin_and_host();
}

function validate_origin_and_host(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return;
    }
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    $hostParts = parse_url('http://' . $host);
    $originParts = parse_url($origin);
    $scheme = is_array($originParts) ? strtolower((string) ($originParts['scheme'] ?? '')) : '';
    $originHost = parse_url($origin, PHP_URL_HOST);
    if (!is_array($hostParts) || !is_array($originParts) || !is_string($originHost)
        || !in_array($scheme, ['http', 'https'], true)
        || !isset($hostParts['host']) || isset($hostParts['user']) || isset($hostParts['pass'])
        || isset($hostParts['path']) || isset($hostParts['query']) || isset($hostParts['fragment'])
        || isset($originParts['user']) || isset($originParts['pass'])
        || isset($originParts['path']) || isset($originParts['query']) || isset($originParts['fragment'])
    ) {
        throw new HttpError(403, 'Origin validation failed');
    }
    $defaultPort = $scheme === 'https' ? 443 : 80;
    $hostPort = (int) ($hostParts['port'] ?? $defaultPort);
    $originPort = (int) ($originParts['port'] ?? $defaultPort);
    if ($hostPort !== $originPort
        || !hash_equals(strtolower((string) $hostParts['host']), strtolower($originHost))
    ) {
        throw new HttpError(403, 'Origin validation failed');
    }
}

function is_authenticated(): bool
{
    if (!(isset($_SESSION['admin_id'], $_SESSION['admin_username'], $_SESSION['auth_version'])
        && is_int($_SESSION['admin_id'])
        && $_SESSION['admin_id'] > 0
        && is_string($_SESSION['admin_username'])
        && is_int($_SESSION['auth_version']))) {
        return false;
    }
    $statement = open_database((string) app_config()['database_path'])
        ->prepare('SELECT auth_version FROM admins WHERE id = :id');
    $statement->execute([':id' => $_SESSION['admin_id']]);
    return (int) $statement->fetchColumn() === $_SESSION['auth_version'];
}

function require_authentication(): void
{
    if (!is_authenticated()) {
        throw new HttpError(401, 'Authentication required');
    }
}

function complete_login_session(array $admin): void
{
    if (!session_regenerate_id(true)) {
        throw new RuntimeException('Unable to rotate session identifier');
    }
    $_SESSION = [
        'admin_id' => (int) $admin['id'],
        'admin_username' => (string) $admin['username'],
        'auth_version' => (int) ($admin['auth_version'] ?? 1),
        'csrf_token' => bin2hex(random_bytes(32)),
        'logged_in_at' => time(),
    ];
}

function destroy_admin_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $options = session_cookie_options();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $options['path'],
            'secure' => $options['secure'],
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

function login_rate_directory(): string
{
    $directory = (string) app_config()['login_rate_dir'];
    if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create login rate limit directory');
    }
    if (is_link($directory) || !is_writable($directory)) {
        throw new RuntimeException('Login rate limit directory is unsafe');
    }
    if (PHP_OS_FAMILY !== 'Windows' && ((int) fileperms($directory) & 0027) !== 0) {
        throw new RuntimeException('Login rate limit directory permissions are too broad');
    }
    return rtrim($directory, '/\\');
}

function login_rate_file(string $clientIp): string
{
    return login_rate_directory() . DIRECTORY_SEPARATOR . hash('sha256', $clientIp) . '.rate';
}

/** @return list<int> */
function read_login_attempts_from_handle($handle): array
{
    rewind($handle);
    $raw = stream_get_contents($handle);
    $attempts = $raw === false || $raw === '' ? [] : json_decode($raw, true);
    if (!is_array($attempts)) {
        return [];
    }
    $cutoff = time() - LOGIN_WINDOW_SECONDS;
    return array_values(array_filter(
        $attempts,
        static fn ($value): bool => is_int($value) && $value > $cutoff
    ));
}

function write_login_attempts_to_handle($handle, array $attempts): void
{
    if (!ftruncate($handle, 0) || rewind($handle) === false
        || fwrite($handle, json_encode($attempts, JSON_THROW_ON_ERROR)) === false
        || !fflush($handle)
    ) {
        throw new RuntimeException('Unable to write login rate limit state');
    }
}

function with_login_rate_lock(string $clientIp, callable $callback): mixed
{
    $directory = login_rate_directory();
    $gate = fopen($directory . DIRECTORY_SEPARATOR . '.cleanup.lock', 'c+');
    if ($gate === false) {
        throw new RuntimeException('Unable to open login rate cleanup lock');
    }
    $handle = false;
    try {
        if (!flock($gate, LOCK_SH)) {
            throw new RuntimeException('Unable to lock login rate cleanup gate');
        }
        $path = login_rate_file($clientIp);
        $handle = fopen($path, 'c+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock login rate limit state');
        }
        if (PHP_OS_FAMILY !== 'Windows' && !chmod($path, 0600)) {
            throw new RuntimeException('Unable to secure login rate limit state');
        }
        flock($gate, LOCK_UN);
        return $callback($handle);
    } finally {
        if (is_resource($handle)) {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        fclose($gate);
    }
}

/** @return array{id:int,username:string}|null */
function authenticate_admin_rate_limited(PDO $pdo, string $clientIp, string $username, string $password): ?array
{
    return with_login_rate_lock($clientIp, static function ($handle) use ($pdo, $username, $password): ?array {
        $attempts = read_login_attempts_from_handle($handle);
        if (count($attempts) >= LOGIN_MAX_FAILURES) {
            throw new HttpError(429, 'Too many login attempts');
        }
        $admin = authenticate_admin($pdo, $username, $password);
        if ($admin === null) {
            $attempts[] = time();
            write_login_attempts_to_handle($handle, $attempts);
            return null;
        }
        write_login_attempts_to_handle($handle, []);
        return $admin;
    });
}

function clear_login_failures(string $clientIp): void
{
    with_login_rate_lock($clientIp, static function ($handle): void {
        write_login_attempts_to_handle($handle, []);
    });
}

function cleanup_login_rate_files(string $directory): int
{
    $gate = fopen($directory . DIRECTORY_SEPARATOR . '.cleanup.lock', 'c+');
    if ($gate === false) {
        throw new RuntimeException('Unable to open login rate cleanup lock');
    }
    $removed = 0;
    try {
        if (!flock($gate, LOCK_EX)) {
            throw new RuntimeException('Unable to lock login rate cleanup gate');
        }
        foreach (glob($directory . DIRECTORY_SEPARATOR . '*.rate') ?: [] as $path) {
            $handle = fopen($path, 'c+');
            if ($handle === false) {
                continue;
            }
            try {
                if (!flock($handle, LOCK_EX)) {
                    continue;
                }
                clearstatcache(true, $path);
                $modified = filemtime($path);
                if ($modified !== false
                    && $modified < time() - LOGIN_WINDOW_SECONDS - 3600
                    && read_login_attempts_from_handle($handle) === []
                ) {
                    if (unlink($path)) {
                        $removed++;
                    }
                }
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
        }
    } finally {
        flock($gate, LOCK_UN);
        fclose($gate);
    }
    return $removed;
}

function maybe_cleanup_login_rate_files(): void
{
    if (random_int(1, 128) !== 1) {
        return;
    }
    try {
        cleanup_login_rate_files(login_rate_directory());
    } catch (Throwable $error) {
        error_log('Login rate cleanup failure: ' . $error::class);
    }
}
function resolve_admin_route(string $requestUri): string
{
    $path = parse_url($requestUri, PHP_URL_PATH);
    if (!is_string($path)) {
        throw new HttpError(404, 'Not found');
    }
    $prefix = '/' . app_config()['admin_secret_path'];
    if ($path !== $prefix && !str_starts_with($path, $prefix . '/')) {
        throw new HttpError(404, 'Not found');
    }
    $route = substr($path, strlen($prefix));
    return $route === '' ? '/' : $route;
}

/** @return array<string, mixed> */
function json_request_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 65536) {
        throw new HttpError(400, 'Invalid request body');
    }
    return decode_json_object($raw);
}

/** @return array<string, mixed> */
function decode_json_object(string $raw): array
{
    try {
        $body = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new HttpError(400, 'Invalid JSON');
    }
    if (!$body instanceof stdClass) {
        throw new HttpError(400, 'JSON object required');
    }
    return (array) $body;
}

/** @param array<string, mixed> $body */
function validate_rate_request_body(array $body): array
{
    foreach (['rate_enabled', 'rate_per_minute', 'rate_burst'] as $field) {
        if (!array_key_exists($field, $body)) {
            throw new InvalidArgumentException("Missing {$field}");
        }
    }
    return validate_rate_settings($body['rate_enabled'], $body['rate_per_minute'], $body['rate_burst']);
}

/** @param array<string, mixed> $payload */
function send_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function send_saved_publish_result(array $payload, array $publish): never
{
    send_json($payload + ['saved' => true, 'publish' => $publish], $publish['applied'] === true ? 200 : 202);
}

function handle_api(string $route, string $method): never
{
    try {
        $pdo = app_db();

        if ($route === '/api/session' && $method === 'GET') {
            send_json([
                'ok' => true,
                'authenticated' => is_authenticated(),
                'username' => is_authenticated() ? $_SESSION['admin_username'] : null,
                'csrf_token' => csrf_token(),
            ]);
        }

        if ($route === '/api/login' && $method === 'POST') {
            require_csrf();
            $clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            maybe_cleanup_login_rate_files();
            $body = json_request_body();
            $admin = authenticate_admin_rate_limited(
                $pdo,
                $clientIp,
                (string) ($body['username'] ?? ''),
                (string) ($body['password'] ?? '')
            );
            if ($admin === null) {
                throw new HttpError(401, 'Invalid username or password');
            }
            complete_login_session($admin);
            send_json(['ok' => true, 'csrf_token' => csrf_token()]);
        }

        if ($route === '/api/logout' && $method === 'POST') {
            require_authentication();
            require_csrf();
            destroy_admin_session();
            send_json(['ok' => true]);
        }

        require_authentication();

        if ($route === '/api/overview' && $method === 'GET') {
            send_json(['ok' => true, 'overview' => overview_data($pdo)]);
        }
        if ($route === '/api/analysis/tokens' && $method === 'GET') {
            $groupId = isset($_GET['group_id']) && $_GET['group_id'] !== '' ? (int) $_GET['group_id'] : null;
            send_json(['ok' => true, 'rows' => token_analysis_rows(
                $pdo,
                (int) ($_GET['limit'] ?? 50),
                $groupId
            )]);
        }
        if ($route === '/api/logs' && $method === 'GET') {
            send_json(['ok' => true, 'result' => access_log_page($pdo, $_GET)]);
        }
        if (preg_match('#^/api/tokens/(\d+)/full$#D', $route, $match) && $method === 'GET') {
            $statement = $pdo->prepare('SELECT token_encrypted FROM tokens WHERE id = :id');
            $statement->execute([':id' => (int) $match[1]]);
            $encrypted = $statement->fetchColumn();
            if (!is_string($encrypted)) throw new HttpError(404, 'Token not found');
            send_json(['ok' => true, 'token' => decrypt_token($encrypted)]);
        }
        if (preg_match('#^/api/tokens/(\d+)/detail$#D', $route, $match) && $method === 'GET') {
            $detail = token_detail_data($pdo, (int) $match[1], (string) ($_GET['window'] ?? '24h'));
            if ($detail === null) throw new HttpError(404, 'Token not found');
            send_json(['ok' => true, 'detail' => $detail]);
        }
        if (preg_match('#^/api/tokens/(\d+)/state$#D', $route, $match) && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            $state = (string) ($body['state'] ?? '');
            $expiresAt = isset($body['expires_at']) ? (int) $body['expires_at'] : null;
            write_transaction($pdo, static function () use ($pdo, $match, $state, $expiresAt): void {
                $lookup = $pdo->prepare('SELECT token_encrypted, note FROM tokens WHERE id = :id');
                $lookup->execute([':id' => (int) $match[1]]);
                $row = $lookup->fetch();
                if (!is_array($row)) throw new HttpError(404, 'Token not found');
                save_token($pdo, decrypt_token((string) $row['token_encrypted']), $state,
                    $expiresAt, (string) $row['note']);
                bump_config_version($pdo);
            });
            send_saved_publish_result(['ok' => true], publish_current_rules($pdo));
        }

        if ($route === '/api/tokens' && $method === 'GET') {
            $groupId = isset($_GET['group_id']) && $_GET['group_id'] !== '' ? (int) $_GET['group_id'] : null;
            send_json(['ok' => true, 'tokens' => token_analysis_rows($pdo, 50, $groupId)]);
        }
        if ($route === '/api/tokens' && $method === 'POST') {
            require_csrf();
            $body = json_request_body();
            $expiresAt = isset($body['expires_at']) ? (int) $body['expires_at'] : null;
            $id = write_transaction($pdo, static function () use ($pdo, $body, $expiresAt): int {
                $id = save_token(
                    $pdo,
                    (string) ($body['token'] ?? ''),
                    (string) ($body['state'] ?? 'NORMAL'),
                    $expiresAt,
                    (string) ($body['note'] ?? '')
                );
                bump_config_version($pdo);
                return $id;
            });
            send_saved_publish_result(['ok' => true, 'id' => $id], publish_current_rules($pdo));
        }

        if ($route === '/api/ip-rules' && $method === 'GET') {
            send_json(['ok' => true, 'rules' => list_ip_rules($pdo)]);
        }
        if ($route === '/api/ip-rules' && $method === 'POST') {
            require_csrf();
            $body = json_request_body();
            $id = write_transaction($pdo, static function () use ($pdo, $body): int {
                $id = add_ip_rule(
                    $pdo,
                    (string) ($body['network'] ?? ''),
                    (string) ($body['action'] ?? ''),
                    (string) ($body['note'] ?? '')
                );
                bump_config_version($pdo);
                return $id;
            });
            send_saved_publish_result(['ok' => true, 'id' => $id], publish_current_rules($pdo));
        }
        if (preg_match('#^/api/ip-rules/(\d+)$#D', $route, $match) && $method === 'DELETE') {
            require_csrf();
            write_transaction($pdo, static function () use ($pdo, $match): void {
                delete_rule_by_id($pdo, 'ip_rules', (int) $match[1]);
                bump_config_version($pdo);
            });
            send_saved_publish_result(['ok' => true], publish_current_rules($pdo));
        }

        if ($route === '/api/ua-rules' && $method === 'GET') {
            send_json(['ok' => true, 'rules' => list_ua_rules($pdo)]);
        }
        if ($route === '/api/ua-rules' && $method === 'POST') {
            require_csrf();
            $body = json_request_body();
            $id = write_transaction($pdo, static function () use ($pdo, $body): int {
                $id = add_ua_rule(
                    $pdo,
                    (string) ($body['pattern'] ?? ''),
                    (string) ($body['action'] ?? ''),
                    (string) ($body['note'] ?? '')
                );
                bump_config_version($pdo);
                return $id;
            });
            send_saved_publish_result(['ok' => true, 'id' => $id], publish_current_rules($pdo));
        }
        if (preg_match('#^/api/ua-rules/(\d+)$#D', $route, $match) && $method === 'DELETE') {
            require_csrf();
            write_transaction($pdo, static function () use ($pdo, $match): void {
                delete_rule_by_id($pdo, 'ua_rules', (int) $match[1]);
                bump_config_version($pdo);
            });
            send_saved_publish_result(['ok' => true], publish_current_rules($pdo));
        }

        if ($route === '/api/settings' && $method === 'GET') {
            send_json([
                'ok' => true,
                'settings' => [
                    'rate_enabled' => setting_get($pdo, 'rate_enabled', '1') === '1',
                    'rate_per_minute' => (int) setting_get($pdo, 'rate_per_minute', '20'),
                    'rate_burst' => (int) setting_get($pdo, 'rate_burst', '5'),
                    'log_retention_days' => (int) setting_get($pdo, 'log_retention_days', '30'),
                    'config_version' => (int) setting_get($pdo, 'config_version', '0'),
                ],
            ]);
        }
        if ($route === '/api/settings/rate' && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            [$enabled, $rate, $burst] = validate_rate_request_body($body);
            save_rate_settings($pdo, $enabled, $rate, $burst);
            send_saved_publish_result(['ok' => true], publish_current_rules($pdo));
        }
        if ($route === '/api/settings/retention' && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            $days = $body['log_retention_days'] ?? null;
            if (!is_int($days) || $days < 1 || $days > 3650) {
                throw new InvalidArgumentException('log_retention_days must be 1-3650');
            }
            setting_set($pdo, 'log_retention_days', (string) $days);
            send_json(['ok' => true]);
        }

        if ($route === '/api/settings/gateway' && $method === 'GET') {
            send_json([
                'ok' => true,
                'settings' => [
                    'upstream_url' => setting_get($pdo, 'upstream_url', ''),
                    'subscribe_path_template' => setting_get($pdo, 'subscribe_path_template'),
                    'token_query_key' => setting_get($pdo, 'token_query_key'),
                    'token_format_profile' => setting_get($pdo, 'token_format_profile'),
                ],
                'publish' => gateway_publish_status($pdo),
            ]);
        }
        if ($route === '/api/settings/gateway' && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            $settings = validate_gateway_settings([
                'upstream_url' => $body['upstream_url'] ?? null,
                'subscribe_path_template' => $body['subscribe_path_template'] ?? null,
                'token_query_key' => $body['token_query_key'] ?? null,
                'token_format_profile' => $body['token_format_profile'] ?? null,
                'tracking_mode' => setting_get($pdo, 'tracking_mode', 'off'),
                'rate_enabled' => setting_get($pdo, 'rate_enabled'),
                'rate_per_minute' => setting_get($pdo, 'rate_per_minute'),
                'rate_burst' => setting_get($pdo, 'rate_burst'),
            ]);
            write_transaction($pdo, static function () use ($pdo, $settings): void {
                foreach (['upstream_url', 'subscribe_path_template', 'token_query_key', 'token_format_profile'] as $key) {
                    setting_set($pdo, $key, $settings[$key]);
                }
                bump_config_version($pdo);
            });
            send_saved_publish_result(['ok' => true], publish_current_rules($pdo));
        }
        if ($route === '/api/tracking' && $method === 'GET') {
            send_json(['ok' => true, 'tracking' => [
                'mode' => tracking_mode($pdo),
                'groups' => tracking_list_groups($pdo),
                'stats_24h' => tracking_transform_stats($pdo),
            ]]);
        }
        if ($route === '/api/tracking/mode' && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            tracking_set_mode($pdo, (string) ($body['mode'] ?? ''));
            send_saved_publish_result(['ok' => true, 'mode' => tracking_mode($pdo)], publish_current_rules($pdo));
        }
        if (preg_match('#^/api/tracking/groups/(\d+)/mappings$#D', $route, $match) && $method === 'PUT') {
            require_csrf();
            $body = json_request_body();
            $mappings = $body['mappings'] ?? null;
            if (!is_array($mappings) || !array_is_list($mappings)) {
                throw new InvalidArgumentException('mappings must be a JSON array');
            }
            tracking_save_group_mappings($pdo, (int) $match[1], $mappings);
            send_json(['ok' => true, 'mappings' => tracking_group_mappings($pdo, (int) $match[1])]);
        }
        if (preg_match('#^/api/tracking/groups/(\d+)/split$#D', $route, $match) && $method === 'POST') {
            require_csrf();
            send_json(['ok' => true, 'children' => tracking_create_split($pdo, (int) $match[1])]);
        }
        if (preg_match('#^/api/tracking/groups/(\d+)/validate-split$#D', $route, $match) && $method === 'POST') {
            require_csrf();
            send_json(['ok' => true, 'children' => tracking_validate_split($pdo, (int) $match[1])]);
        }
        if (preg_match('#^/api/tracking/groups/(\d+)/activate-split$#D', $route, $match) && $method === 'POST') {
            require_csrf();
            send_json(['ok' => true, 'moved' => tracking_activate_split($pdo, (int) $match[1])]);
        }
        if ($route === '/api/gateway/status' && $method === 'GET') {
            send_json(['ok' => true, 'publish' => gateway_publish_status($pdo)]);
        }
        if ($route === '/api/gateway/apply' && $method === 'POST') {
            require_csrf();
            send_json(['ok' => true, 'publish' => publish_current_rules($pdo)]);
        }
        if ($route === '/api/admin/password' && $method === 'PATCH') {
            require_csrf();
            $body = json_request_body();
            $version = change_admin_password($pdo, $_SESSION['admin_id'],
                (string) ($body['current_password'] ?? ''), (string) ($body['new_password'] ?? ''));
            $_SESSION['auth_version'] = $version;
            session_regenerate_id(true);
            send_json(['ok' => true]);
        }

        throw new HttpError(404, 'Not found');
    } catch (HttpError $error) {
        send_json(['ok' => false, 'error' => $error->getMessage()], $error->status);
    } catch (DomainException $error) {
        send_json(['ok' => false, 'error' => $error->getMessage()], 409);
    } catch (InvalidArgumentException $error) {
        send_json(['ok' => false, 'error' => $error->getMessage()], 422);
    } catch (Throwable $error) {
        error_log('Admin API failure: ' . $error::class);
        send_json(['ok' => false, 'error' => 'Internal server error'], 500);
    }
}
