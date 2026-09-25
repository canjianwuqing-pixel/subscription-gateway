<?php

declare(strict_types=1);

require_once __DIR__ . '/worker.php';

function time_window(string $value): int
{
    return match ($value) {
        '1h' => 3600,
        '24h' => 86400,
        '7d' => 604800,
        '30d' => 2592000,
        default => throw new InvalidArgumentException('Invalid time window'),
    };
}

function overview_data(PDO $pdo): array
{
    $today = strtotime('today');
    $query = $pdo->prepare(<<<'SQL'
SELECT COUNT(*) AS requests, COUNT(DISTINCT token_id) AS tokens,
       COUNT(DISTINCT client_ip) AS ips,
       SUM(CASE WHEN status_code = 403 THEN 1 ELSE 0 END) AS blocked,
       SUM(CASE WHEN status_code = 429 THEN 1 ELSE 0 END) AS rate_limited
FROM access_logs WHERE created_at >= :today
SQL);
    $query->execute([':today' => $today]);
    $counts = $query->fetch();
    $certificate = (string) (getenv('ACTIVE_CERT_PATH') ?: '/ssl/active/fullchain.pem');
    $expires = null;
    if (is_file($certificate)) {
        $parsed = openssl_x509_parse((string) file_get_contents($certificate));
        $expires = is_array($parsed) ? ($parsed['validTo_time_t'] ?? null) : null;
    }
    $database = (string) app_config()['database_path'];
    return [
        'gateway_domain' => getenv('GATEWAY_DOMAIN') ?: null,
        'upstream_url' => setting_get($pdo, 'upstream_url', ''),
        'publish' => gateway_publish_status($pdo),
        'today' => array_map('intval', $counts ?: []),
        'database_bytes' => is_file($database) ? filesize($database) : 0,
        'certificate_expires_at' => $expires,
        'admin_port' => getenv('ADMIN_PORT') ?: null,
        'trusted_proxy_ips' => getenv('TRUSTED_PROXY_IPS') ?: '',
    ];
}

function token_analysis_rows(PDO $pdo, int $limit = 50): array
{
    $limit = max(1, min(100, $limit));
    $now = time();
    $query = $pdo->prepare(<<<'SQL'
WITH recent AS (
    SELECT id, token_encrypted, state, expires_at, first_seen, last_seen, request_count
    FROM tokens ORDER BY COALESCE(last_seen, created_at) DESC LIMIT :limit
)
SELECT t.*,
    COUNT(CASE WHEN l.created_at >= :m1 THEN 1 END) AS requests_1m,
    COUNT(CASE WHEN l.created_at >= :m5 THEN 1 END) AS requests_5m,
    COUNT(CASE WHEN l.created_at >= :h1 THEN 1 END) AS requests_1h,
    COUNT(CASE WHEN l.created_at >= :h24 THEN 1 END) AS requests_24h,
    COUNT(DISTINCT CASE WHEN l.created_at >= :h24 THEN l.client_ip END) AS ips_24h,
    COUNT(DISTINCT CASE WHEN l.created_at >= :h24 THEN l.user_agent END) AS uas_24h,
    COUNT(CASE WHEN l.created_at >= :h24 AND l.status_code >= 400 THEN 1 END) AS errors_24h,
    (SELECT x.client_ip FROM access_logs x WHERE x.token_id = t.id ORDER BY x.created_at DESC, x.id DESC LIMIT 1) AS last_ip,
    (SELECT x.user_agent FROM access_logs x WHERE x.token_id = t.id ORDER BY x.created_at DESC, x.id DESC LIMIT 1) AS last_ua
FROM recent t LEFT JOIN access_logs l ON l.token_id = t.id AND l.created_at >= :h24
GROUP BY t.id ORDER BY t.last_seen DESC
SQL);
    foreach ([':limit' => $limit, ':m1' => $now - 60, ':m5' => $now - 300,
        ':h1' => $now - 3600, ':h24' => $now - 86400] as $key => $value) {
        $query->bindValue($key, $value, PDO::PARAM_INT);
    }
    $query->execute();
    $rows = $query->fetchAll();
    foreach ($rows as &$row) {
        $plain = decrypt_token((string) $row['token_encrypted']);
        $row['token_hint'] = substr($plain, 0, 6) . '…' . substr($plain, -4);
        unset($row['token_encrypted']);
        $labels = [];
        if ((int) $row['ips_24h'] >= 5) $labels[] = '多IP';
        if ((int) $row['uas_24h'] >= 3) $labels[] = '多UA';
        if ((int) $row['requests_1m'] >= 20) $labels[] = '高频';
        if ((int) $row['requests_24h'] > 0
            && (int) $row['errors_24h'] * 5 >= (int) $row['requests_24h']) $labels[] = '错误率高';
        $row['labels'] = $labels;
        $row['health'] = max(0, 100 - 20 * count($labels));
        if ($row['state'] === 'TEMP_BLOCKED' && (int) $row['expires_at'] <= $now) {
            $row['state'] = 'NORMAL';
        }
    }
    unset($row);
    return $rows;
}

function token_detail_data(PDO $pdo, int $id, string $window): ?array
{
    $query = $pdo->prepare('SELECT id, state, expires_at, first_seen, last_seen, request_count FROM tokens WHERE id = :id');
    $query->execute([':id' => $id]);
    $token = $query->fetch();
    if (!is_array($token)) return null;
    $since = time() - time_window($window);
    $logs = $pdo->prepare('SELECT id, client_ip, user_agent, status_code, request_path, decision, created_at '
        . 'FROM access_logs WHERE token_id = :id AND created_at >= :since ORDER BY created_at DESC, id DESC LIMIT 100');
    $logs->execute([':id' => $id, ':since' => $since]);
    $groups = [];
    foreach (['ip' => 'client_ip', 'ua' => 'user_agent'] as $name => $column) {
        $statement = $pdo->prepare("SELECT {$column} AS value, COUNT(*) AS count FROM access_logs "
            . "WHERE token_id = :id AND created_at >= :since GROUP BY {$column} ORDER BY count DESC LIMIT 50");
        $statement->execute([':id' => $id, ':since' => $since]);
        $groups[$name] = $statement->fetchAll();
    }
    return ['token' => $token, 'logs' => $logs->fetchAll(), 'groups' => $groups];
}

function access_log_page(PDO $pdo, array $filters): array
{
    $window = time_window((string) ($filters['window'] ?? '24h'));
    $page = min(10000, max(1, (int) ($filters['page'] ?? 1)));
    $where = ['l.created_at >= :since'];
    $params = [':since' => time() - $window];
    foreach (['ip' => 'l.client_ip', 'ua' => 'l.user_agent', 'decision' => 'l.decision'] as $input => $column) {
        if (isset($filters[$input]) && $filters[$input] !== '') {
            $value = (string) $filters[$input];
            if (strlen($value) > 256) throw new InvalidArgumentException('Filter is too long');
            $where[] = "{$column} = :{$input}";
            $params[':' . $input] = $value;
        }
    }
    if (isset($filters['status']) && $filters['status'] !== '') {
        $status = (int) $filters['status'];
        if ($status < 100 || $status > 599) throw new InvalidArgumentException('Invalid status filter');
        $where[] = 'l.status_code = :status';
        $params[':status'] = $status;
    }
    if (isset($filters['token_id']) && $filters['token_id'] !== '') {
        $where[] = 'l.token_id = :token_id';
        $params[':token_id'] = (int) $filters['token_id'];
    }
    $sql = 'SELECT l.id, l.token_id, l.client_ip, l.user_agent, l.request_path, '
        . 'l.status_code, l.decision, l.created_at FROM access_logs l WHERE '
        . implode(' AND ', $where) . ' ORDER BY l.created_at DESC, l.id DESC LIMIT 50 OFFSET :offset';
    $statement = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $statement->bindValue($key, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
    }
    $statement->bindValue(':offset', ($page - 1) * 50, PDO::PARAM_INT);
    $statement->execute();
    return ['page' => $page, 'rows' => $statement->fetchAll()];
}
