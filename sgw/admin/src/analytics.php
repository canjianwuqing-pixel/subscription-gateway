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

function token_analysis_rows(PDO $pdo, int $limit = 50, ?int $trackingGroupId = null): array
{
    return token_analysis_page($pdo, ['limit' => max(1, min(50, $limit)), 'group_id' => $trackingGroupId])['rows'];
}

function analytics_positive_integer(mixed $value, int $maximum, string $error): int
{
    if ((!is_int($value) && !is_string($value)) || !preg_match('/^[1-9][0-9]*$/D', (string) $value)
        || filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => $maximum]]) === false) {
        throw new InvalidArgumentException($error);
    }
    return (int) $value;
}

function token_analysis_page(PDO $pdo, array $filters = []): array
{
    $page = analytics_positive_integer($filters['page'] ?? 1, 10000, 'Invalid page filter');
    $limit = min(50, analytics_positive_integer($filters['limit'] ?? 50, PHP_INT_MAX, 'Invalid limit filter'));
    $trackingGroupId = isset($filters['group_id']) && $filters['group_id'] !== ''
        ? analytics_positive_integer($filters['group_id'], PHP_INT_MAX, 'Invalid tracking group filter') : null;
    $where = [];
    $params = [];
    $token = $filters['token'] ?? '';
    if (!is_string($token)) throw new InvalidArgumentException('Token must be 32 lowercase hexadecimal characters');
    if ($token !== '') {
        validate_token_format($token);
        $where[] = 't.token_hash = :analysis_token_hash';
        $params[':analysis_token_hash'] = token_hash_value($token);
    }
    $ip = $filters['ip'] ?? '';
    if (!is_string($ip) || ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)) {
        throw new InvalidArgumentException('Invalid analysis IP filter');
    }
    if ($ip !== '') {
        $where[] = 'EXISTS (SELECT 1 FROM access_logs match_ip WHERE match_ip.token_id = t.id AND match_ip.client_ip = :analysis_ip)';
        $params[':analysis_ip'] = $ip;
    }
    $ua = $filters['ua'] ?? '';
    if (!is_string($ua) || str_contains($ua, "\0")) throw new InvalidArgumentException('Invalid analysis UA filter');
    if (strlen($ua) > 256) throw new InvalidArgumentException('Analysis search is too long');
    if ($ua !== '') {
        $where[] = "EXISTS (SELECT 1 FROM access_logs match_ua WHERE match_ua.token_id = t.id AND LOWER(match_ua.user_agent) LIKE LOWER(:analysis_ua) ESCAPE '\\')";
        $params[':analysis_ua'] = '%' . strtr($ua, ['\\' => '\\\\', '%' => '\\%', '_' => '\\_']) . '%';
    }
    if ($trackingGroupId !== null) {
        $where[] = 'a.group_id = :tracking_group_id';
        $params[':tracking_group_id'] = $trackingGroupId;
    }
    tracking_backfill_token_assignments($pdo);
    $now = time();
    $groupFilter = $where ? 'WHERE ' . implode(' AND ', $where) : '';
    $query = $pdo->prepare(<<<SQL
WITH recent AS (
    SELECT t.id, t.token_encrypted, t.state, t.expires_at, t.first_seen, t.last_seen, t.request_count,
           a.group_id AS tracking_group_id, g.path AS tracking_group_path,
           COALESCE(t.last_seen, t.created_at) AS sort_seen
    FROM tokens t
    LEFT JOIN tracking_assignments a ON a.token_hash = t.token_hash
    LEFT JOIN tracking_groups g ON g.id = a.group_id
    {$groupFilter}
    ORDER BY COALESCE(t.last_seen, t.created_at) DESC, t.id DESC LIMIT :limit OFFSET :offset
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
GROUP BY t.id ORDER BY t.sort_seen DESC, t.id DESC
SQL);
    foreach ([':limit' => $limit + 1, ':offset' => ($page - 1) * $limit, ':m1' => $now - 60, ':m5' => $now - 300,
        ':h1' => $now - 3600, ':h24' => $now - 86400] as $key => $value) {
        $query->bindValue($key, $value, PDO::PARAM_INT);
    }
    foreach ($params as $key => $value) {
        $query->bindValue($key, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
    }
    $query->execute();
    $rows = $query->fetchAll();
    $hasNext = $page < 10000 && count($rows) > $limit;
    $rows = array_slice($rows, 0, $limit);
    foreach ($rows as &$row) {
        $plain = decrypt_token((string) $row['token_encrypted']);
        $row['token'] = $plain;
        unset($row['token_encrypted'], $row['sort_seen']);
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
    return ['rows' => $rows, 'page' => $page, 'has_next' => $hasNext];
}

function token_detail_data(PDO $pdo, int $id, string $window): ?array
{
    tracking_backfill_token_assignments($pdo);
    $query = $pdo->prepare('SELECT t.id, t.token_encrypted, t.state, t.expires_at, t.first_seen, t.last_seen, t.request_count, '
        . 'a.group_id AS tracking_group_id, g.path AS tracking_group_path FROM tokens t '
        . 'LEFT JOIN tracking_assignments a ON a.token_hash = t.token_hash '
        . 'LEFT JOIN tracking_groups g ON g.id = a.group_id WHERE t.id = :id');
    $query->execute([':id' => $id]);
    $token = $query->fetch();
    if (!is_array($token)) return null;
    $token['token'] = decrypt_token((string) $token['token_encrypted']);
    unset($token['token_encrypted']);
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
    tracking_backfill_token_assignments($pdo);
    $window = time_window((string) ($filters['window'] ?? '24h'));
    $page = min(10000, max(1, (int) ($filters['page'] ?? 1)));
    $where = ['l.created_at >= :since'];
    $params = [':since' => time() - $window];
    if (isset($filters['group_id']) && $filters['group_id'] !== '') {
        $groupId = analytics_positive_integer($filters['group_id'], PHP_INT_MAX, 'Invalid tracking group filter');
        $group = $pdo->prepare('SELECT path FROM tracking_groups WHERE id = :id');
        $group->execute([':id' => $groupId]);
        $path = $group->fetchColumn();
        if (!is_string($path)) throw new InvalidArgumentException('Invalid tracking group filter');
        $where[] = '(g.path = :group_path OR g.path LIKE :group_descendants)';
        $params[':group_path'] = $path;
        $params[':group_descendants'] = $path . '.%';
    }
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
    if (isset($filters['token']) && $filters['token'] !== '') {
        $plain = (string) $filters['token'];
        validate_token_format($plain);
        $where[] = 't.token_hash = :token_hash';
        $params[':token_hash'] = token_hash_value($plain);
    }
    $sql = 'SELECT l.id, l.token_id, l.client_ip, l.user_agent, l.request_path, '
        . 'l.status_code, l.decision, l.created_at, t.token_encrypted, g.path AS tracking_group_path '
        . 'FROM access_logs l LEFT JOIN tokens t ON t.id = l.token_id '
        . 'LEFT JOIN tracking_assignments a ON a.token_hash = t.token_hash '
        . 'LEFT JOIN tracking_groups g ON g.id = a.group_id WHERE '
        . implode(' AND ', $where) . ' ORDER BY l.created_at DESC, l.id DESC LIMIT 50 OFFSET :offset';
    $statement = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $statement->bindValue($key, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
    }
    $statement->bindValue(':offset', ($page - 1) * 50, PDO::PARAM_INT);
    $statement->execute();
    $rows = $statement->fetchAll();
    foreach ($rows as &$row) {
        $row['token'] = is_string($row['token_encrypted']) ? decrypt_token($row['token_encrypted']) : null;
        unset($row['token_encrypted']);
    }
    unset($row);
    return ['page' => $page, 'rows' => $rows];
}
