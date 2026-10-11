<?php
declare(strict_types=1);

const CLOUDFLARE_AAD = 'subscription-gateway:cloudflare-token:v1';

function domain_fqdn(string $value): string
{
    $value = strtolower(trim($value));
    if (strlen($value) > 253 || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/D', $value)
        || filter_var($value, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException('域名必须为合法的 DNS FQDN，不可包含协议、端口或路径');
    }
    return $value;
}

function cloudflare_encrypt(string $secret): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    return 'v1:' . base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $secret, CLOUDFLARE_AAD, $nonce, app_config()['token_encryption_key']));
}

function cloudflare_decrypt(string $encrypted): string
{
    $payload = str_starts_with($encrypted, 'v1:') ? base64_decode(substr($encrypted, 3), true) : false;
    $n = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    if ($payload === false || strlen($payload) <= $n) throw new RuntimeException('凭据解密失败');
    $secret = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($payload, $n), CLOUDFLARE_AAD,
        substr($payload, 0, $n), app_config()['token_encryption_key']);
    if ($secret === false) throw new RuntimeException('凭据解密失败');
    return $secret;
}

function cloudflare_zone_id(string $id): string
{
    $id = strtolower(trim($id));
    if (!preg_match('/^[0-9a-f]{32}$/D', $id)) throw new InvalidArgumentException('Zone ID 必须为 32 位十六进制');
    return $id;
}

/** No shell/curl argv, response bodies or headers are logged. Test endpoints require an explicit opt-in. */
function cloudflare_request(string $token, string $method, string $path, ?array $body = null): array
{
    $base = 'https://api.cloudflare.com/client/v4';
    if (getenv('SGW_CERT_TEST_MODE') === '1') $base = rtrim((string) (getenv('SGW_CF_TEST_URL') ?: $base), '/');
    $curl = curl_init($base . '/' . $path);
    $response = '';
    curl_setopt_array($curl, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token, 'Content-Type: application/json'],
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response): int {
            if (strlen($response) + strlen($chunk) > 1048576) return 0;
            $response .= $chunk; return strlen($chunk);
        }]);
    if ($body !== null) curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
    $ok = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    $data = json_decode($response, true);
    if ($ok === false || $code < 200 || $code >= 300 || !is_array($data) || ($data['success'] ?? false) !== true) {
        throw new RuntimeException(in_array($code, [401,403], true) ? 'Cloudflare 认证失败，请检查 Token 权限' : 'Cloudflare 请求失败，请检查凭据和 Zone');
    }
    return $data;
}

function cloudflare_zone(string $token, string $zoneId, ?callable $client = null): string
{
    if (!preg_match('/^[A-Za-z0-9_-]{8,512}$/D', $token)) throw new InvalidArgumentException('Cloudflare Token 格式不正确');
    $zoneId = cloudflare_zone_id($zoneId);
    $data = ($client ?? 'cloudflare_request')($token, 'GET', 'zones/' . $zoneId);
    if (($data['result']['id'] ?? null) !== $zoneId || !is_string($data['result']['name'] ?? null)) throw new RuntimeException('Cloudflare Zone 验证失败');
    return domain_fqdn($data['result']['name']);
}

function domain_in_zone(string $fqdn, string $zone): bool
{
    return $fqdn === $zone || str_ends_with($fqdn, '.' . $zone);
}

function cloudflare_profile(PDO $pdo, int $id): array
{
    $q = $pdo->prepare('SELECT * FROM cloudflare_credentials WHERE id=?'); $q->execute([$id]);
    $row = $q->fetch(); if (!$row) throw new InvalidArgumentException('Cloudflare 凭据不存在');
    return $row;
}

function cloudflare_profiles(PDO $pdo): array
{
    $rows = $pdo->query('SELECT id,name,token_last4,zone_id,zone_name,created_at,updated_at,last_tested_at,last_test_ok,last_error FROM cloudflare_credentials ORDER BY id')->fetchAll();
    foreach ($rows as &$row) $row['token_configured'] = true;
    return $rows;
}

function cloudflare_save_profile(PDO $pdo, array $body, ?int $id = null, ?callable $client = null): int
{
    $old = $id === null ? null : cloudflare_profile($pdo, $id);
    $token = trim((string) ($body['token'] ?? ''));
    if ($token === '' && $old !== null) $token = cloudflare_decrypt($old['token_encrypted']);
    $zoneId = cloudflare_zone_id((string) ($body['zone_id'] ?? $old['zone_id'] ?? ''));
    $zone = cloudflare_zone($token, $zoneId, $client);
    $name = trim((string) ($body['name'] ?? $old['name'] ?? ''));
    if ($name === '') $name = 'Cloudflare ' . $zone;
    if (strlen($name) > 160 || preg_match('/[\x00-\x1f\x7f]/', $name)) throw new InvalidArgumentException('凭据名称不正确');
    return write_transaction($pdo, static function () use ($pdo, $id, $token, $zoneId, $zone, $name): int {
        if ($id !== null) {
            $q = $pdo->prepare("SELECT fqdn FROM gateway_domains WHERE role='ALIAS' AND credential_id=?"); $q->execute([$id]);
            foreach ($q->fetchAll(PDO::FETCH_COLUMN) as $fqdn) if (!domain_in_zone($fqdn, $zone)) throw new InvalidArgumentException('新 Zone 不覆盖正在使用该凭据的入口域名');
            $q = $pdo->prepare('UPDATE cloudflare_credentials SET name=?,token_encrypted=?,token_last4=?,zone_id=?,zone_name=?,updated_at=?,last_tested_at=?,last_test_ok=1,last_error=NULL WHERE id=?');
            $q->execute([$name,cloudflare_encrypt($token),substr($token,-4),$zoneId,$zone,time(),time(),$id]);
            return $id;
        }
        // Inline additions may reuse a profile, but never compare encrypted randomized payloads.
        $q = $pdo->prepare('SELECT * FROM cloudflare_credentials WHERE zone_id=?'); $q->execute([$zoneId]);
        foreach ($q->fetchAll() as $row) if (hash_equals(cloudflare_decrypt($row['token_encrypted']),$token)) return (int)$row['id'];
        $q = $pdo->prepare('INSERT INTO cloudflare_credentials(name,token_encrypted,token_last4,zone_id,zone_name,created_at,updated_at,last_tested_at,last_test_ok) VALUES (?,?,?,?,?,?,?,?,1)');
        $q->execute([$name,cloudflare_encrypt($token),substr($token,-4),$zoneId,$zone,time(),time(),time()]);
        return (int)$pdo->lastInsertId();
    });
}

function cloudflare_test_profile(PDO $pdo, int $id, ?callable $client = null): array
{
    $profile = cloudflare_profile($pdo,$id);
    try {
        $zone = cloudflare_zone(cloudflare_decrypt($profile['token_encrypted']),$profile['zone_id'],$client);
        if ($zone !== $profile['zone_name']) throw new RuntimeException('Zone 不匹配');
        $ok = true; $error = null;
    } catch (Throwable) { $ok = false; $error = 'Cloudflare 凭据测试失败，请检查 Token 和 Zone'; }
    $q = $pdo->prepare('UPDATE cloudflare_credentials SET last_tested_at=?,last_test_ok=?,last_error=? WHERE id=?');
    $q->execute([time(),(int)$ok,$error,$id]);
    return ['tested'=>$ok,'zone_name'=>$profile['zone_name'],'error'=>$error];
}

function cloudflare_delete_profile(PDO $pdo, int $id): void
{
    write_transaction($pdo, static function () use ($pdo,$id): void {
        cloudflare_profile($pdo,$id);
        $q=$pdo->prepare("SELECT COUNT(*) FROM gateway_domains WHERE role='ALIAS' AND credential_id=?"); $q->execute([$id]); $n=(int)$q->fetchColumn();
        if($n) throw new InvalidArgumentException("仍有 {$n} 个入口域名使用该凭据，请先迁移或删除对应域名");
        $pdo->prepare('DELETE FROM cloudflare_credentials WHERE id=?')->execute([$id]);
    });
}
