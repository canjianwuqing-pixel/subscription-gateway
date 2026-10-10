<?php

declare(strict_types=1);

require_once __DIR__ . '/compiler.php';
require_once __DIR__ . '/subscription_transform.php';

const TRANSFORM_MAX_BODY_BYTES = 8 * 1024 * 1024;
const TRANSFORM_HARD_BODY_BYTES = 64 * 1024 * 1024;

/** @return array{status:int,headers:array<string,list<string>>,stream:resource,size:int} */
function transformer_fetch_upstream(PDO $pdo, string $requestUri, string $method): array
{
    if (!extension_loaded('curl')) {
        throw new RuntimeException('PHP cURL extension is unavailable');
    }
    $upstream = validate_upstream_url((string) setting_get($pdo, 'upstream_url', ''));
    $url = $upstream['url'] . $requestUri;
    $stream = fopen('php://temp/maxmemory:2097152', 'w+b');
    if ($stream === false) {
        throw new RuntimeException('Unable to allocate upstream response buffer');
    }
    $headers = [];
    $size = 0;
    $tooLarge = false;
    $curl = curl_init($url);
    if ($curl === false) {
        fclose($stream);
        throw new RuntimeException('Unable to initialize upstream request');
    }
    $userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? 'Subscription-Gateway/1');
    $accept = (string) ($_SERVER['HTTP_ACCEPT'] ?? '*/*');
    $clientIp = (string) ($_SERVER['HTTP_X_SGW_CLIENT_IP'] ?? '');
    if (strlen($userAgent) > 1024 || preg_match('/[\r\n]/', $userAgent)) {
        $userAgent = 'Subscription-Gateway/1';
    }
    if ($accept === '' || strlen($accept) > 1024 || preg_match('/[\r\n]/', $accept)) {
        $accept = '*/*';
    }
    if (filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
        $clientIp = '';
    }
    $forwardHeaders = ['Host: ' . $upstream['host'], 'Accept: ' . $accept, 'Accept-Encoding: identity'];
    if ($clientIp !== '') {
        $forwardHeaders[] = 'X-Real-IP: ' . $clientIp;
        $forwardHeaders[] = 'X-Forwarded-For: ' . $clientIp;
    }
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_NOBODY => $method === 'HEAD',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 25,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_USERAGENT => $userAgent,
        CURLOPT_HTTPHEADER => $forwardHeaders,
        CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$headers): int {
            $length = strlen($line);
            if (preg_match('#^HTTP/\S+\s+[0-9]{3}#', $line)) {
                $headers = [];
                return $length;
            }
            $separator = strpos($line, ':');
            if ($separator !== false) {
                $name = strtolower(trim(substr($line, 0, $separator)));
                $value = trim(substr($line, $separator + 1));
                if ($name !== '' && $value !== '' && !preg_match('/[\x00-\x1F\x7F]/', $value)) {
                    $headers[$name][] = $value;
                }
            }
            return $length;
        },
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use ($stream, &$size, &$tooLarge): int {
            $size += strlen($chunk);
            if ($size > TRANSFORM_HARD_BODY_BYTES) {
                $tooLarge = true;
                return 0;
            }
            $written = fwrite($stream, $chunk);
            return $written === false ? 0 : $written;
        },
    ]);
    $ok = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $errorNumber = curl_errno($curl);
    curl_close($curl);
    if ($ok !== true || $errorNumber !== CURLE_OK) {
        fclose($stream);
        if ($tooLarge) {
            throw new TrackingTransformFailure('RESPONSE_TOO_LARGE', 'UNKNOWN', 'Upstream response exceeds hard limit');
        }
        throw new RuntimeException('Upstream request failed');
    }
    if ($status < 100 || $status > 599) {
        fclose($stream);
        throw new RuntimeException('Upstream returned an invalid status');
    }
    rewind($stream);
    return ['status' => $status, 'headers' => $headers, 'stream' => $stream, 'size' => $size];
}

/** @param array<string,list<string>> $headers */
function transformer_send_headers(array $headers, int $contentLength): void
{
    $allowed = [
        'content-type' => 'Content-Type',
        'content-disposition' => 'Content-Disposition',
        'subscription-userinfo' => 'Subscription-Userinfo',
        'profile-update-interval' => 'Profile-Update-Interval',
        'profile-web-page-url' => 'Profile-Web-Page-Url',
        'www-authenticate' => 'WWW-Authenticate',
        'retry-after' => 'Retry-After',
    ];
    foreach ($allowed as $source => $name) {
        foreach ($headers[$source] ?? [] as $value) {
            header($name . ': ' . $value, false);
        }
    }
    header('Content-Length: ' . $contentLength);
}

/** @param array{status:int,headers:array<string,list<string>>,stream:resource,size:int} $response */
function transformer_emit_upstream(array $response, string $method, ?string $replacement = null): never
{
    http_response_code($response['status']);
    $length = $replacement === null ? $response['size'] : strlen($replacement);
    if ($method === 'HEAD' && $replacement === null) {
        $contentLengths = $response['headers']['content-length'] ?? [];
        if (count($contentLengths) === 1 && preg_match('/^(?:0|[1-9][0-9]*)$/D', $contentLengths[0])) {
            $length = (int) $contentLengths[0];
        }
    }
    transformer_send_headers($response['headers'], $length);
    if ($method !== 'HEAD') {
        if ($replacement !== null) {
            echo $replacement;
        } else {
            rewind($response['stream']);
            fpassthru($response['stream']);
        }
    }
    fclose($response['stream']);
    exit;
}

function transformer_error(int $status): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo 'Subscription transformation unavailable.';
    exit;
}

function transformer_failure_status(string $reason): int
{
    return in_array($reason, ['MAPPING_INCOMPLETE', 'NO_USABLE_NODES', 'INTERNAL_ERROR'], true) ? 503 : 502;
}

function transformer_main(): never
{
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    if (!in_array($method, ['GET', 'HEAD'], true)) {
        transformer_error(405);
    }
    $requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
    if ($requestUri === '' || strlen($requestUri) > 4096 || preg_match('/[\x00-\x20\x7F]/', $requestUri)) {
        transformer_error(400);
    }
    $path = parse_url($requestUri, PHP_URL_PATH);
    if (!is_string($path) || !preg_match('#^/api/v1/[^/]+/subscribe$#D', $path)) {
        transformer_error(404);
    }
    $mode = (string) ($_SERVER['HTTP_X_SGW_TRACKING_MODE'] ?? '');
    if (!in_array($mode, ['preflight', 'enforced'], true)) {
        transformer_error(403);
    }
    $token = (string) ($_SERVER['HTTP_X_SGW_VALIDATED_TOKEN'] ?? '');
    try {
        validate_token_format($token);
    } catch (InvalidArgumentException) {
        transformer_error(403);
    }

    $pdo = null;
    $response = null;
    $groupId = null;
    try {
        $pdo = app_db();
        $response = transformer_fetch_upstream($pdo, $requestUri, $method);
    } catch (TrackingTransformFailure $failure) {
        if ($pdo instanceof PDO) {
            tracking_record_transform_event_safe($pdo, null, $mode, $failure->format, $failure->reason);
        }
        transformer_error(transformer_failure_status($failure->reason));
    } catch (Throwable $error) {
        if ($pdo instanceof PDO) {
            tracking_record_transform_event_safe($pdo, null, $mode, 'UNKNOWN', 'UPSTREAM_ERROR');
        }
        error_log('Transformer upstream failure: ' . $error::class);
        transformer_error(502);
    }

    if ($response['status'] < 200 || $response['status'] >= 300) {
        tracking_record_transform_event_safe($pdo, null, $mode, 'UNKNOWN', 'UPSTREAM_ERROR');
        transformer_emit_upstream($response, $method);
    }
    if ($method === 'HEAD') {
        transformer_emit_upstream($response, $method);
    }

    try {
        $tokenHash = token_hash_value($token);
        $groupId = tracking_assignment_for_hash($pdo, $tokenHash);
    } catch (DomainException $error) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'MAPPING_INCOMPLETE');
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(503);
    } catch (Throwable $error) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'INTERNAL_ERROR');
        error_log('Transformer tracking failure: ' . $error::class);
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(503);
    }

    if ($response['size'] > TRANSFORM_MAX_BODY_BYTES) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'RESPONSE_TOO_LARGE');
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(502);
    }

    $body = stream_get_contents($response['stream']);
    if (!is_string($body) || strlen($body) !== $response['size']) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'INTERNAL_ERROR');
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(503);
    }
    try {
        $transformed = tracking_process_subscription($pdo, $groupId, $body);
        tracking_record_transform_event_safe($pdo, $groupId, $mode, $transformed['format'], $transformed['outcome'], $transformed);
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        transformer_emit_upstream($response, $method, $transformed['content']);
    } catch (DomainException) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'MAPPING_INCOMPLETE');
        if ($mode === 'preflight') transformer_emit_upstream($response, $method);
        fclose($response['stream']);
        transformer_error(503);
    } catch (TrackingTransformFailure $failure) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, $failure->format, $failure->reason, $failure->counts);
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(transformer_failure_status($failure->reason));
    } catch (Throwable $error) {
        tracking_record_transform_event_safe($pdo, $groupId, $mode, 'UNKNOWN', 'INTERNAL_ERROR');
        error_log('Transformer conversion failure: ' . $error::class);
        if ($mode === 'preflight') {
            transformer_emit_upstream($response, $method);
        }
        fclose($response['stream']);
        transformer_error(503);
    }
}

transformer_main();
