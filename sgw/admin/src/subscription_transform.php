<?php

declare(strict_types=1);

require_once __DIR__ . '/tracking.php';

final class TrackingTransformFailure extends RuntimeException
{
    public function __construct(
        public readonly string $reason,
        public readonly string $format = 'UNKNOWN',
        string $message = 'Subscription transformation failed'
    ) {
        parent::__construct($message);
    }
}

/** @return array{decoded:string,urlsafe:bool,padded:bool} */
function tracking_decode_base64(string $encoded, string $format): array
{
    $compact = preg_replace('/\s+/', '', $encoded);
    if (!is_string($compact) || $compact === ''
        || !preg_match('/^[A-Za-z0-9+\/_-]*={0,2}$/D', $compact)
        || str_contains(substr($compact, 0, -2), '=')
    ) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'Invalid Base64 payload');
    }
    $urlsafe = str_contains($compact, '-') || str_contains($compact, '_');
    if ($urlsafe && (str_contains($compact, '+') || str_contains($compact, '/'))) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'Mixed Base64 alphabet');
    }
    $padded = str_ends_with($compact, '=');
    $standard = strtr(rtrim($compact, '='), '-_', '+/');
    if ((strlen($standard) % 4) === 1) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'Invalid Base64 length');
    }
    $standard .= str_repeat('=', (4 - strlen($standard) % 4) % 4);
    $decoded = base64_decode($standard, true);
    if ($decoded === false) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'Invalid Base64 payload');
    }
    return ['decoded' => $decoded, 'urlsafe' => $urlsafe, 'padded' => $padded];
}

/** @param array{urlsafe:bool,padded:bool} $meta */
function tracking_encode_base64(string $content, array $meta): string
{
    $encoded = base64_encode($content);
    if ($meta['urlsafe']) {
        $encoded = strtr($encoded, '+/', '-_');
    }
    return $meta['padded'] ? $encoded : rtrim($encoded, '=');
}

/** @param array<string, string> $mapping */
function tracking_mapped_host(string $host, array $mapping, string $format): string
{
    try {
        $normalized = normalize_tracking_host($host);
    } catch (InvalidArgumentException $error) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, $error->getMessage());
    }
    if (!array_key_exists($normalized, $mapping)) {
        throw new TrackingTransformFailure('MAPPING_INCOMPLETE', $format, 'Entry mapping is incomplete');
    }
    return $mapping[$normalized];
}

function tracking_uri_host_text(string $host): string
{
    return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,source_host:string,target_host:string}
 */
function tracking_transform_authority_uri(string $uri, array $mapping, string $format = 'URI'): array
{
    $schemeEnd = strpos($uri, '://');
    if ($schemeEnd === false || $schemeEnd < 1) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI scheme is invalid');
    }
    $authorityStart = $schemeEnd + 3;
    $authorityLength = strcspn($uri, '/?#', $authorityStart);
    $authority = substr($uri, $authorityStart, $authorityLength);
    if ($authority === '') {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI authority is missing');
    }
    $at = strrpos($authority, '@');
    $hostPortOffset = $at === false ? 0 : $at + 1;
    $hostPort = substr($authority, $hostPortOffset);
    if ($hostPort === '') {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI host is missing');
    }
    if ($hostPort[0] === '[') {
        $closing = strpos($hostPort, ']');
        if ($closing === false) {
            throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI IPv6 host is invalid');
        }
        $host = substr($hostPort, 1, $closing - 1);
        $hostOffset = $authorityStart + $hostPortOffset;
        $hostLength = $closing + 1;
    } else {
        if (substr_count($hostPort, ':') > 1) {
            throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI IPv6 host must be bracketed');
        }
        $colon = strrpos($hostPort, ':');
        $host = $colon === false ? $hostPort : substr($hostPort, 0, $colon);
        if ($host === '') {
            throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI host is missing');
        }
        if ($colon !== false) {
            $port = substr($hostPort, $colon + 1);
            if (!preg_match('/^[0-9]{1,5}$/D', $port) || (int) $port < 1 || (int) $port > 65535) {
                throw new TrackingTransformFailure('PARSE_FAILED', $format, 'URI port is invalid');
            }
        }
        $hostOffset = $authorityStart + $hostPortOffset;
        $hostLength = strlen($host);
    }
    $target = tracking_mapped_host($host, $mapping, $format);
    $replacement = tracking_uri_host_text($target);
    $transformed = substr($uri, 0, $hostOffset) . $replacement . substr($uri, $hostOffset + $hostLength);
    $outsideBefore = substr($uri, 0, $hostOffset) . substr($uri, $hostOffset + $hostLength);
    $outsideAfter = substr($transformed, 0, $hostOffset)
        . substr($transformed, $hostOffset + strlen($replacement));
    if (!hash_equals($outsideBefore, $outsideAfter)) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', $format, 'URI integrity validation failed');
    }
    return ['content' => $transformed, 'source_host' => normalize_tracking_host($host),
        'target_host' => $target];
}

/** @param array<string, string> $mapping */
function tracking_transform_vmess_uri(string $uri, array $mapping): string
{
    $prefix = substr($uri, 0, strlen('vmess://'));
    $payload = substr($uri, strlen($prefix));
    if ($payload === '' || strpbrk($payload, '?#') !== false) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'VMESS', 'VMess payload is invalid');
    }
    $decoded = tracking_decode_base64($payload, 'VMESS');
    try {
        $document = json_decode($decoded['decoded'], true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException $error) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'VMESS', 'VMess JSON is invalid');
    }
    if (!is_array($document) || !is_string($document['add'] ?? null)) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'VMESS', 'VMess server address is missing');
    }
    $original = $document;
    $document['add'] = tracking_mapped_host($document['add'], $mapping, 'VMESS');
    $comparison = $document;
    $comparison['add'] = $original['add'];
    if ($comparison !== $original) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', 'VMESS', 'VMess integrity validation failed');
    }
    try {
        $json = json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (JsonException) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', 'VMESS', 'VMess encoding failed');
    }
    return $prefix . tracking_encode_base64($json, $decoded);
}

/** @param array<string, string> $mapping */
function tracking_transform_ss_uri(string $uri, array $mapping): string
{
    $prefix = substr($uri, 0, strlen('ss://'));
    $payloadStart = strlen($prefix);
    $suffixOffset = strcspn($uri, '?#', $payloadStart) + $payloadStart;
    $authority = substr($uri, $payloadStart, $suffixOffset - $payloadStart);
    if (str_contains($authority, '@')) {
        return tracking_transform_authority_uri($uri, $mapping)['content'];
    }
    $decoded = tracking_decode_base64($authority, 'URI');
    $innerPrefix = 'ss://';
    $inner = tracking_transform_authority_uri($innerPrefix . $decoded['decoded'], $mapping)['content'];
    $encoded = tracking_encode_base64(substr($inner, strlen($prefix)), $decoded);
    return $prefix . $encoded . substr($uri, $suffixOffset);
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,format:string,node_count:int}|null
 */
function tracking_try_transform_uri_list(string $body, array $mapping): ?array
{
    $parts = preg_split('/(\r\n|\n|\r)/', $body, -1, PREG_SPLIT_DELIM_CAPTURE);
    if (!is_array($parts)) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'URI');
    }
    $nodes = 0;
    $vmessNodes = 0;
    foreach ($parts as $index => $part) {
        if ($part === "\r\n" || $part === "\n" || $part === "\r") {
            continue;
        }
        $line = trim($part);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        if (!preg_match('#^(vless|hysteria2|hy2|trojan|ss|tuic|vmess)://#i', $line, $match)) {
            return null;
        }
        $scheme = strtolower($match[1]);
        if ($scheme === 'vmess') {
            $replacement = tracking_transform_vmess_uri($line, $mapping);
            $vmessNodes++;
        } elseif ($scheme === 'ss') {
            $replacement = tracking_transform_ss_uri($line, $mapping);
        } else {
            $replacement = tracking_transform_authority_uri($line, $mapping)['content'];
        }
        $leading = substr($part, 0, strlen($part) - strlen(ltrim($part)));
        $trailing = substr($part, strlen(rtrim($part)));
        $parts[$index] = $leading . $replacement . $trailing;
        $nodes++;
    }
    if ($nodes === 0) {
        return null;
    }
    return ['content' => implode('', $parts), 'format' => $vmessNodes === $nodes ? 'VMESS' : 'URI',
        'node_count' => $nodes];
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,format:string,node_count:int}|null
 */
function tracking_try_transform_yaml(string $body, array $mapping): ?array
{
    if (!preg_match('/(?:^|\r\n|\n|\r)[ \t]*proxies[ \t]*:/', $body)) {
        return null;
    }
    if (!extension_loaded('yaml')) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'YAML extension is unavailable');
    }
    $document = @yaml_parse($body);
    if (!is_array($document) || !isset($document['proxies']) || !is_array($document['proxies'])) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash YAML proxies are invalid');
    }
    $original = $document;
    $nodes = 0;
    foreach ($document['proxies'] as $index => &$proxy) {
        if (!is_array($proxy) || !is_string($proxy['server'] ?? null)) {
            throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash proxy server is invalid');
        }
        $proxy['server'] = tracking_mapped_host($proxy['server'], $mapping, 'YAML');
        $nodes++;
    }
    unset($proxy);
    if ($nodes === 0) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash YAML has no proxies');
    }
    $comparison = $document;
    foreach ($comparison['proxies'] as $index => &$proxy) {
        $proxy['server'] = $original['proxies'][$index]['server'];
    }
    unset($proxy);
    if ($comparison !== $original) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Clash YAML integrity validation failed');
    }
    $encoded = @yaml_emit($document, YAML_UTF8_ENCODING, YAML_LN_BREAK);
    if (!is_string($encoded)) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Clash YAML encoding failed');
    }
    return ['content' => $encoded, 'format' => 'YAML', 'node_count' => $nodes];
}

function tracking_looks_like_base64(string $body): bool
{
    $trimmed = trim($body);
    return strlen($trimmed) >= 8 && preg_match('/^[A-Za-z0-9+\/_=\s-]+$/D', $trimmed) === 1;
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,format:string,node_count:int}
 */
function tracking_transform_subscription_body(string $body, array $mapping, bool $allowOuterBase64 = true): array
{
    if ($mapping === []) {
        throw new TrackingTransformFailure('MAPPING_INCOMPLETE', 'UNKNOWN', 'Entry mapping is empty');
    }
    $yaml = tracking_try_transform_yaml($body, $mapping);
    if ($yaml !== null) {
        return $yaml;
    }
    $uris = tracking_try_transform_uri_list($body, $mapping);
    if ($uris !== null) {
        return $uris;
    }
    if ($allowOuterBase64 && tracking_looks_like_base64($body)) {
        $leadingLength = strlen($body) - strlen(ltrim($body));
        $trailingLength = strlen($body) - strlen(rtrim($body));
        $leading = substr($body, 0, $leadingLength);
        $trailing = $trailingLength > 0 ? substr($body, -$trailingLength) : '';
        $encodedBody = trim($body);
        try {
            $decoded = tracking_decode_base64($encodedBody, 'BASE64');
            if (preg_match('//u', $decoded['decoded']) !== 1) {
                throw new TrackingTransformFailure('PARSE_FAILED', 'BASE64', 'Decoded subscription is not UTF-8');
            }
            $inner = tracking_transform_subscription_body($decoded['decoded'], $mapping, false);
        } catch (TrackingTransformFailure $failure) {
            throw new TrackingTransformFailure($failure->reason, 'BASE64', $failure->getMessage());
        }
        return ['content' => $leading . tracking_encode_base64($inner['content'], $decoded) . $trailing,
            'format' => 'BASE64', 'node_count' => $inner['node_count']];
    }
    throw new TrackingTransformFailure('UNKNOWN_FORMAT', 'UNKNOWN', 'Subscription format is unsupported');
}
