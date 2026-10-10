<?php

declare(strict_types=1);

require_once __DIR__ . '/tracking.php';

final class TrackingTransformFailure extends RuntimeException
{
    public function __construct(
        public readonly string $reason,
        public readonly string $format = 'UNKNOWN',
        string $message = 'Subscription transformation failed',
        public readonly array $counts = []
    ) {
        parent::__construct($message);
    }
}

/** Internal control flow: only a validated known node may be filtered. */
final class TrackingUnmappedNode extends RuntimeException {}

function tracking_transform_result(string $content, string $format, int $total, int $emitted): array
{
    $counts = ['total_nodes' => $total, 'emitted_nodes' => $emitted, 'skipped_nodes' => $total - $emitted];
    if ($emitted === 0) throw new TrackingTransformFailure('NO_USABLE_NODES', $format, 'No usable proxy nodes', $counts);
    return ['content' => $content, 'format' => $format, 'node_count' => $emitted,
        'outcome' => $total === $emitted ? 'SUCCESS' : 'PARTIAL_SUCCESS'] + $counts;
}

/** Metadata-only identity pass through the same structured parser/validation. */
final class TrackingSourceCollector
{
    /** @var array<string,true> */
    public array $hosts = [];

    public function collect(string $host, string $format): string
    {
        $this->hosts[$host] = true;
        if (count($this->hosts) > 1000) {
            throw new TrackingTransformFailure('RESPONSE_TOO_LARGE', $format, 'Too many source hosts');
        }
        return $host;
    }
}

/** @return list<string> */
function tracking_subscription_source_hosts(string $body): array
{
    $sources = new TrackingSourceCollector();
    tracking_transform_subscription_body($body, [], true, $sources);
    $hosts = array_keys($sources->hosts);
    sort($hosts, SORT_STRING);
    return $hosts;
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
function tracking_mapped_host(string $host, array $mapping, string $format, ?TrackingSourceCollector $sources = null): string
{
    try {
        $normalized = normalize_tracking_host($host);
    } catch (InvalidArgumentException $error) {
        throw new TrackingTransformFailure('PARSE_FAILED', $format, $error->getMessage());
    }
    if ($sources !== null) return $sources->collect($normalized, $format);
    if (!array_key_exists($normalized, $mapping)) {
        throw new TrackingUnmappedNode();
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
function tracking_transform_authority_uri(string $uri, array $mapping, string $format = 'URI', ?TrackingSourceCollector $sources = null): array
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
    $target = tracking_mapped_host($host, $mapping, $format, $sources);
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
function tracking_transform_vmess_uri(string $uri, array $mapping, ?TrackingSourceCollector $sources = null): string
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
    $document['add'] = tracking_mapped_host($document['add'], $mapping, 'VMESS', $sources);
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
function tracking_transform_ss_uri(string $uri, array $mapping, ?TrackingSourceCollector $sources = null): string
{
    $prefix = substr($uri, 0, strlen('ss://'));
    $payloadStart = strlen($prefix);
    $suffixOffset = strcspn($uri, '?#', $payloadStart) + $payloadStart;
    $authority = substr($uri, $payloadStart, $suffixOffset - $payloadStart);
    if (str_contains($authority, '@')) {
        return tracking_transform_authority_uri($uri, $mapping, 'URI', $sources)['content'];
    }
    $decoded = tracking_decode_base64($authority, 'URI');
    $innerPrefix = 'ss://';
    $inner = tracking_transform_authority_uri($innerPrefix . $decoded['decoded'], $mapping, 'URI', $sources)['content'];
    $encoded = tracking_encode_base64(substr($inner, strlen($prefix)), $decoded);
    return $prefix . $encoded . substr($uri, $suffixOffset);
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,format:string,node_count:int}|null
 */
function tracking_try_transform_uri_list(string $body, array $mapping, ?TrackingSourceCollector $sources = null): ?array
{
    $parts = preg_split('/(\r\n|\n|\r)/', $body, -1, PREG_SPLIT_DELIM_CAPTURE);
    if (!is_array($parts)) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'URI');
    }
    $nodes = 0;
    $emitted = 0;
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
            // Only a scheme at the first non-whitespace character can be a node.
            // HTTP(S) and ordinary metadata remain byte-for-byte in $parts.
            if (preg_match('#^([a-z][a-z0-9+.-]*)://#i', $line, $unknown)
                && !in_array(strtolower($unknown[1]), ['http', 'https'], true)) {
                throw new TrackingTransformFailure('UNKNOWN_FORMAT', 'URI', 'Unsupported proxy scheme');
            }
            continue;
        }
        $scheme = strtolower($match[1]);
        $nodes++;
        if ($scheme === 'vmess') $vmessNodes++;
        try {
            if ($scheme === 'vmess') $replacement = tracking_transform_vmess_uri($line, $mapping, $sources);
            elseif ($scheme === 'ss') $replacement = tracking_transform_ss_uri($line, $mapping, $sources);
            else $replacement = tracking_transform_authority_uri($line, $mapping, 'URI', $sources)['content'];
        } catch (TrackingUnmappedNode) {
            $parts[$index] = '';
            // Remove this node's terminator, not surrounding metadata/blank lines.
            if (isset($parts[$index + 1])) $parts[$index + 1] = '';
            continue;
        }
        $leading = substr($part, 0, strlen($part) - strlen(ltrim($part)));
        $trailing = substr($part, strlen(rtrim($part)));
        $parts[$index] = $leading . $replacement . $trailing;
        $emitted++;
    }
    if ($nodes === 0) {
        return null;
    }
    return tracking_transform_result(implode('', $parts), $vmessNodes === $nodes ? 'VMESS' : 'URI', $nodes, $emitted);
}

/**
 * @param array<string, string> $mapping
 * @return array{content:string,format:string,node_count:int}|null
 */
function tracking_try_transform_yaml(string $body, array $mapping, ?TrackingSourceCollector $sources = null): ?array
{
    if (!preg_match('/(?:^|\r\n|\n|\r)[ \t]*proxies[ \t]*:/', $body)) {
        return null;
    }
    if (!extension_loaded('yaml')) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'YAML extension is unavailable');
    }
    $document = @yaml_parse($body);
    if (!is_array($document) || !isset($document['proxies']) || !is_array($document['proxies']) || !array_is_list($document['proxies'])) {
        throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash YAML proxies are invalid');
    }
    $total = count($document['proxies']);
    if ($total === 0) throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash YAML has no proxies');
    $names = [];
    foreach ($document['proxies'] as $proxy) {
        if (!is_array($proxy) || !is_string($proxy['server'] ?? null)
            || !is_string($proxy['name'] ?? null) || $proxy['name'] === '' || isset($names[$proxy['name']])) {
            throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Clash proxy server is invalid');
        }
        if (!in_array(strtolower((string) ($proxy['type'] ?? '')), ['vless','vmess','trojan','ss','hysteria2','hy2','tuic'], true))
            throw new TrackingTransformFailure('UNKNOWN_FORMAT', 'YAML', 'Unsupported proxy type');
        $names[$proxy['name']] = true;
    }
    $groups = $document['proxy-groups'] ?? [];
    if (!is_array($groups) || !array_is_list($groups)) throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Proxy groups are invalid');
    $groupNames = [];
    $builtins = array_fill_keys(['DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE','GLOBAL'], true);
    foreach ($names as $name => $_) if (isset($builtins[$name])) throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Reserved proxy name');
    foreach ($groups as $group) {
        if (!is_array($group) || !is_string($group['name'] ?? null) || $group['name'] === ''
            || isset($names[$group['name']]) || isset($groupNames[$group['name']]) || isset($builtins[$group['name']]))
            throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Ambiguous proxy group name');
        $groupNames[$group['name']] = true;
    }
    foreach ($groups as $group) {
        $refs = $group['proxies'] ?? [];
        if (!is_array($refs) || !array_is_list($refs)) throw new TrackingTransformFailure('PARSE_FAILED', 'YAML', 'Proxy references are invalid');
        foreach ($refs as $ref) if (!is_string($ref) || (!isset($names[$ref]) && !isset($groupNames[$ref]) && !isset($builtins[$ref])))
            throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Dangling proxy reference');
        if ($refs === [] && empty($group['use'])) throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Empty proxy group');
    }
    $byName = array_column($groups, null, 'name');
    $visiting = []; $visited = [];
    $visit = static function (string $name) use (&$visit, &$visiting, &$visited, $byName): void {
        if (isset($visiting[$name])) throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Cyclic proxy groups');
        if (isset($visited[$name])) return;
        $visiting[$name] = true;
        foreach ($byName[$name]['proxies'] ?? [] as $ref) if (isset($byName[$ref])) $visit($ref);
        unset($visiting[$name]); $visited[$name] = true;
    };
    foreach (array_keys($byName) as $name) $visit((string) $name);
    $kept = [];
    $removed = [];
    foreach ($document['proxies'] as $proxy) {
        try { $proxy['server'] = tracking_mapped_host($proxy['server'], $mapping, 'YAML', $sources); }
        catch (TrackingUnmappedNode) { $removed[$proxy['name']] = true; continue; }
        $kept[] = $proxy;
    }
    if ($kept === []) return tracking_transform_result('', 'YAML', $total, 0);
    $document['proxies'] = $kept;
    foreach ($groups as &$group) {
        $hadRefs = array_key_exists('proxies', $group);
        $refs = $group['proxies'] ?? [];
        $group['proxies'] = array_values(array_filter($refs, static fn ($ref) => !isset($removed[$ref])));
        // Provider-only/dynamic or empty groups cannot be safely repaired by
        // this local filter. Fail closed instead of inventing a DIRECT fallback.
        if ($removed !== [] && ($group['proxies'] === [] || !empty($group['use']) || !empty($group['include-all'])))
            throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Filtering would make proxy groups unsafe');
        if (!$hadRefs) unset($group['proxies']);
    }
    unset($group);
    if (array_key_exists('proxy-groups', $document)) $document['proxy-groups'] = $groups;
    $encoded = @yaml_emit($document, YAML_UTF8_ENCODING, YAML_LN_BREAK);
    if (!is_string($encoded)) {
        throw new TrackingTransformFailure('VALIDATION_FAILED', 'YAML', 'Clash YAML encoding failed');
    }
    return tracking_transform_result($encoded, 'YAML', $total, count($kept));
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
function tracking_transform_subscription_body(string $body, array $mapping, bool $allowOuterBase64 = true, ?TrackingSourceCollector $sources = null): array
{
    $yaml = tracking_try_transform_yaml($body, $mapping, $sources);
    if ($yaml !== null) {
        return $yaml;
    }
    $uris = tracking_try_transform_uri_list($body, $mapping, $sources);
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
            $inner = tracking_transform_subscription_body($decoded['decoded'], $mapping, false, $sources);
        } catch (TrackingTransformFailure $failure) {
            throw new TrackingTransformFailure($failure->reason, 'BASE64', $failure->getMessage(), $failure->counts);
        }
        return array_replace($inner, ['content' => $leading . tracking_encode_base64($inner['content'], $decoded) . $trailing, 'format' => 'BASE64']);
    }
    throw new TrackingTransformFailure('UNKNOWN_FORMAT', 'UNKNOWN', 'Subscription format is unsupported');
}

/** Parse before changing lifecycle; filtering and source edits share one write
 * transaction. Zero usable nodes is a valid observation, not a parse failure. */
function tracking_process_subscription(PDO $pdo, int $groupId, string $body): array
{
    $hosts = tracking_subscription_source_hosts($body);
    $result = write_transaction($pdo, static function () use ($pdo, $groupId, $body, $hosts): array|TrackingTransformFailure {
        tracking_sync_source_hosts($pdo, $hosts);
        try { return tracking_transform_subscription_body($body, tracking_effective_mapping($pdo, $groupId)); }
        catch (TrackingTransformFailure $failure) {
            if ($failure->reason !== 'NO_USABLE_NODES') throw $failure;
            return $failure;
        }
    });
    if ($result instanceof TrackingTransformFailure) throw $result;
    return $result;
}
