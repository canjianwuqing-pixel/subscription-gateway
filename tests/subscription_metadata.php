<?php

declare(strict_types=1);

$metadataMapping = ['origin.example.invalid' => 'private.example.invalid'];
$metadataNode = 'vless://uuid@origin.example.invalid:443?sni=origin.example.invalid#Node';
$metadataTarget = str_replace('@origin.example.invalid:', '@private.example.invalid:', $metadataNode);
foreach (["剩余流量：88 GB", "已用流量：12 GB", "套餐到期：2026-12-31", "重置时间：下月1日",
    '官网地址：https://example.com', '客户端下载：https://download.example.com', '公告：请及时更新订阅',
    '客服说明：联系客服', 'metadata=value', 'Hint: use vless:// capable clients',
    'https://example.com', 'http://example.com', "  # 注释 😀  ", '', "  提示：请使用 vless:// 格式客户端  "] as $index => $line) {
    test_case('URI metadata line ' . $index . ' is preserved byte for byte', function () use ($line, $metadataNode, $metadataTarget, $metadataMapping): void {
        $result = tracking_transform_subscription_body($line . "\r\n" . $metadataNode . "\r\n", $metadataMapping);
        expect_same('URI', $result['format']);
        expect_same(1, $result['node_count']);
        expect_same($line . "\r\n" . $metadataTarget . "\r\n", $result['content']);
    });
}

test_case('Mixed metadata and 41 nodes transform and learn only connection hosts', function () use ($metadataMapping): void {
    $notes = "  剩余流量：88GB  \r\n套餐到期：2026-12-31\n官网地址：https://example.com\r\n"
        . "https://download.example.com\n# 公告 😀\r\n\r\n提示：请使用 vless:// 格式客户端\r\n";
    $nodes = [];
    for ($i = 0; $i < 41; $i++) $nodes[] = ($i % 2 ? 'hysteria2' : 'vless')
        . '://credential@origin.example.invalid:443?sni=origin.example.invalid#Node-' . $i;
    $plain = $notes . implode("\r\n", $nodes) . "\r\n";
    $expected = $notes . str_replace('@origin.example.invalid:', '@private.example.invalid:', implode("\r\n", $nodes)) . "\r\n";
    $result = tracking_transform_subscription_body($plain, $metadataMapping);
    expect_same(41, $result['node_count']);
    expect_same($expected, $result['content']);
    expect_same(['origin.example.invalid'], tracking_subscription_source_hosts($plain));
    foreach ([['urlsafe' => false, 'padded' => true], ['urlsafe' => false, 'padded' => false],
        ['urlsafe' => true, 'padded' => true], ['urlsafe' => true, 'padded' => false]] as $meta) {
        $encoded = tracking_encode_base64($plain, $meta);
        $output = tracking_transform_subscription_body(" \r\n" . $encoded . "\n ", $metadataMapping);
        expect_same('BASE64', $output['format']);
        expect_same(41, $output['node_count']);
        expect_same(" \r\n" . tracking_encode_base64($expected, tracking_decode_base64($encoded, 'BASE64')) . "\n ", $output['content']);
        expect_same($expected, tracking_decode_base64(trim($output['content']), 'BASE64')['decoded']);
        expect_same(['origin.example.invalid'], tracking_subscription_source_hosts($encoded));
    }
});

foreach (['anytls', 'socks5', 'wireguard', 'unknown', 'Custom+proxy'] as $scheme) {
    foreach ([false, true] as $outer) {
        test_case(($outer ? 'Base64' : 'URI') . ' unknown scheme ' . $scheme . ' fails closed', function () use ($scheme, $outer, $metadataNode, $metadataMapping): void {
            $body = "官网：https://example.com\r\n" . $metadataNode . "\n  " . $scheme . '://credential@origin.example.invalid:443';
            if ($outer) $body = base64_encode($body);
            try {
                tracking_transform_subscription_body($body, $metadataMapping);
                throw new RuntimeException('Unknown proxy silently passed through');
            } catch (TrackingTransformFailure $failure) {
                expect_same('UNKNOWN_FORMAT', $failure->reason);
                expect_same($outer ? 'BASE64' : 'URI', $failure->format);
            }
            expect_exception(fn () => tracking_subscription_source_hosts($body), TrackingTransformFailure::class);
        });
    }
}

test_case('Metadata alone is not a successful proxy subscription', function () use ($metadataMapping): void {
    expect_exception(fn () => tracking_transform_subscription_body("说明：无节点\nhttps://example.com\n", $metadataMapping), TrackingTransformFailure::class);
});
test_case('Malformed supported nodes cannot hide among metadata', function () use ($metadataMapping): void {
    try {
        tracking_transform_subscription_body("说明：流量\nvless://\n", $metadataMapping);
        throw new RuntimeException('Malformed node accepted');
    } catch (TrackingTransformFailure $failure) {
        expect_same('PARSE_FAILED', $failure->reason);
    }
});
foreach (['vless', 'hysteria2', 'hy2', 'trojan', 'tuic', 'ss'] as $scheme) {
    test_case('Mixed metadata retains supported authority protocol ' . $scheme, function () use ($scheme, $metadataMapping): void {
        $body = "说明：套餐\n  " . $scheme . "://credential@origin.example.invalid:443?sni=origin.example.invalid#tag  \n";
        expect_same(str_replace('@origin.example.invalid:', '@private.example.invalid:', $body), tracking_transform_subscription_body($body, $metadataMapping)['content']);
    });
}
test_case('VMess metadata keeps description fields and learns only add', function () use ($metadataMapping): void {
    $doc = ['add' => 'origin.example.invalid', 'ps' => 'https://website.example.com', 'sni' => 'sni.example.com', 'port' => '443'];
    $body = "官网：https://website.example.com\nvmess://" . base64_encode(json_encode($doc, JSON_THROW_ON_ERROR));
    $result = tracking_transform_subscription_body($body, $metadataMapping);
    expect_same('VMESS', $result['format']);
    expect_true(str_starts_with($result['content'], "官网：https://website.example.com\n"));
    $after = json_decode(tracking_decode_base64(explode('vmess://', $result['content'], 2)[1], 'VMESS')['decoded'], true, 32, JSON_THROW_ON_ERROR);
    $doc['add'] = 'private.example.invalid';
    expect_same($doc, $after);
    expect_same(['origin.example.invalid'], tracking_subscription_source_hosts($body));
});
