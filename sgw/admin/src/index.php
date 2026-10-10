<?php

declare(strict_types=1);

require_once __DIR__ . '/api.php';

try {
    start_admin_session();
    $route = resolve_admin_route((string) ($_SERVER['REQUEST_URI'] ?? '/'));
} catch (HttpError) {
    http_response_code(404);
    exit;
} catch (Throwable $error) {
    error_log('Admin startup failure: ' . $error::class);
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo '后台服务配置异常，请检查服务日志。';
    exit;
}

if (str_starts_with($route, '/api/')) {
    handle_api($route, strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')));
}

if ($route !== '/') {
    http_response_code(404);
    exit;
}

if (is_authenticated()) {
    require __DIR__ . '/dashboard.php';
    exit;
}

$basePath = '/' . app_config()['admin_secret_path'];
$csrf = csrf_token();
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
    <title>订阅清洗网关 · 管理员登录</title>
    <style>
        :root{color-scheme:light;font:14px/1.45 system-ui,sans-serif;background:#F4F7FB;color:#1F2937}
        *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center}
        form{width:min(360px,calc(100vw - 32px));padding:22px;border:1px solid #DCE4EE;background:#FFFFFF;border-radius:8px}
        h1{font-size:18px;margin:0 0 18px}label{display:block;margin:12px 0 5px;color:#64748B}
        input,button{width:100%;height:38px;border:1px solid #DCE4EE;background:#FFFFFF;color:#1F2937;padding:0 10px;border-radius:4px}
        input:focus-visible{outline:2px solid #0891B2;outline-offset:2px}
        button{margin-top:18px;background:#0891B2;border-color:#0891B2;color:#FFFFFF;cursor:pointer;font-weight:600}
        #error{min-height:20px;margin-top:10px;color:#DC2626;font-size:12px}
    </style>
</head>
<body>
<form id="login" autocomplete="off">
    <h1>订阅清洗网关</h1>
    <label for="username">管理员</label>
    <input id="username" name="username" autocomplete="username" required maxlength="64">
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
    <button type="submit">登录</button>
    <div id="error" role="alert"></div>
</form>
<script>
const base = <?= json_encode($basePath, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
document.getElementById('login').addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = document.getElementById('error');
    error.textContent = '';
    try {
        const response = await fetch(base + '/api/login', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
            body: JSON.stringify({
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            })
        });
        const data = await response.json();
        if (!response.ok || !data.ok) throw new Error(data.error || '登录失败');
        location.replace(base + '/');
    } catch (exception) {
        error.textContent = /[\u3400-\u9fff]/.test(exception.message || '') ? exception.message : '登录失败，请检查网络后重试';
    }
});
</script>
</body>
</html>
