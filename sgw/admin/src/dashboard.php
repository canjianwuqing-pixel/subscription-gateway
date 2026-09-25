<?php

declare(strict_types=1);

$basePath = '/' . app_config()['admin_secret_path'];
$username = htmlspecialchars((string) $_SESSION['admin_username'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$csrf = htmlspecialchars(csrf_token(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="csrf-token" content="<?= $csrf ?>">
    <title>Subscription Gateway Admin</title>
    <style>
        :root{color-scheme:dark;font:13px/1.4 system-ui,sans-serif;background:#080e17;color:#d8e3f0}
        *{box-sizing:border-box}body{margin:0}.top{height:42px;border-bottom:1px solid #27364a;padding:0 14px;display:flex;align-items:center;justify-content:space-between;background:#0d1521}
        main{padding:14px}.panel{max-width:900px;border:1px solid #26364a;background:#101927;padding:14px}
        h1{font-size:16px;margin:0}h2{font-size:14px;margin:0 0 10px}.muted{color:#91a4ba}
        button{height:30px;border:1px solid #30435b;background:#142238;color:#d8e3f0;padding:0 11px;cursor:pointer}
        code{color:#7fd7e5}
    </style>
</head>
<body>
<header class="top">
    <h1>Subscription Gateway</h1>
    <div><?= $username ?>　<button id="logout">退出</button></div>
</header>
<main>
    <section class="panel">
        <h2>第一阶段基础已启用</h2>
        <p>SQLite、Token加密、管理员认证、Session、CSRF和输入验证已经建立。</p>
        <p class="muted">Gateway规则、分析页面和安全reload将在后续阶段实现。本页面不会修改Gateway行为。</p>
        <p>API入口：<code><?= htmlspecialchars($basePath, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>/api/</code></p>
    </section>
</main>
<script>
const base = <?= json_encode($basePath, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
document.getElementById('logout').addEventListener('click', async () => {
    const response = await fetch(base + '/api/logout', {
        method: 'POST', credentials: 'same-origin', headers: {'X-CSRF-Token': csrf}
    });
    if (response.ok) location.replace(base + '/');
});
</script>
</body>
</html>
