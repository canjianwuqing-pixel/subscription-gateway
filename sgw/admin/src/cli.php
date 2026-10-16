<?php
declare(strict_types=1);
require_once __DIR__ . '/publish.php';
require_once __DIR__ . '/installation.php';
require_once __DIR__ . '/domain_certificates.php';

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

try {
    $command = $argv[1] ?? '';
    if ($command === 'installation-probe') {
        installation_extensions_check();
        echo 'INSTALLER_API_1', PHP_EOL;
        exit;
    }
    if ($command === 'transformer-check') {
        installation_transformer_check();
        echo 'TRANSFORMER_OK', PHP_EOL;
        exit;
    }
    $readOnly = in_array($command, ['domain-check','installation-check', 'admin-status', 'integrity', 'versions', 'upstream-state'], true);
    if ($readOnly && !is_file((string) app_config()['database_path'])) {
        throw new RuntimeException('Database missing; run the installer to migrate it');
    }
    $pdo = $readOnly ? open_database((string) app_config()['database_path']) : app_db();
    if ($command === 'cloudflare-bootstrap') {
        // Two newline-delimited fields via stdin only. Never echo credentials or upstream exceptions.
        try {
            $token=rtrim((string)fgets(STDIN,514),"\r\n"); $zone=rtrim((string)fgets(STDIN,64),"\r\n");
            if($zone==='') $zone=cloudflare_discover_zone($token,env_required('GATEWAY_DOMAIN'));
            cloudflare_save_profile($pdo,['name'=>'默认 Cloudflare','token'=>$token,'zone_id'=>$zone]);
            sodium_memzero($token); echo 'CLOUDFLARE_PROFILE_READY',PHP_EOL;
        } catch(Throwable) { fwrite(STDERR,"Cloudflare profile initialization failed; add it in Admin later.\n"); exit(1); }
    } elseif ($command === 'sync-primary-domain') {
        domain_sync_primary($pdo,env_required('GATEWAY_DOMAIN')); echo 'PRIMARY_SYNCED',PHP_EOL;
    } elseif ($command === 'domain-check') {
        $status=domain_installation_check($pdo);
        $pid=trim((string)@file_get_contents('/run/certificate-worker.pid'));
        $stat=ctype_digit($pid)?@file_get_contents('/proc/'.$pid.'/stat'):false;
        if(!is_string($stat)||preg_match('/\) [ZX] /',$stat)||!is_file('/control/certificate-worker.ready')) throw new RuntimeException('Certificate worker unavailable');
        echo 'DOMAINS_OK schema=',$status['schema'],' active_aliases=',$status['active_aliases'],' worker=ready',PHP_EOL;
    } elseif ($command === 'migrate') {
        echo 'MIGRATED', PHP_EOL;
    } elseif ($command === 'installation-check') {
        installation_extensions_check();
        $status = installation_database_check($pdo);
        echo 'INSTALLATION_OK schema=', $status['schema'], ' tracking_mode=', $status['tracking_mode'],
            ' upstream=', $status['upstream'], PHP_EOL;
    } elseif ($command === 'admin-status') {
        $count = admin_count($pdo);
        $username = $count === 1 ? (string) $pdo->query('SELECT username FROM admins LIMIT 1')->fetchColumn() : '';
        echo $count, ' ', $username, PHP_EOL;
    } elseif ($command === 'init-admin') {
        if (admin_count($pdo) !== 0) throw new RuntimeException('Administrator already exists');
        $username = (string) ($argv[2] ?? '');
        $password = rtrim((string) stream_get_contents(STDIN), "\r\n");
        create_admin($pdo, $username, $password);
        echo 'ADMIN_CREATED', PHP_EOL;
    } elseif ($command === 'reset-admin-password') {
        $password = rtrim((string) stream_get_contents(STDIN), "\r\n");
        $hash = password_hash_secure($password);
        $statement = $pdo->prepare('UPDATE admins SET password_hash = :hash, '
            . 'auth_version = auth_version + 1, updated_at = :updated');
        $statement->execute([':hash' => $hash, ':updated' => time()]);
        if ($statement->rowCount() !== 1) throw new RuntimeException('Expected exactly one administrator');
        echo 'PASSWORD_RESET', PHP_EOL;
    } elseif ($command === 'integrity') {
        if ($pdo->query('PRAGMA integrity_check')->fetchColumn() !== 'ok') {
            throw new RuntimeException('SQLite integrity_check failed');
        }
        echo 'SQLITE_OK', PHP_EOL;
    } elseif ($command === 'backup') {
        $target = (string) ($argv[2] ?? '');
        if (!preg_match('#^/backups/[A-Za-z0-9._-]+\.db$#D', $target)) {
            throw new InvalidArgumentException('Invalid backup destination');
        }
        $statement = $pdo->prepare('VACUUM INTO :path');
        $statement->execute([':path' => $target]);
        echo 'BACKUP_OK', PHP_EOL;
    } elseif ($command === 'compile') {
        if (setting_get($pdo, 'upstream_url', '') === '') {
            echo 'FAIL_CLOSED', PHP_EOL;
        } else {
            $result = publish_current_rules($pdo);
            if ($result['applied'] !== true) throw new RuntimeException('Gateway rule application did not complete');
            echo 'RULES_APPLIED', PHP_EOL;
        }
    } elseif ($command === 'versions') {
        $status = gateway_publish_status($pdo);
        echo $status['config_version'], ' ', $status['active_version'], PHP_EOL;
    } elseif ($command === 'upstream-state') {
        echo setting_get($pdo, 'upstream_url', '') === '' ? 'EMPTY' : 'CONFIGURED', PHP_EOL;
    } else {
        throw new InvalidArgumentException('Unknown CLI command');
    }
} catch (Throwable $error) {
    fwrite(STDERR, 'CLI failed: ' . $error::class . ': ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
