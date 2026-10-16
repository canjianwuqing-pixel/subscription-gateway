<?php
declare(strict_types=1);
require_once $root . '/sgw/admin/src/certificate_worker.php';

const WORKER_TEST_SECRET = 'SGW_TEST_CF_SECRET_NEVER_LOG_987654321';
function contention_error(int $code, string $message = 'private diagnostic'): PDOException
{
    $error = new PDOException($message); $error->errorInfo = ['HY000', $code, $message]; return $error;
}
class ContentionPDO extends PDO
{
    public int $begins = 0;
    public int $busyBegins = 0;
    public string $releaseOnBusy = '';
    public ?PDOException $beginError = null;
    public ?PDOException $commitError = null;
    public function exec(string $statement): int|false
    {
        if ($statement === 'BEGIN IMMEDIATE') { $this->begins++; if ($this->beginError) throw $this->beginError; }
        if ($statement === 'COMMIT' && $this->commitError) throw $this->commitError;
        try { return parent::exec($statement); }
        catch (PDOException $error) {
            if ($statement === 'BEGIN IMMEDIATE' && sqlite_is_busy($error)) {
                $this->busyBegins++;
                if ($this->releaseOnBusy !== '') file_put_contents($this->releaseOnBusy, 'release');
            }
            throw $error;
        }
    }
}
function contention_db(): array
{
    global $temporaryRoot;
    $path = $temporaryRoot . '/contention-' . bin2hex(random_bytes(6)) . '.db';
    $db = open_database($path); initialize_database($db); return [$db, $path];
}
function contention_connection(string $path): ContentionPDO
{
    $db = new ContentionPDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA busy_timeout=20'); $db->exec('PRAGMA foreign_keys=ON'); return $db;
}
function contention_holder(string $path): array
{
    global $temporaryRoot;
    $prefix = $temporaryRoot . '/lock-' . bin2hex(random_bytes(6));
    $worker = spawn_test_worker(__DIR__ . '/sqlite_lock_holder.php', [$path, $prefix . '.ready', $prefix . '.release']);
    $deadline = microtime(true) + 5;
    while (!is_file($prefix . '.ready') && microtime(true) < $deadline) { usleep(10000); clearstatcache(); }
    if (!is_file($prefix . '.ready')) {
        file_put_contents($prefix . '.release', 'release'); finish_test_worker($worker);
        throw new RuntimeException('SQLite lock fixture did not acquire its write lock');
    }
    return ['worker' => $worker, 'release' => $prefix . '.release'];
}
function contention_release(array $holder): void
{
    file_put_contents($holder['release'], 'release'); expect_same('RELEASED', finish_test_worker($holder['worker']));
}
function contention_restore_env(string $name, string|false $value): void { putenv($value === false ? $name : $name . '=' . $value); }

foreach ([5, 6, 261, 262, 517, 773] as $code) test_case('SQLite BUSY/LOCKED primary/extended code ' . $code, static function () use ($code): void {
    expect_true(sqlite_is_busy(contention_error($code, 'not an English lock message')));
});
foreach ([1, 10, 11, 13, 19] as $code) test_case('Non-busy SQLite code has precedence over lock-like text ' . $code, static function () use ($code): void {
    expect_same(false, sqlite_is_busy(contention_error($code, 'database is locked')));
});
test_case('SQLite missing driver info supports legacy lock messages only for PDO errors', static function (): void {
    expect_true(sqlite_is_busy(new PDOException('database is locked')));
    expect_true(sqlite_is_busy(new PDOException('database table is locked: settings')));
    expect_same(false, sqlite_is_busy(new PDOException('no such table')));
    expect_same(false, sqlite_is_busy(new RuntimeException('database is locked')));
});
test_case('Real SQLite lock contention retries BEGIN and executes callback once after release', static function (): void {
    [$setup, $path] = contention_db(); $db = contention_connection($path); $holder = contention_holder($path);
    try {
        // The other process releases only after this connection observes a real SQLite BUSY.
        $db->releaseOnBusy = $holder['release']; $callbacks = 0;
        $result = write_transaction($db, static function () use ($db, &$callbacks): string { $callbacks++; setting_set($db, 'lock_test', 'committed'); return 'once'; });
        expect_same('once', $result); expect_same(1, $callbacks); expect_true($db->busyBegins >= 1); expect_true($db->begins >= 2 && $db->begins <= 3);
        expect_same('committed', setting_get($setup, 'lock_test')); expect_same(20, (int) $db->query('PRAGMA busy_timeout')->fetchColumn());
    } finally { contention_release($holder); }
});
test_case('Unreleased real lock exhausts exactly three BEGIN attempts with no callback or half transaction', static function (): void {
    [$holder, $path] = contention_db(); $db = contention_connection($path); $holder->exec('BEGIN IMMEDIATE'); $callbacks = 0; $start = microtime(true);
    try {
        expect_exception(static function () use ($db, &$callbacks): void { write_transaction($db, static function () use (&$callbacks): void { $callbacks++; }); }, PDOException::class);
        expect_same(3, $db->begins); expect_same(3, $db->busyBegins); expect_same(0, $callbacks); expect_true(microtime(true) - $start < 2);
        expect_same(false, $db->inTransaction()); expect_same(20, (int) $db->query('PRAGMA busy_timeout')->fetchColumn());
    } finally { $holder->exec('ROLLBACK'); }
    write_transaction($db, static fn () => setting_set($db, 'after_lock', 'healthy'));
    expect_same('healthy', setting_get($holder, 'after_lock')); expect_same([], $db->query('PRAGMA foreign_key_check')->fetchAll());
});
test_case('Real same-connection table lock is recognized as SQLITE_LOCKED', static function (): void {
    [$db] = contention_db(); $cursor = $db->query('SELECT * FROM settings'); $cursor->fetch();
    try {
        try { $db->exec('DROP TABLE settings'); throw new RuntimeException('Expected a real table lock'); }
        catch (PDOException $error) { expect_same(6, ((int) $error->errorInfo[1]) & 0xff); expect_true(sqlite_is_busy($error)); }
    } finally { $cursor->closeCursor(); }
});
test_case('Non-busy BEGIN failure is immediate and never calls callback', static function (): void {
    [$setup, $path] = contention_db(); $db = contention_connection($path); $db->beginError = contention_error(10); $callbacks = 0; $start = microtime(true);
    expect_exception(static function () use ($db, &$callbacks): void { write_transaction($db, static function () use (&$callbacks): void { $callbacks++; }); }, PDOException::class);
    expect_same(1, $db->begins); expect_same(0, $callbacks); expect_true(microtime(true) - $start < 0.5);
});
foreach (['callback_busy', 'callback_sql_error', 'commit_busy'] as $mode) test_case('No transaction callback replay after ' . $mode, static function () use ($mode): void {
    [$setup, $path] = contention_db(); $db = contention_connection($path); $callbacks = 0;
    if ($mode === 'commit_busy') $db->commitError = contention_error(5);
    expect_exception(static function () use ($db, &$callbacks, $mode): void {
        write_transaction($db, static function () use ($db, &$callbacks, $mode): void {
            $callbacks++; setting_set($db, 'must_rollback', 'side effect');
            if ($mode === 'callback_busy') throw contention_error(5);
            if ($mode === 'callback_sql_error') $db->exec('INSERT INTO no_such_table VALUES (1)');
        });
    }, PDOException::class);
    expect_same(1, $callbacks); expect_same(1, $db->begins); expect_same('', setting_get($setup, 'must_rollback', '')); expect_same(false, $db->inTransaction());
});
test_case('Successful and nested write_transaction callbacks retain original behavior and timeout', static function (): void {
    [$db] = contention_db(); $calls = 0;
    expect_same(42, write_transaction($db, static function () use ($db, &$calls): int { $calls++; return write_transaction($db, static function () use (&$calls): int { $calls++; return 42; }); }));
    expect_same(2, $calls); expect_same(5000, (int) $db->query('PRAGMA busy_timeout')->fetchColumn());
});
test_case('Worker iteration survives BUSY and releases its private PDO before reconnecting', static function (): void {
    [$setup, $path] = contention_db(); global $temporaryRoot; $dir = $temporaryRoot . '/worker-iteration'; mkdir($dir, 0700);
    $oldControl = getenv('CONTROL_DIR'); $oldLog = ini_get('error_log'); putenv('CONTROL_DIR=' . $dir); ini_set('error_log', $dir . '/errors.log');
    $pdo = null; $connections = 0; $connect = static function () use ($path, &$connections): PDO { $connections++; return open_database($path); };
    try {
        expect_true(certificate_worker_iteration($pdo, static fn () => null, $connect)); $weak = WeakReference::create($pdo);
        expect_same(false, certificate_worker_iteration($pdo, static fn () => throw contention_error(5, WORKER_TEST_SECRET), $connect));
        expect_same(null, $pdo); expect_same(null, $weak->get());
        expect_true(certificate_worker_iteration($pdo, static fn ($db) => setting_set($db, 'reconnected', 'yes'), $connect));
        expect_same(2, $connections); expect_same('yes', setting_get($setup, 'reconnected'));
        $log = (string) file_get_contents($dir . '/errors.log'); expect_true(str_contains($log, 'SQLITE_BUSY_OR_LOCKED')); expect_true(!str_contains($log, WORKER_TEST_SECRET));
    } finally { ini_set('error_log', (string) $oldLog); contention_restore_env('CONTROL_DIR', $oldControl); }
});
test_case('Non-PDO iteration error is safely caught and next iteration still executes', static function (): void {
    [$pdo] = contention_db(); global $temporaryRoot; $dir = $temporaryRoot . '/worker-runtime'; mkdir($dir, 0700);
    $oldControl = getenv('CONTROL_DIR'); $oldLog = ini_get('error_log'); putenv('CONTROL_DIR=' . $dir); ini_set('error_log', $dir . '/errors.log');
    try {
        expect_same(false, certificate_worker_iteration($pdo, static fn () => throw new RuntimeException(WORKER_TEST_SECRET)));
        expect_true(certificate_worker_iteration($pdo, static fn ($db) => setting_set($db, 'next_iteration', 'yes'))); expect_same('yes', setting_get($pdo, 'next_iteration'));
        expect_true(!str_contains((string) file_get_contents($dir . '/errors.log'), WORKER_TEST_SECRET));
    } finally { ini_set('error_log', (string) $oldLog); contention_restore_env('CONTROL_DIR', $oldControl); }
});
test_case('Real issue failure plus recovery write lock leaves restartable RUNNING, then RETRY and next queued alias completes', static function (): void {
    $oldControl = getenv('CONTROL_DIR'); $oldCerts = getenv('DOMAIN_CERT_DIR'); $oldLog = ini_get('error_log');
    $setup = domain_fixture(); $path = $setup->query('PRAGMA database_list')->fetch()['file']; $log = control_directory() . '/worker-errors.log'; ini_set('error_log', $log);
    $holder = null; $pdo = null; $issues = 0;
    try {
        $profile = domain_profile_fixture($setup, 'a', WORKER_TEST_SECRET);
        $a = domain_add($setup, ['fqdn' => 'a.example.net', 'credential_id' => $profile], 'domain_test_client');
        $b = domain_add($setup, ['fqdn' => 'b.example.net', 'credential_id' => $profile], 'domain_test_client');
        $setup->exec("UPDATE certificate_jobs SET state='RUNNING' WHERE domain_id=" . $a);
        $connect = static fn () => contention_connection($path);
        $issuer = static function ($row, $dir, $credential) use ($a, $path, &$holder, &$issues): void {
            if ((int) $row['id'] === $a) { if ($issues++ === 0) $holder = contention_holder($path); throw new RuntimeException(WORKER_TEST_SECRET); }
            domain_test_issuer($row, $dir, $credential);
        };
        $processor = static fn ($db) => domain_process_one($db, $issuer, 'domain_test_publish');
        expect_same(false, certificate_worker_iteration($pdo, $processor, $connect)); expect_same(null, $pdo);
        expect_same('RUNNING', domain_job($setup, $a)['state']); expect_same('PENDING', domain_job($setup, $b)['state']);
        contention_release($holder); $holder = null;
        expect_true(certificate_worker_iteration($pdo, $processor, $connect)); expect_same('ERROR', domain_row($setup, $a)['status']); expect_same('RETRY', domain_job($setup, $a)['state']);
        expect_true(str_contains(domain_row($setup, $a)['last_error'], '证书申请')); expect_true(!str_contains(domain_row($setup, $a)['last_error'], 'database is locked'));
        expect_true(certificate_worker_iteration($pdo, $processor, $connect)); expect_same('ACTIVE', domain_row($setup, $b)['status']); expect_same('DONE', domain_job($setup, $b)['state']);
        $text = (string) file_get_contents($log); expect_true(str_contains($text, 'ISSUE_FAILED')); expect_true(str_contains($text, 'SQLITE_BUSY_OR_LOCKED')); expect_true(!str_contains($text, WORKER_TEST_SECRET));
    } finally {
        if ($holder) contention_release($holder);
        ini_set('error_log', (string) $oldLog); contention_restore_env('CONTROL_DIR', $oldControl); contention_restore_env('DOMAIN_CERT_DIR', $oldCerts);
    }
});
test_case('Actual certificate worker process survives real DB contention and continues after release with its singleton lock intact', static function (): void {
    global $root, $temporaryRoot;
    [$setup, $path] = contention_db(); $dir = $temporaryRoot . '/worker-process'; mkdir($dir, 0700);
    $oldDb = getenv('DATABASE_PATH'); $oldControl = getenv('CONTROL_DIR'); $worker = null; $holder = null;
    try {
        $holder = contention_holder($path); putenv('DATABASE_PATH=' . $path); putenv('CONTROL_DIR=' . $dir);
        $worker = spawn_test_worker($root . '/sgw/admin/src/certificate_worker.php'); stream_set_blocking($worker['pipes'][2], false);
        $errors = ''; $deadline = microtime(true) + 10;
        while (!str_contains($errors, 'SQLITE_BUSY_OR_LOCKED') && microtime(true) < $deadline) { $errors .= (string) stream_get_contents($worker['pipes'][2]); usleep(20000); }
        expect_true(str_contains($errors, 'SQLITE_BUSY_OR_LOCKED')); expect_true(proc_get_status($worker['process'])['running']);
        clearstatcache(); $before = is_file($dir . '/certificate-worker.ready') ? (int) file_get_contents($dir . '/certificate-worker.ready') : 0;
        contention_release($holder); $holder = null;
        $deadline = microtime(true) + 6;
        do { usleep(20000); clearstatcache(); $after = is_file($dir . '/certificate-worker.ready') ? (int) file_get_contents($dir . '/certificate-worker.ready') : 0; } while ($after <= $before && microtime(true) < $deadline);
        expect_true($after > $before); expect_true(proc_get_status($worker['process'])['running']);
        $other = fopen($dir . '/certificate-worker.lock', 'c+'); expect_same(false, flock($other, LOCK_EX | LOCK_NB)); fclose($other);
        expect_true(!str_contains($errors, 'Fatal error')); expect_true(!str_contains($errors, WORKER_TEST_SECRET));
        expect_true(str_contains((string) file_get_contents($root . '/sgw/admin/src/certificate_worker.php'), 'sleep(2)'));
    } finally {
        if ($holder) contention_release($holder);
        if ($worker) { proc_terminate($worker['process']); foreach ($worker['pipes'] as $pipe) { if (is_resource($pipe)) fclose($pipe); } proc_close($worker['process']); }
        contention_restore_env('DATABASE_PATH', $oldDb); contention_restore_env('CONTROL_DIR', $oldControl);
    }
});
