<?php
// Independent stock PHP/PDO observations; application methods are not replaced.
$mode = $argv[1] ?? '';
if ($mode === 'metadata') {
    $paths = ['bootstrap.php', 'header-unlogged.php', 'includes/functions.php', 'includes/app.php', 'includes/functions.options.php', 'includes/security/csrf.php', 'options.php', 'index.php', 'register.php', 'includes/upload.process.php', 'install/index.php', 'install/database.php'];
    $hashes = [];
    foreach ($paths as $path) {
        $hashes[$path] = hash_file('sha256', '/app/www/public/' . $path);
    }
    $identity = trim((string) shell_exec('id -u'));
    if (!ctype_digit($identity)) {
        throw new RuntimeException('Cannot observe the stock PHP command UID');
    }
    echo json_encode(['php' => PHP_VERSION, 'uid' => (int) $identity, 'files_sha256' => $hashes], JSON_THROW_ON_ERROR);
    exit;
}
require '/app/www/public/includes/sys.config.php';
$db = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4', DB_USER, DB_PASSWORD, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
$table = TABLES_PREFIX . 'options';
if (!preg_match('/^[a-zA-Z0-9_]+$/D', $table)) {
    throw new InvalidArgumentException('Invalid table name');
}
if ($mode === 'options') {
    echo json_encode($db->query('SELECT * FROM `' . $table . '` ORDER BY id')->fetchAll(), JSON_THROW_ON_ERROR);
} elseif ($mode === 'set-options') {
    $values = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    $statement = $db->prepare('UPDATE `' . $table . '` SET value=? WHERE name=?');
    foreach ($values as $name => $value) {
        $statement->execute([$value, $name]);
    }
    echo json_encode(['updated' => array_keys($values)], JSON_THROW_ON_ERROR);
} elseif ($mode === 'restore-options') {
    $rows = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    $db->beginTransaction();
    try {
        $db->exec('DELETE FROM `' . $table . '`');
        $statement = $db->prepare('INSERT INTO `' . $table . '` (id,name,value) VALUES (?,?,?)');
        foreach ($rows as $row) {
            $statement->execute([$row['id'], $row['name'], $row['value']]);
        }
        $db->commit();
    } catch (Throwable $error) {
        $db->rollBack();
        throw $error;
    }
    echo json_encode(['restored' => count($rows)], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unknown observation mode');
}
