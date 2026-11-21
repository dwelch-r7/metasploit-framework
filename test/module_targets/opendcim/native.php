<?php
// CLI-only evidence using the image's own PDO and PHP; no extra web endpoint.
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$action = $argv[1];
if ($action === 'metadata') {
    $sources = [];
    foreach (['version.php', 'container-install.php', 'config.inc.php', 'report_network_map.php', 'db.inc.php', 'facilities.inc.php', 'classes/People.class.php'] as $name) {
        $sources[$name] = hash_file('sha256', '/var/www/html/' . $name);
    }
    require '/var/www/html/version.php';
    $result = ['version' => VERSION, 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'sources' => $sources,
        'install_sha256' => hash_file('sha256', '/var/www/html/install.php'),
        'install_link' => is_link('/var/www/html/install.php') ? readlink('/var/www/html/install.php') : null];
} elseif ($action === 'query' || $action === 'transaction') {
    chdir('/var/www/html');
    require 'db.inc.php';
    $queries = $action === 'transaction' ? $input['queries'] : [$input];
    $results = [];
    if ($action === 'transaction') {
        $dbh->beginTransaction();
    }
    try {
        foreach ($queries as $query) {
            $statement = $dbh->prepare($query['sql']);
            $statement->execute($query['params'] ?? []);
            $results[] = ['rows' => $statement->columnCount() ? $statement->fetchAll(PDO::FETCH_ASSOC) : [], 'affected' => $statement->rowCount()];
        }
        if ($action === 'transaction') {
            $dbh->commit();
        }
    } catch (PDOException $error) {
        if ($dbh->inTransaction()) {
            $dbh->rollBack();
        }
        throw $error;
    }
    $result = $action === 'transaction' ? $results : $results[0];
} elseif ($action === 'file' || $action === 'remove') {
    $path = $input['path'];
    if (!preg_match('~\A/tmp/module-target-opendcim-[a-z0-9_-]+\z~', $path)) {
        throw new InvalidArgumentException('Invalid fixture path');
    }
    if ($action === 'remove' && file_exists($path) && !unlink($path)) {
        throw new RuntimeException('Cannot remove fixture file');
    }
    clearstatcache(true, $path);
    $result = file_exists($path) ? ['exists' => true, 'uid' => fileowner($path), 'base64' => base64_encode(file_get_contents($path))] : ['exists' => false];
} else {
    throw new InvalidArgumentException('Unknown native action');
}
echo json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE), "\n";
