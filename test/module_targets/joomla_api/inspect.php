<?php
define('_JEXEC', 1);
define('JPATH_BASE', '/var/www/html' . getenv('LAB_PREFIX'));
require JPATH_BASE . '/includes/defines.php';
require JPATH_LIBRARIES . '/bootstrap.php';
require JPATH_BASE . '/configuration.php';
$configuration = new JConfig();
$database = (new Joomla\Database\DatabaseFactory())->getDriver('mysqli', [
    'host' => $configuration->host,
    'user' => $configuration->user,
    'password' => $configuration->password,
    'database' => $configuration->db,
    'prefix' => $configuration->dbprefix,
]);
if (isset($argv[1])) {
    if (!in_array($argv[1], ['users', 'config'], true) || !in_array($argv[2] ?? '', ['0', '1'], true)) {
        throw new InvalidArgumentException('Expected native webservice plugin and enabled state');
    }
    $database->setQuery("UPDATE #__extensions SET enabled = " . (int) $argv[2] . " WHERE type = 'plugin' AND folder = 'webservices' AND element = " . $database->quote($argv[1]))->execute();
}
$users = $database->setQuery('SELECT u.id, u.name, u.username, u.email, u.password, u.block, u.sendEmail, u.registerDate, u.lastvisitDate, g.title AS group_name FROM #__users u JOIN #__user_usergroup_map m ON m.user_id = u.id JOIN #__usergroups g ON g.id = m.group_id ORDER BY u.id')->loadAssocList();
$accounts = json_decode(file_get_contents('/opt/module-target/accounts.json'), true, 512, JSON_THROW_ON_ERROR);
foreach ($users as &$user) {
    $user['password_valid'] = password_verify($accounts[$user['username']]['password'], $user['password']);
    unset($user['password']);
}
unset($user);
$plugins = $database->setQuery("SELECT folder, element, enabled FROM #__extensions WHERE type = 'plugin' AND folder IN ('webservices', 'api-authentication') ORDER BY folder, element")->loadAssocList();
echo json_encode([
    'version' => JVERSION,
    'php' => PHP_VERSION,
    'router_sha256' => hash_file('sha256', JPATH_BASE . '/libraries/src/Router/ApiRouter.php'),
    'configuration' => get_object_vars($configuration),
    'users' => $users,
    'plugins' => $plugins,
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE) . "\n";
