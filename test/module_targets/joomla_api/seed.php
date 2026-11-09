<?php
// Manual installation uses Joomla's supplied defaults, schema and database API.
define('_JEXEC', 1);
define('JPATH_BASE', $argv[1]);
require JPATH_BASE . '/includes/defines.php';
require JPATH_LIBRARIES . '/bootstrap.php';
require JPATH_BASE . '/installation/configuration.php-dist';

$configuration = new JConfig();
$configuration->host = getenv('JOOMLA_DB_HOST');
$configuration->user = getenv('JOOMLA_DB_USER');
$configuration->password = getenv('JOOMLA_DB_PASSWORD');
$configuration->db = getenv('JOOMLA_DB_NAME');
$configuration->dbprefix = 'jt_';
$configuration->secret = 'module-target-public-site-secret';
$configuration->sitename = 'Module target Joomla';
$configuration->log_path = JPATH_BASE . '/administrator/logs';
$configuration->tmp_path = JPATH_BASE . '/tmp';
$configuration->mailonline = false;
$configuration->sendmail = '/bin/true';
$configuration->sef = false;
$configuration->sef_rewrite = false;
$configuration->error_reporting = 'none';
$source = "<?php\nclass JConfig\n{\n";
foreach (get_object_vars($configuration) as $key => $value) {
    $source .= '    public $' . $key . ' = ' . var_export($value, true) . ";\n";
}
file_put_contents(JPATH_BASE . '/configuration.php', $source . "}\n");

$database = (new Joomla\Database\DatabaseFactory())->getDriver('mysqli', [
    'host' => $configuration->host,
    'user' => $configuration->user,
    'password' => $configuration->password,
    'database' => $configuration->db,
    'prefix' => $configuration->dbprefix,
    'charset' => 'utf8mb4',
]);
foreach (['base', 'extensions', 'supports'] as $schema) {
    $path = JPATH_BASE . '/installation/sql/mysql/' . $schema . '.sql';
    foreach (Joomla\Database\DatabaseDriver::splitSql(file_get_contents($path)) as $query) {
        if (trim($query) !== '') {
            $database->setQuery($query)->execute();
        }
    }
}

$accounts = json_decode(file_get_contents('/opt/module-target/accounts.json'), true, 512, JSON_THROW_ON_ERROR);
foreach ($accounts as $username => $account) {
    $user = (object) [
        'id' => $account['id'],
        'name' => $account['name'],
        'username' => $username,
        'email' => $account['email'],
        'password' => Joomla\CMS\User\UserHelper::hashPassword($account['password']),
        'block' => 0,
        'sendEmail' => $account['group'] === 8 ? 1 : 0,
        'registerDate' => '2023-01-01 12:00:00',
        'lastvisitDate' => null,
        'activation' => '',
        'params' => '{}',
    ];
    $database->insertObject('#__users', $user);
    $membership = (object) ['user_id' => $account['id'], 'group_id' => $account['group']];
    $database->insertObject('#__user_usergroup_map', $membership);
}

// Core Basic API authentication is enabled only to prove fixed routes really work.
$database->setQuery("UPDATE #__extensions SET enabled = 1 WHERE type = 'plugin' AND folder = 'api-authentication' AND element = 'basic'")->execute();
echo json_encode(['version' => JVERSION, 'database' => $configuration->db, 'users' => array_keys($accounts)], JSON_THROW_ON_ERROR) . "\n";
