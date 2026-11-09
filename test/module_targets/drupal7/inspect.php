<?php
chdir('/var/www/html' . (getenv('LAB_PREFIX') ?: ''));
define('DRUPAL_ROOT', getcwd());
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['SERVER_NAME'] = 'module-target.test';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['SCRIPT_NAME'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['PHP_SELF'] = $_SERVER['SCRIPT_NAME'];
require_once DRUPAL_ROOT . '/includes/bootstrap.inc';
drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
$account = user_load(1);
echo json_encode(array(
    'version' => VERSION, 'php' => PHP_VERSION,
    'uid' => posix_geteuid(), 'account' => posix_getpwuid(posix_geteuid())['name'],
    'root' => DRUPAL_ROOT, 'base_path' => base_path(),
    'profile' => variable_get('install_profile'),
    'modules' => array_keys(module_list()),
    'database_driver' => Database::getConnection()->driver(),
    'admin' => array('name' => $account->name, 'active' => $account->status),
    'assert_active' => (bool) ini_get('assert.active'),
    'source_bootstrap_sha256' => hash_file('sha256', DRUPAL_ROOT . '/includes/bootstrap.inc'),
    'request_sanitizer' => file_exists(DRUPAL_ROOT . '/includes/request-sanitizer.inc'),
    'changelog' => file_exists(DRUPAL_ROOT . '/CHANGELOG.txt'),
    'root_writable' => is_writable(DRUPAL_ROOT),
    'temporary_directory' => file_directory_temp(),
    'clean_url' => variable_get('clean_url'),
    'cron_safe_threshold' => variable_get('cron_safe_threshold'),
), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
