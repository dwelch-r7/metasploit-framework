<?php
define('DRUPAL_ROOT', getcwd());
define('MAINTENANCE_MODE', 'install');
$prefix = getenv('LAB_PREFIX') ?: '';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['SERVER_NAME'] = 'module-target.test';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['SERVER_SOFTWARE'] = 'Apache';
$_SERVER['REQUEST_URI'] = $prefix . '/install.php';
$_SERVER['SCRIPT_NAME'] = $prefix . '/install.php';
$_SERVER['PHP_SELF'] = $prefix . '/install.php';
require_once DRUPAL_ROOT . '/includes/install.core.inc';

// Drupal's supported noninteractive installer creates the schema, user and
// actual core forms. The standard profile enables the bundled File module,
// which owns the AJAX route used by this Drupal 7 exploit vector.
try {
install_drupal(array(
    'interactive' => FALSE,
    'parameters' => array('profile' => 'standard', 'locale' => 'en'),
    'forms' => array(
        'install_settings_form' => array(
            'driver' => 'mysql',
            'mysql' => array(
                'database' => getenv('DRUPAL_DB_NAME'),
                'username' => 'module_target',
                'password' => 'module-target-db-password',
                'host' => 'db', 'port' => '3306', 'prefix' => '',
            ),
        ),
        'install_configure_form' => array(
            'site_name' => 'Module target Drupal',
            'site_mail' => 'module-target@example.test',
            'account' => array(
                'name' => 'module_admin',
                'mail' => 'module-admin@example.test',
                'pass' => array('pass1' => 'module-target-password', 'pass2' => 'module-target-password'),
            ),
            'site_default_country' => 'GB',
            'date_default_timezone' => 'UTC',
            'clean_url' => 0,
            'update_status_module' => array(),
        ),
    ),
));
variable_set('cron_safe_threshold', 0);
variable_set('cache', 0);
variable_set('page_compression', 0);
drupal_flush_all_caches();
if (!is_dir('/tmp/module-target-drupal-drop')) {
    mkdir('/tmp/module-target-drupal-drop', 0770);
}
file_put_contents('/tmp/module-target-ready', "ready\n");
} catch (Exception $error) {
    fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . "\n" . $error->getTraceAsString() . "\n");
    fwrite(STDERR, 'Form errors: ' . json_encode(form_get_errors()) . "\n");
    exit(1);
}
