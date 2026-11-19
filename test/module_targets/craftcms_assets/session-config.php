<?php
require '/app/bootstrap.php';
$app = require CRAFT_VENDOR_PATH . '/craftcms/cms/bootstrap/web.php';
$session = $app->getSession();
header('Content-Type: application/json');
echo json_encode([
    'sapi' => PHP_SAPI,
    'php_version' => PHP_VERSION,
    'uid' => posix_geteuid(),
    'class' => get_class($session),
    'name' => $session->getName(),
    'component_path' => $session->getSavePath(),
    'ini_path' => ini_get('session.save_path'),
    'handler' => ini_get('session.save_handler'),
    'serialize_handler' => ini_get('session.serialize_handler'),
    'temporary_directory' => sys_get_temp_dir(),
    'session_status' => session_status(),
    'session_id' => session_id(),
]);
