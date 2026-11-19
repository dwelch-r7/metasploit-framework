<?php
header('Content-Type: application/json');
ini_set('default_socket_timeout', '3');
$result = ['sapi' => PHP_SAPI, 'register_argc_argv' => ini_get('register_argc_argv'), 'argv' => $_SERVER['argv'] ?? null, 'wrappers' => stream_get_wrappers()];
if (isset($_GET['url'])) {
    $bytes = @file_get_contents($_GET['url']);
    $result['body_base64'] = $bytes === false ? null : base64_encode($bytes);
    $result['error'] = error_get_last();
}
echo json_encode($result);
