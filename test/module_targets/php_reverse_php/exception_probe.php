<?php
fwrite(STDERR, json_encode(['kind' => 'runtime', 'pid' => getmypid(), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'disabled_functions' => ini_get('disable_functions'), 'fsockopen' => function_exists('fsockopen'), 'socket_create' => function_exists('socket_create')]) . "\n");
register_shutdown_function(function () {
    $error = error_get_last();
    if ($error !== null) {
        fwrite(STDERR, json_encode(['kind' => 'shutdown_error', 'error' => $error]) . "\n");
    }
});
