<?php
$token = $argv[1];
$port = filter_var($argv[2], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
if (!preg_match('/\A[a-zA-Z0-9-]+\z/', $token) || $port === false) {
    throw new InvalidArgumentException('Invalid callback arguments');
}
$proof = '/tmp/module-target-projectsend-callback-' . getmypid();
$host = gethostbyname('host.docker.internal');
$socket = stream_socket_client('tcp://' . $host . ':' . $port, $errno, $message, 5);
if ($socket === false) {
    throw new RuntimeException('Callback failed: ' . $message);
}
try {
    if (file_exists($proof) || file_put_contents($proof, $token) !== strlen($token)) {
        throw new RuntimeException('Cannot create callback proof');
    }
    $identity = ['token' => $token, 'uid' => fileowner($proof), 'pid' => getmypid(), 'host' => $host];
    stream_set_timeout($socket, 8);
    fwrite($socket, json_encode($identity, JSON_THROW_ON_ERROR) . "\n");
    if (trim(fgets($socket)) !== 'ACK:' . $token) {
        throw new RuntimeException('Unexpected callback acknowledgment');
    }
    echo json_encode($identity, JSON_THROW_ON_ERROR);
} finally {
    fclose($socket);
    if (file_exists($proof)) {
        unlink($proof);
    }
}
