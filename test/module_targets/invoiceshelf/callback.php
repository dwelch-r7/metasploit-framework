<?php
$host = gethostbyname('host.docker.internal');
$port = filter_var($argv[2], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
if ($port === false) {
    throw new InvalidArgumentException('Invalid callback port');
}
$socket = stream_socket_client('tcp://' . $host . ':' . $port, $code, $message, 5);
if ($socket === false) {
    throw new RuntimeException('Callback failed: ' . $message);
}
stream_set_timeout($socket, 10);
$identity = ['host' => $host, 'pid' => getmypid(), 'ppid' => posix_getppid(), 'uid' => posix_geteuid(), 'token' => $argv[1]];
fwrite($socket, json_encode($identity, JSON_THROW_ON_ERROR) . "\n");
$reply = fgets($socket);
fclose($socket);
if ($reply !== 'ACK:' . $argv[1] . "\n") {
    throw new RuntimeException('Wrong callback acknowledgement');
}
echo json_encode($identity, JSON_THROW_ON_ERROR);
