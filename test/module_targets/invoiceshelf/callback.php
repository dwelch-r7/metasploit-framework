<?php
$host = gethostbyname('host.docker.internal');
$socket = stream_socket_client('tcp://' . $host . ':4492', $code, $message, 5);
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
