<?php
// Reuse the existing procfs observer; add socket identity without POSIX support.
ob_start();
require '/opt/module-target-common-process.php';
$state = json_decode(ob_get_clean(), true, 512, JSON_THROW_ON_ERROR);
$all = [];
foreach (['tcp', 'tcp6'] as $name) {
    foreach (array_slice(file('/proc/net/' . $name, FILE_IGNORE_NEW_LINES), 1) as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if ($fields[3] === '06') {
            continue; // TIME_WAIT has no live payload socket.
        }
        $all[] = ['local' => $fields[1], 'remote' => $fields[2], 'state' => $fields[3], 'uid' => (int) $fields[7], 'inode' => $fields[9]];
    }
}
$state['tcp'] = $all;
$state['connections'] = array_values(array_filter($all, function ($row) use ($port) {
    $remote = explode(':', $row['remote']);
    return hexdec(end($remote)) === $port;
}));
echo json_encode($state, JSON_THROW_ON_ERROR);
