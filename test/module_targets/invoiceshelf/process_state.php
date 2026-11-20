<?php
// Match h2_console/process_state.py without adding an interpreter to the victim.
// Field positions: https://docs.kernel.org/filesystems/proc.html
$port = filter_var($argv[1], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
if ($port === false) {
    throw new InvalidArgumentException('Invalid observation port');
}
$processes = [];
foreach (glob('/proc/[0-9]*') as $directory) {
    $pid = (int) basename($directory);
    if ($pid === getmypid()) {
        continue;
    }
    $stat = @file_get_contents($directory . '/stat');
    $command = @file_get_contents($directory . '/cmdline');
    $status = @file_get_contents($directory . '/status');
    if ($stat === false || $command === false || $status === false) {
        if (!is_dir($directory)) {
            continue; // A short-lived process may exit between the reads.
        }
        throw new RuntimeException('Cannot observe live process ' . $pid);
    }
    $fields = preg_split('/\s+/', trim(substr($stat, strrpos($stat, ')') + 1)));
    if (count($fields) < 20 || !preg_match('/^Uid:\s+(\d+)/m', $status, $uid)) {
        throw new RuntimeException('Invalid process metadata ' . $pid);
    }
    $processes[] = ['pid' => $pid, 'ppid' => (int) $fields[1], 'state' => $fields[0], 'birth' => $fields[19], 'uid' => $uid[1], 'command' => trim(str_replace("\0", ' ', $command))];
}
usort($processes, fn($first, $second) => $first['pid'] <=> $second['pid']);
$connections = [];
foreach (['tcp', 'tcp6'] as $name) {
    $lines = file('/proc/net/' . $name, FILE_IGNORE_NEW_LINES);
    foreach (array_slice($lines, 1) as $line) {
        $fields = preg_split('/\s+/', trim($line));
        $remote = explode(':', $fields[2]);
        if (hexdec(end($remote)) === $port && $fields[3] !== '06') {
            $connections[] = ['local' => $fields[1], 'remote' => $fields[2], 'state' => $fields[3]];
        }
    }
}
echo json_encode(['processes' => $processes, 'connections' => $connections], JSON_THROW_ON_ERROR);
