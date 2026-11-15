<?php
error_reporting(E_ALL);
$started = microtime(true);
$fixture = json_decode(file_get_contents('/probe/cases.json'), true, 512, JSON_THROW_ON_ERROR);
$methods = $fixture['execution_methods'];
$cases = $fixture['cases'];
$request = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$code = base64_decode($request['payload_base64'], true);
if ($code === false || hash('sha256', $code) !== $request['source_identity']['payload_sha256']) {
    throw new RuntimeException('Generated payload bytes differ from source identity');
}
if (PHP_VERSION !== '8.3.28' || !extension_loaded('sockets') || !function_exists('fsockopen')) {
    throw new RuntimeException('Required PHP 8.3.28 socket capabilities unavailable');
}
$case_root = '/tmp/php-reverse-' . bin2hex(random_bytes(8));
mkdir($case_root, 0700);
$payload = $case_root . '/payload.php';
file_put_contents($payload, $code);
function counters() {
    $result = [];
    foreach (['memory.events', 'pids.events'] as $file) {
        if (!is_readable('/sys/fs/cgroup/' . $file)) {
            $result[$file] = null;
            continue;
        }
        $text = file_get_contents('/sys/fs/cgroup/' . $file);
        foreach (explode("\n", trim($text)) as $line) {
            if (!preg_match('/^([a-z_]+) ([0-9]+)$/D', $line, $match)) {
                throw new RuntimeException('Malformed resource counter: ' . $file);
            }
            $result[$file][$match[1]] = (int)$match[2];
        }
    }
    return $result;
}
function receive_bytes($socket, $length, $seconds) {
    $output = '';
    $deadline = microtime(true) + $seconds;
    while (strlen($output) < $length && microtime(true) < $deadline && !feof($socket)) {
        $read = [$socket];
        $write = null;
        $except = null;
        if (stream_select($read, $write, $except, 0, 50000) > 0) {
            $data = fread($socket, max(1, $length - strlen($output)));
            if ($data === false || $data === '') {
                break;
            }
            $output .= $data;
        }
    }
    return $output;
}
if (!is_executable('/probe/bin/0')) { throw new RuntimeException('Readonly command-zero source is not executable'); }
$evidence = ['command_zero_mode' => decoct(fileperms('/probe/bin/0') & 0777), 'php' => PHP_VERSION, 'php_binary_sha256' => hash_file('sha256', PHP_BINARY), 'sockets_extension' => extension_loaded('sockets'), 'before' => counters(), 'cases' => [], 'source_sha256' => hash_file('sha256', $payload)];
$evidence['source_identity'] = $request['source_identity'];
$evidence['source_files_sha256'] = [];
foreach (['controller.php', 'exception_probe.php', 'cases.json', 'bin/0'] as $file) {
    $evidence['source_files_sha256'][$file] = hash_file('sha256', '/probe/' . $file);
}
echo json_encode(['kind' => 'preflight', 'data' => $evidence]) . "\n";
flush();
$failed = 0;
foreach ($cases as $index => $case) {
    if (microtime(true) - $started > 50) { throw new RuntimeException('Whole native probe deadline'); }
    $record = $case + ['steps' => [], 'errors' => []];
    $directory = $case_root . '/case-' . $index;
    mkdir($directory, 0700);
    $server = stream_socket_server('tcp://' . $fixture['callback']['host'] . ':' . $fixture['callback']['port'], $errno, $error);
    if (!$server) { throw new RuntimeException("Listener failed: $error"); }
    $disabled = isset($case['method']) ? array_values(array_diff($methods, [$case['method']])) : [];
    if ($case['transport'] === 'socket') { $disabled[] = 'fsockopen'; }
    $argv = [PHP_BINARY, '-d', 'auto_prepend_file=/probe/exception_probe.php', '-d', 'zend.exception_ignore_args=0', '-d', 'disable_functions=' . implode(',', $disabled), $payload];
    $process = proc_open($argv, [['file', '/dev/null', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, $directory, array_merge(getenv(), ['PATH' => '/probe/bin:' . getenv('PATH')]));
    $state = proc_get_status($process);
    $record['pid'] = $state['pid'];
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $socket = @stream_socket_accept($server, 3);
    if (!$socket) {
        $record['errors'][] = 'Generated payload did not connect';
    } else {
        stream_set_blocking($socket, false);
        if ($case['transport'] === 'socket') {
            $record['banner_base64'] = base64_encode(receive_bytes($socket, strlen('socket_create'), 1));
            if (base64_decode($record['banner_base64']) !== 'socket_create') { $record['errors'][] = 'Missing genuine socket fallback banner'; }
        }
        if (array_key_exists('probe', $case)) {
            $written = $case['probe'] === '' ? 0 : @fwrite($socket, $case['probe']);
            $unexpected = receive_bytes($socket, 1, 0.2);
            $record['probe_observation'] = ['sent_base64' => base64_encode($case['probe']), 'written' => $written, 'unexpected_base64' => base64_encode($unexpected), 'eof_before_command' => feof($socket)];
        }
        $steps = [
            ["printf '%s\\n' 'ordinary-command'\n", "ordinary-command\n"],
            ["printf '%s\\n' 'café-雪'\n", "café-雪\n"],
            ["  printf '%s\\n' '  padded  '  \n", ($case['method'] ?? $fixture['default_execution_method']) === 'exec' ? "  padded\n" : "  padded  \n"],
            ["printf 'compound-'; printf 'command\\n'\n", "compound-command\n"],
            ["0\n", "zero-command\n"]
        ];
        foreach ($steps as [$command, $expected]) {
            $written = @fwrite($socket, $command);
            $actual = receive_bytes($socket, strlen($expected), 1);
            $record['steps'][] = ['input_base64' => base64_encode($command), 'written' => $written, 'expected_base64' => base64_encode($expected), 'actual_base64' => base64_encode($actual), 'matches' => $actual === $expected];
            if ($actual !== $expected) { $record['errors'][] = 'Command output mismatch'; break; }
        }
        if (!$record['errors']) {
            @fwrite($socket, 'cd /tmp' . "\n");
            usleep(20000);
            @fwrite($socket, "pwd\n");
            $actual = receive_bytes($socket, strlen("/tmp\n"), 1);
            $record['cwd_base64'] = base64_encode($actual);
            if ($actual !== "/tmp\n") { $record['errors'][] = 'Directory change differs'; }
        }
        if (($case['ending'] ?? 'exit') !== 'eof') { @fwrite($socket, ($case['ending'] ?? 'exit') . "\n"); }
        fclose($socket);
    }
    fclose($server);
    $deadline = microtime(true) + 1;
    do {
        $state = proc_get_status($process);
        if (!$state['running']) {
            break;
        }
        usleep(10000);
    } while (microtime(true) < $deadline);
    if ($state['running']) { proc_terminate($process); $record['errors'][] = 'Payload did not exit promptly'; }
    $record['stdout_base64'] = base64_encode(stream_get_contents($pipes[1]));
    $record['stderr_base64'] = base64_encode(stream_get_contents($pipes[2]));
    fclose($pipes[1]);
    fclose($pipes[2]);
    $closed = proc_close($process);
    $record['exitstatus'] = $closed === -1 ? $state['exitcode'] : $closed;
    $record['reaped'] = !file_exists('/proc/' . $record['pid']);
    if ($record['exitstatus'] !== 0 || !$record['reaped']) { $record['errors'][] = 'Payload exit/reaping differs'; }
    if ($record['errors']) { $failed++; }
    rmdir($directory);
    $evidence['cases'][] = $record;
    echo json_encode(['kind' => 'case', 'data' => $record]) . "\n";
    flush();
}
$evidence['after'] = counters();
$evidence['temporary_files_removed'] = unlink($payload) && rmdir($case_root);
$evidence['failures'] = $failed;
$evidence['elapsed_seconds'] = microtime(true) - $started;
$evidence['complete_transports'] = count(array_unique(array_column($evidence['cases'], 'transport'))) === 2;
echo json_encode(['kind' => 'final', 'data' => $evidence]) . "\n";
exit($failed || !$evidence['complete_transports'] ? 1 : 0);
