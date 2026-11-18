<?php
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
chdir('/var/www/html' . getenv('LAB_PREFIX'));
$_SERVER += ['HTTP_HOST' => $input['authority'], 'REMOTE_ADDR' => '127.0.0.1', 'SERVER_PORT' => 80, 'REQUEST_METHOD' => 'GET', 'SCRIPT_NAME' => '/module-target-control.php', 'REQUEST_URI' => '/'];
require 'main.inc.php';
$action = $input['action'];
if ($action === 'ticket') {
    $errors = [];
    $user = User::lookupByEmail($input['client_email']);
    $ticket = Ticket::create(['source' => 'Web', 'email' => $input['client_email'], 'name' => 'Module Target Client', 'uid' => $user->getId(), 'topicId' => 1, 'subject' => 'MCV osTicket case', 'message' => 'NATIVE_OSTICKET_BASELINE_MARKER'], $errors, 'api', false, false);
    if (!$ticket) {
        throw new RuntimeException('Native ticket creation failed: ' . json_encode($errors));
    }
    echo json_encode(['ticket_id' => $ticket->getId(), 'ticket_number' => $ticket->getNumber()]);
} elseif ($action === 'delete') {
    foreach ($input['ids'] as $id) {
        $ticket = Ticket::lookup($id);
        if (!$ticket || !in_array($ticket->getSubject(), ['MCV osTicket case', 'Module target native ticket'])) {
            throw new RuntimeException('Refusing to remove a ticket outside the lab fixture');
        }
        if (!$ticket->delete('Removing this run\'s disposable test ticket')) {
            throw new RuntimeException('Native ticket removal failed');
        }
    }
    echo json_encode(['deleted' => $input['ids']]);
} elseif ($action === 'fixtures') {
    $fixtures = [
        '/tmp/module-target-osticket-native-canary.txt' => file_get_contents('/tmp/module-target-osticket-native-canary.txt'),
        '/tmp/module-target-osticket-ascii.txt' => "File: osTicket exact ASCII fixture!\nSecond line.\n",
        '/tmp/module-target-osticket-binary.bin' => "Binary:\x00\x01\x02\x1b\x7f\x80\xff;\r\nUTF8: caf\xc3\xa9\n" . str_repeat('module-target binary padding! ', 8),
        '/tmp/module-target-osticket-plain.txt' => "root:x:0:0:module-target:/root:/bin/bash\n" . str_repeat("module-target:plain:punctuation!\n", 20),
    ];
    $result = [];
    foreach ($fixtures as $path => $bytes) {
        if (file_put_contents($path, $bytes) !== strlen($bytes)) {
            throw new RuntimeException('Native file fixture creation failed');
        }
        $result[$path] = ['base64' => base64_encode(file_get_contents($path)), 'uid' => fileowner($path)];
    }
    echo json_encode($result);
} elseif ($action === 'state') {
    $tickets = [];
    foreach (Ticket::objects() as $ticket) {
        $tickets[] = ['ticket_id' => $ticket->getId(), 'ticket_number' => $ticket->getNumber(), 'subject' => $ticket->getSubject(), 'entries' => $ticket->getThreadCount()];
    }
    $root = '/opt/osticket/source/upload/';
    $mismatches = [];
    $files = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files++;
            $relative = substr($file->getPathname(), strlen($root));
            if (hash_file('sha256', $file->getPathname()) !== hash_file('sha256', getcwd() . '/' . $relative)) {
                $mismatches[] = $relative;
            }
        }
    }
    echo json_encode(['tickets' => $tickets, 'vendor_files' => $files, 'vendor_mismatches' => $mismatches, 'version' => THIS_VERSION, 'uid' => posix_geteuid(), 'config_base64' => base64_encode(file_get_contents('include/ost-config.php'))]);
} else {
    throw new InvalidArgumentException('Unknown native control action');
}
