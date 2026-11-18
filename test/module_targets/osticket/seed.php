<?php
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$root = '/var/www/html' . getenv('LAB_PREFIX');
chdir($root);
$_SERVER += ['HTTP_HOST' => $input['authority'], 'REMOTE_ADDR' => '127.0.0.1', 'SERVER_PORT' => 80, 'REQUEST_METHOD' => 'GET', 'SCRIPT_NAME' => '/module-target-native-seed.php', 'REQUEST_URI' => '/'];
require 'main.inc.php';
$online = $cfg->isOnline();
if (!$online && !$cfg->update('isonline', 1)) {
    throw new RuntimeException('Could not enable ordinary helpdesk access');
}
$user = User::fromVars(['name' => 'Module Target Client', 'email' => $input['client_email']]);
if (!$user) {
    throw new RuntimeException('Native user creation failed');
}
$errors = [];
$account = UserAccount::register($user, ['backend' => '', 'timezone' => 'UTC', 'passwd1' => $input['password'], 'passwd2' => $input['password']], $errors);
if (!$account || $errors || !$account->isConfirmed()) {
    throw new RuntimeException('Native account creation failed: ' . json_encode($errors));
}
$errors = [];
$ticket = Ticket::create(['source' => 'Web', 'email' => $input['client_email'], 'name' => 'Module Target Client', 'uid' => $user->getId(), 'topicId' => 1, 'subject' => 'Module target native ticket', 'message' => 'NATIVE_OSTICKET_BASELINE_MARKER'], $errors, 'api', false, false);
if (!$ticket) {
    throw new RuntimeException('Native ticket creation failed: ' . json_encode($errors));
}
echo 'OSTICKET_NATIVE_JSON=' . json_encode(['root' => $root, 'uid' => posix_geteuid(), 'user_id' => $user->getId(), 'account_confirmed' => $account->isConfirmed(), 'ticket_id' => $ticket->getId(), 'ticket_number' => $ticket->getNumber(), 'online_before' => $online, 'richtext' => $cfg->isRichTextEnabled(), 'php' => PHP_VERSION, 'version' => THIS_VERSION]) . "\n";
