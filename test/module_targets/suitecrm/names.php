<?php
chdir('/var/www/html');
define('sugarEntry', true);
require_once 'include/entryPoint.php';
$current_user = BeanFactory::getBean('Users', '1');
$seed = json_decode(file_get_contents('/tmp/module-target-seed.json'), true);
$user = BeanFactory::getBean('Users', $seed['viewer']);
if (!$current_user || !$current_user->is_admin || !$user || $user->is_admin) {
    throw new RuntimeException('Native user identities do not match the names fixture');
}
// Bean fields follow native HTML-encoded input; DBManager decodes before save.
$fixture = json_decode(file_get_contents('/opt/module-target/names.json'), true);
$user->user_name = to_html($fixture['username']);
$user->save();
echo json_encode(array('id' => $user->id, 'user_name' => from_html($user->user_name), 'is_admin' => $user->is_admin)), "\n";
