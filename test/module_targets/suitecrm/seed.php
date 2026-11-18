<?php
chdir('/var/www/html');
define('sugarEntry', true);
require_once 'include/entryPoint.php';
$current_user = BeanFactory::getBean('Users', '1');
if (!$current_user || !$current_user->is_admin) {
    throw new RuntimeException('Native administrator bootstrap unavailable');
}
$account = BeanFactory::newBean('Accounts');
$account->name = 'Module Native Account';
$account->assigned_user_id = $current_user->id;
$account->save();
$user = BeanFactory::newBean('Users');
$user->user_name = 'viewer';
$user->first_name = 'Module';
$user->last_name = 'Viewer';
$user->status = 'Active';
$user->is_admin = 0;
$user->employee_status = 'Active';
// Supply a native password hash before save to select explicit-password creation
// instead of the application's form-driven GeneratePassword workflow.
$user->user_hash = User::getPasswordHash('Module-suite-viewer42!');
$user->save();
$user->setNewPassword('Module-suite-viewer42!');
echo json_encode(array('account' => $account->id, 'viewer' => $user->id, 'admin' => $current_user->id)), "\n";
