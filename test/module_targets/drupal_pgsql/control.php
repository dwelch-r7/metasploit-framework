<?php
require '/opt/module-target/bootstrap.php';

$database = Drupal::database();
$is_pgsql = $database->driver() === 'pgsql';
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[getenv('DRUPAL_RELEASE')];
$hashes = [];
foreach ($catalog['critical_sha256'] as $name => $expected) {
  $hashes[$name] = hash_file('sha256', DRUPAL_ROOT . '/' . $name);
}
$fields = [];
foreach (['field_module_marker', 'field_case_marker'] as $name) {
  $fields[$name] = Drupal\field\Entity\FieldStorageConfig::loadByName('node', $name)->getSettings();
}
$nodes = [];
foreach (Drupal::entityTypeManager()->getStorage('node')->loadMultiple() as $node) {
  $nodes[] = [
    'id' => (int)$node->id(),
    'uuid' => $node->uuid(),
    'title' => $node->label(),
    'status' => $node->isPublished(),
    'type' => $node->bundle(),
    'marker' => $node->get('field_module_marker')->value,
    'case_marker' => $node->get('field_case_marker')->value,
  ];
}
$users = [];
foreach (Drupal::entityTypeManager()->getStorage('user')->loadMultiple() as $user) {
  $users[] = [
    'uid' => (int)$user->id(),
    'name' => $user->getAccountName(),
    'pass' => $user->getPassword(),
    'active' => $user->isActive(),
  ];
}
echo json_encode([
  'mode' => getenv('DRUPAL_MODE'),
  'prefix' => getenv('LAB_PREFIX'),
  'anonymous_access_content' => Drupal\user\Entity\Role::load('anonymous')->hasPermission('access content'),
  'drupal' => Drupal::VERSION,
  'php' => PHP_VERSION,
  'uid' => posix_geteuid(),
  'driver' => $database->driver(),
  'connection_class' => get_class($database),
  'server' => $database->query('select version()')->fetchField(),
  'database_role' => $database->query($is_pgsql ? 'select current_user' : 'select current_user()')->fetchField(),
  'database_role_superuser' => $is_pgsql
    ? in_array($database->query('select usesuper from pg_user where usename=current_user')->fetchField(), [true, 1, '1', 't'], true)
    : null,
  'database_grants' => $is_pgsql ? null : $database->query('SHOW GRANTS FOR CURRENT_USER')->fetchCol(),
  'installed_modules' => array_keys(Drupal::moduleHandler()->getModuleList()),
  'archive_sha256' => hash_file('sha256', '/opt/module-target/drupal.tar.gz'),
  'critical_sha256' => $hashes,
  'fields' => $fields,
  'nodes' => $nodes,
  'users' => $users,
  'native_created' => json_decode(file_get_contents('/tmp/module-target-drupal-native.json'), true),
], JSON_PRETTY_PRINT), "\n";
