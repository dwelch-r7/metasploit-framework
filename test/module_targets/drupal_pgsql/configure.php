<?php
require '/opt/module-target/bootstrap.php';

Drupal::currentUser()->setAccount(Drupal\user\Entity\User::load(1));
if (getenv('DRUPAL_MODE') !== 'disabled') {
  Drupal::service('module_installer')->install(['jsonapi']);
}
// Keep unrelated scheduled network work outside the timing controls.
Drupal::configFactory()->getEditable('automated_cron.settings')->set('interval', 0)->save();
Drupal::configFactory()->getEditable('system.performance')
  ->set('css.preprocess', false)->set('js.preprocess', false)->save();
foreach (['field_module_marker' => false, 'field_case_marker' => true] as $name => $sensitive) {
  $storage = Drupal\field\Entity\FieldStorageConfig::create([
    'field_name' => $name,
    'entity_type' => 'node',
    'type' => 'string',
    'settings' => ['max_length' => 255, 'case_sensitive' => $sensitive],
  ]);
  $storage->save();
  Drupal\field\Entity\FieldConfig::create([
    'field_storage' => $storage,
    'bundle' => 'article',
    'label' => $name,
  ])->save();
}
if (getenv('DRUPAL_MODE') !== 'empty') {
  $node = Drupal\node\Entity\Node::create([
    'type' => 'article',
    'title' => 'Module native café article',
    'status' => true,
    'uid' => 1,
    'field_module_marker' => 'Module native marker',
    'field_case_marker' => 'Module case marker',
  ]);
  $node->save();
}
if (getenv('DRUPAL_MODE') === 'private') {
  $role = Drupal\user\Entity\Role::load('anonymous');
  $role->revokePermission('access content')->save();
}
Drupal::service('router.builder')->rebuild();
$created = isset($node)
  ? ['node_id' => (int)$node->id(), 'node_uuid' => $node->uuid(), 'node_title' => $node->label()]
  : null;
file_put_contents('/tmp/module-target-drupal-native.json', json_encode($created));
echo "Genuine JSON:API and Node entity configuration completed\n";
