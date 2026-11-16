<?php
const MODULE_TARGET_ROOT = '/var/www/module-target-drupal';
chdir(MODULE_TARGET_ROOT);
$loader = require MODULE_TARGET_ROOT . '/autoload.php';
$request = Symfony\Component\HttpFoundation\Request::create('http://module-target.test/');
$kernel = Drupal\Core\DrupalKernel::createFromRequest($request, $loader, 'prod');
$kernel->boot();
$kernel->preHandle($request);
