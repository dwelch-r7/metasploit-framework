<?php
ob_start();
require '/opt/module-target/control-base.php';
$identity = json_decode(ob_get_clean(), true, 512, JSON_THROW_ON_ERROR);
$identity['file_modifications_disabled'] = defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS;
$identity['bash_executable'] = is_executable('/bin/bash');
$root = WP_PLUGIN_DIR;
$entries = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) {
    $path = substr($file->getPathname(), strlen($root) + 1);
    $entries[$path] = $file->isDir() ? 'directory' : hash_file('sha256', $file->getPathname());
}
ksort($entries);
$identity['plugin_entries'] = $entries;
echo json_encode($identity, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
