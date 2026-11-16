<?php
$_SERVER['HTTP_HOST'] = 'module-target.test'; $_SERVER['REQUEST_URI'] = '/'; $_SERVER['PHP_SELF'] = '/index.php'; $_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php'; require_once ABSPATH . 'wp-admin/includes/plugin.php';
$version = getenv('FILE_MANAGER_RELEASE') ?: '6.0';
$root = WP_PLUGIN_DIR . '/wp-file-manager/lib/files';
$mode = $argv[1] ?? 'snapshot';
if ($mode === 'harden') { if (!chmod($root, 0555)) { throw new RuntimeException('Native upload root hardening failed'); } echo json_encode(['hardened' => true]), "\n"; exit; }
if ($mode === 'cleanup' || $mode === 'cleanup-owned') {
    $names = ($argv[2] ?? '') === '' ? [] : explode(',', $argv[2]);
    foreach ($names as $name) { if (!preg_match($mode === 'cleanup-owned' ? '/\A[A-Za-z0-9]{6}\.php\z/' : '/\Amodule-target-file-manager-[a-z0-9_-]+\.(?:gif|txt|php)\z/', $name)) { throw new RuntimeException('Invalid owned recovery name'); } $path = $root . '/' . $name; if (is_file($path) && !unlink($path)) { throw new RuntimeException('Owned recovery failed'); } }
    if (file_exists('/tmp/module-target-file-manager-native-proof')) { unlink('/tmp/module-target-file-manager-native-proof'); }
    if ($mode === 'cleanup-owned' && file_exists('/tmp/module-target-file-manager-owner-proof')) { unlink('/tmp/module-target-file-manager-owner-proof'); }
    echo json_encode(['removed' => $names]), "\n"; exit;
}
if ($mode === 'native') {
    $name = $argv[2] ?? '';
    if (!preg_match('/\Amodule-target-file-manager-native(?:\/(?:image\.gif|text\.txt))?\z/', $name)) { throw new RuntimeException('Invalid native path'); }
    $path = ABSPATH . $name;
    echo json_encode(['exists' => file_exists($path), 'is_file' => is_file($path), 'size' => is_file($path) ? filesize($path) : null, 'sha256' => is_file($path) ? hash_file('sha256', $path) : null, 'uid' => file_exists($path) ? fileowner($path) : null]), "\n"; exit;
}
$files = [];
if (is_dir($root)) foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { $path = substr($file->getPathname(), strlen($root) + 1); $files[$path] = ['type' => $file->isDir() ? 'directory' : 'file', 'sha256' => $file->isFile() ? hash_file('sha256', $file->getPathname()) : null, 'size' => $file->isFile() ? $file->getSize() : null]; }
ksort($files); $hashes = []; $release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version] ?? ['installed_sha256' => []];
foreach ($release['installed_sha256'] as $name => $expected) { $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/wp-file-manager/' . $name); }
$user = get_user_by('login', 'module_admin');
echo json_encode(['core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'plugin_version' => ($version === 'absent' ? null : get_plugin_data(WP_PLUGIN_DIR . '/wp-file-manager/file_folder_manager.php', false, false)['Version']), 'active_plugins' => get_option('active_plugins'), 'installed_sha256' => $hashes, 'outer_sha256' => ($version === 'absent' ? null : hash_file('sha256', '/opt/module-target/plugin.zip')), 'files_root' => $root, 'files_writable' => is_writable($root), 'files' => (object) $files, 'account_hash' => hash('sha256', $user->user_pass), 'owner_proof' => file_exists('/tmp/module-target-file-manager-owner-proof') ? file_get_contents('/tmp/module-target-file-manager-owner-proof') : null, 'owner_proof_uid' => file_exists('/tmp/module-target-file-manager-owner-proof') ? fileowner('/tmp/module-target-file-manager-owner-proof') : null, 'proof' => file_exists('/tmp/module-target-file-manager-native-proof') ? file_get_contents('/tmp/module-target-file-manager-native-proof') : null], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
