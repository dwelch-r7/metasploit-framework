<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH.'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login','module_admin')->ID);
if (!WP_Filesystem() || posix_geteuid() !== 33) { throw new RuntimeException('Native filesystem identity differs'); }
$release = json_decode(file_get_contents('/opt/module-target/releases.json'),true,512,JSON_THROW_ON_ERROR)[getenv('SURE_RELEASE')];
$archive = '/opt/module-target/plugin.zip';
if (!hash_equals($release['sha256'],hash_file('sha256',$archive))) { throw new RuntimeException('Native archive differs'); }
$result = unzip_file($archive,WP_PLUGIN_DIR.'/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
foreach ($release['installed_sha256'] as $path=>$digest) {
    $installed = WP_PLUGIN_DIR.'/suretriggers/'.$path;
    if (!is_file($installed) || !hash_equals($digest,hash_file('sha256',$installed))) { throw new RuntimeException('Installed source differs: '.$path); }
}
echo "Native archive extracted and verified\n";
