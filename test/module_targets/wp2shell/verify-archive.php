<?php
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR);
$release = $catalog[getenv('WORDPRESS_CORE_RELEASE')];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/core.tar.gz'))) { throw new RuntimeException('Core archive differs'); }
