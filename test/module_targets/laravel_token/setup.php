<?php
$settings = ['APP_ENV' => 'local', 'APP_DEBUG' => getenv('APP_DEBUG') ?: 'true', 'APP_KEY' => getenv('APP_KEY')];
if (!in_array($settings['APP_DEBUG'], ['true', 'false'], true) || strpos($settings['APP_KEY'], 'base64:') !== 0 || strlen(base64_decode(substr($settings['APP_KEY'], 7), true)) !== 32) {
    throw new InvalidArgumentException('Expected explicit laboratory configuration');
}
$contents = file_get_contents('/var/www/.env.example');
foreach ($settings as $name => $value) {
    $contents = preg_replace_callback('/^' . preg_quote($name, '/') . '=.*$/m', static function () use ($name, $value) { return $name . '=' . $value; }, $contents);
}
file_put_contents('/var/www/.env', $contents);
if (getenv('EXPOSE_ENV') === 'true') {
    copy('/var/www/.env', '/var/www/public/.env');
}
