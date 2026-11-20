<?php
require '/var/www/app/vendor/autoload.php';
require '/opt/module-target-laravel-gadget.php';
$app = require '/var/www/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$encrypter = app('encrypter');

if ($argv[1] === 'verify') {
    $vendor = json_decode(file_get_contents('/opt/module-target-vendor.json'), true, 512, JSON_THROW_ON_ERROR);
    $hashes = [];
    foreach ($vendor['source_sha256'] as $name => $expected) {
        $hashes[$name] = hash_file('sha256', $name);
        if (!hash_equals($expected, $hashes[$name])) {
            throw new RuntimeException('Vendor source mismatch: ' . $name);
        }
    }
    $routes = [];
    foreach (app('router')->getRoutes() as $route) {
        $routes[] = $route->uri();
    }
    echo json_encode([
        'php' => PHP_VERSION, 'laravel' => $app->version(), 'uid' => posix_geteuid(),
        'database' => config('database.default'), 'users' => App\Models\User::count(),
        'companies' => App\Models\Company::count(), 'timezones' => App\Models\Timezone::count(),
        'clients' => App\Models\Client::count(), 'invoices' => App\Models\Invoice::count(),
        'driver' => config('session.driver'), 'cookie' => config('session.cookie'),
        'route_registered' => in_array('route/{hash}', $routes, true), 'route_count' => count($routes),
        'source_sha256' => $hashes,
    ], JSON_THROW_ON_ERROR);
} elseif ($argv[1] === 'cookie') {
    $plain = $encrypter->decryptString(rawurldecode($input['value']));
    $prefix = Illuminate\Cookie\CookieValuePrefix::create($input['name'], $encrypter->getKey());
    echo json_encode(['prefix_valid' => str_starts_with($plain, $prefix), 'value' => substr($plain, strlen($prefix))], JSON_THROW_ON_ERROR);
} elseif ($argv[1] === 'gadget') {
    $command = base64_decode($input['command_base64'], true);
    if ($command === false || !str_contains($command, '/tmp/module-target-invoiceninja-')) {
        throw new InvalidArgumentException('Native proof must use its controlled path');
    }
    if (isset($input['key'])) {
        $encrypter = new Illuminate\Encryption\Encrypter(base64_decode($input['key'], true), 'AES-256-CBC');
    }
    $serialized = module_target_laravel_command($command);
    echo json_encode(['value' => rawurlencode($encrypter->encryptString($serialized)), 'serialized_base64' => base64_encode($serialized)], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unexpected native mode');
}
