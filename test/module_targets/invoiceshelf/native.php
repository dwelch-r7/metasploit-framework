<?php
require '/opt/InvoiceShelf/vendor/autoload.php';
require '/opt/module-target-laravel-gadget.php';
$app = require '/opt/InvoiceShelf/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$mode = $argv[1];
$encrypter = app('encrypter');

if ($mode === 'verify') {
    $store = app('session')->driver();
    $serialization = new ReflectionProperty($store, 'serialization');
    $checker = new InvoiceShelf\Space\RequirementsChecker();
    $vendor = json_decode(file_get_contents('/opt/module-target-vendor.json'), true, 512, JSON_THROW_ON_ERROR);
    $hashes = [];
    foreach ($vendor['source_sha256'] as $name => $expected) {
        $hashes[$name] = hash_file('sha256', '/opt/InvoiceShelf/' . $name);
        if (!hash_equals($expected, $hashes[$name])) {
            throw new RuntimeException('Vendor source mismatch: ' . $name);
        }
    }
    echo json_encode([
        'php' => PHP_VERSION, 'laravel' => $app->version(), 'uid' => posix_geteuid(),
        'driver' => config('session.driver'), 'cookie' => config('session.cookie'),
        'serialization' => $serialization->getValue($store), 'handler' => get_class($store->getHandler()),
        'database' => config('database.default'), 'users' => InvoiceShelf\Models\User::count(),
        'companies' => InvoiceShelf\Models\Company::count(), 'invoices' => InvoiceShelf\Models\Invoice::count(),
        'requirements' => $checker->check(config('installer.requirements')),
        'php_supported' => $checker->checkPHPVersion(config('installer.core.minPhpVersion'))['supported'],
        'sqlite' => $checker->checkSqliteVersion(config('invoiceshelf.min_sqlite_version')),
        'source_sha256' => $hashes,
    ], JSON_THROW_ON_ERROR);
} elseif ($mode === 'cookie') {
    $name = $input['name'];
    $plain = $encrypter->decryptString(rawurldecode($input['value']));
    $prefix = Illuminate\Cookie\CookieValuePrefix::create($name, $encrypter->getKey());
    echo json_encode(['name' => $name, 'prefix_valid' => str_starts_with($plain, $prefix), 'value' => substr($plain, strlen($prefix))], JSON_THROW_ON_ERROR);
} elseif ($mode === 'gadget') {
    $command = base64_decode($input['command_base64'], true);
    if ($command === false || !str_contains($command, '/tmp/module-target-invoiceshelf-')) {
        throw new InvalidArgumentException('Native proof command must use its controlled path');
    }
    $serialized = module_target_laravel_command($command);
    if (isset($input['key'])) {
        $encrypter = new Illuminate\Encryption\Encrypter(base64_decode($input['key'], true), 'AES-256-CBC');
    }
    $prefix = Illuminate\Cookie\CookieValuePrefix::create($input['name'], $encrypter->getKey());
    $value = $prefix . json_encode(['data' => $serialized, 'expires' => time() + 300], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    echo json_encode(['value' => rawurlencode($encrypter->encryptString($value)), 'serialized_base64' => base64_encode($serialized)], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unknown native mode');
}
