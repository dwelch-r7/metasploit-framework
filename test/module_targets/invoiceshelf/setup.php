<?php
require '/opt/InvoiceShelf/vendor/autoload.php';
$app = require '/opt/InvoiceShelf/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
InvoiceShelf\Models\Setting::setSetting('profile_complete', 'COMPLETED');
if (!InvoiceShelf\Space\InstallUtils::createDbMarker()) {
    throw new RuntimeException('Failed to create the native installation marker');
}
echo json_encode([
    'laravel' => $app->version(),
    'session' => config('session.driver'),
    'cookie_name' => app('session')->driver()->getName(),
    'database' => config('database.default'),
    'users' => InvoiceShelf\Models\User::count(),
    'companies' => InvoiceShelf\Models\Company::count(),
    'uid' => posix_geteuid(),
], JSON_THROW_ON_ERROR) . "\n";
