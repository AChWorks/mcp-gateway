<?php

declare(strict_types=1);

// Isolated disposable MariaDB test worker. Never run against a live database.
use App\Application\Targets\ConnectionRelayTargetBinding;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;

require dirname(__DIR__, 2).'/vendor/autoload.php';
if ($argc !== 4 || getenv('APP_ENV') !== 'testing'
    || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', (string) getenv('DB_DATABASE')) !== 1) {
    fwrite(STDERR, "Refusing Relay concurrency worker without an isolated test database.\n");
    exit(2);
}
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(ConsoleKernel::class)->bootstrap();

DB::connection()->beforeExecuting(static function (string $sql) use ($argv): void {
    if (str_contains(strtolower($sql), 'for update')
        && str_contains(strtolower($sql), 'connection_relays')) {
        touch($argv[3]);
    }
});
try {
    $target = Target::query()->where('target_id', $argv[1])->firstOrFail();
    $result = $app->make(ConnectionRelayTargetBinding::class)->change(
        $target, $argv[2], 'race-iran',
    );
    echo json_encode(['status' => $result ? 'bound' : 'unchanged'], JSON_THROW_ON_ERROR);
} catch (ConnectionRelayUnavailable) {
    echo json_encode(['status' => 'blocked', 'reason' => 'relay_unavailable'], JSON_THROW_ON_ERROR);
} catch (TargetConnectorFailure $exception) {
    echo json_encode(['status' => 'blocked', 'reason' => $exception->field], JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    echo json_encode(['status' => 'unexpected', 'class' => $exception::class], JSON_THROW_ON_ERROR);
}
