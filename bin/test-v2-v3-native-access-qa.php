<?php

declare(strict_types=1);
use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

/**
 * Native v3 AccessControl acceptance on imported synthetic QA records.
 * No requests to registered provider hosts and no application writes.
 */
$opts = getopt('', ['database:', 'socket:']);
$schema = (string) ($opts['database'] ?? '');
$socket = (string) ($opts['socket'] ?? '');
if (preg_match('/^achgw_qa_[a-z0-9_]+$/D', $schema) !== 1 || ! str_starts_with($socket, '/')) {
    throw new RuntimeException('Native access QA requires a disposable achgw_qa_* schema and local socket.');
}

putenv('APP_ENV=testing');
putenv('DB_CONNECTION=mariadb');
putenv('DB_DATABASE='.$schema);
putenv('DB_SOCKET='.$socket);
putenv('DB_USERNAME=root');
putenv('DB_HOST=localhost');
putenv('DB_PASSWORD=');
putenv('CACHE_STORE=array');
putenv('SESSION_DRIVER=array');
putenv('QUEUE_CONNECTION=sync');

require dirname(__DIR__).'/vendor/autoload.php';
$app = require dirname(__DIR__).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$connection = DB::connection();
if ($connection->getDatabaseName() !== $schema) {
    throw new RuntimeException('Laravel is not connected to the intended QA schema.');
}

$owner = User::query()->findOrFail(1);
$admin = User::query()->findOrFail(2);
$ssh = Target::query()->where('target_id', 'qa-ssh')->firstOrFail();
$wp = Target::query()->where('target_id', 'qa-wp')->firstOrFail();

$access = $app->make(AccessControl::class);
$perm = GatewayPermission::class;

function should(bool $condition, string $assertion): void
{
    if (! $condition) {
        throw new RuntimeException('NATIVE_ACCESS_QA_FAILED='.$assertion);
    }
}

should(! (bool) $admin->self_created_target_access, 'creator_scope_disabled');
should($access->allows($admin, $perm::TargetsView, $ssh), 'selected_ssh_visible');
should(! $access->allows($admin, $perm::TargetsView, $wp), 'out_of_scope_wordpress_hidden');
should(! $access->allows($admin, $perm::SshCommandRun, $ssh), 'group_deny_overrides_ssh');
should(! $access->allows($admin, $perm::TargetsRemove, $ssh), 'user_deny_overrides_target_remove');
should($access->allows($owner, $perm::TargetsView, $wp), 'fresh_owner_all_scope');
$ids = Target::query()->pipe(
    fn ($q) => $access->scopeTargets($q, $admin, $perm::TargetsView)
)->pluck('target_id')->all();
sort($ids);
should($ids === ['qa-ssh'], 'admin_target_scope_matches_selected');
echo "RESULT=NATIVE_ACCESS_QA_PASS\n";
