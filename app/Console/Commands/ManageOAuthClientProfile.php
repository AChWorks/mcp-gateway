<?php

namespace App\Console\Commands;

use App\Infrastructure\OAuth\ClientProfileRegistry;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Throwable;

final class ManageOAuthClientProfile extends Command
{
    protected $signature = 'gateway:oauth-client-profile
        {operation : check, list, register, disable, enable, or retire}
        {key? : Exact immutable profile key}
        {--confirm : Explicitly acknowledge profile activation, revocation, or DCR retirement}';

    protected $description = 'Inspect or explicitly change the durable OAuth client profile lifecycle';

    public function handle(ClientProfileRegistry $registry): int
    {
        $operation = (string) $this->argument('operation');
        $key = $this->argument('key');

        if ($operation === 'check') {
            if ($key !== null) {
                $this->error('The check operation does not accept a profile key.');

                return self::FAILURE;
            }

            try {
                $registry->assertReady();
                $this->info('OAuth client profile registry is ready.');

                return self::SUCCESS;
            } catch (Throwable $exception) {
                $this->error('OAuth client profile readiness failed: '.$exception->getMessage());

                return self::FAILURE;
            }
        }

        if ($operation === 'list') {
            if ($key !== null) {
                $this->error('The list operation does not accept a profile key.');

                return self::FAILURE;
            }
            try {
                $profiles = [...$registry->configured(), ...$registry->registeredDcrProfiles()];
            } catch (Throwable $exception) {
                $this->error($exception->getMessage());

                return self::FAILURE;
            }

            $registered = DB::table('oauth_client_profiles')
                ->get(['profile_key', 'client_id', 'auth_strategy', 'disabled_at'])
                ->keyBy('profile_key');

            $this->table(['Profile', 'Protocol client ID', 'Authentication', 'Effective state'], array_values(array_map(
                static function (array $profile) use ($registered): array {
                    $row = $registered->get($profile['key']);
                    $active = $profile['enabled']
                        && ! ($profile['retired'] ?? false)
                        && $row !== null
                        && $row->disabled_at === null
                        && $row->client_id === $profile['client_id']
                        && $row->auth_strategy === $profile['strategy'];

                    return [
                        $profile['key'], $profile['client_id'], $profile['strategy'],
                        ($profile['retired'] ?? false) ? 'retired (permanent)' : ($active ? 'enabled' : 'disabled/unregistered'),
                    ];
                },
                $profiles,
            )));

            return self::SUCCESS;
        }

        if (! in_array($operation, ['register', 'disable', 'enable', 'retire'], true)
            || ! is_string($key) || $key === '' || strlen($key) > 48
            || ! $this->option('confirm')) {
            $this->error('Specify register, disable, enable or retire, an exact profile key and --confirm.');

            return self::FAILURE;
        }

        try {
            match ($operation) {
                'register' => $registry->register($key),
                'disable' => $registry->disable($key),
                'enable' => $registry->enable($key),
                'retire' => $registry->retireDcr($key),
            };
            $this->info('OAuth client profile '.$operation.' completed for '.$key.'.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('OAuth client profile operation refused: '.$exception->getMessage());

            return self::FAILURE;
        }
    }
}
