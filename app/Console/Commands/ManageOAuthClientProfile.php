<?php

namespace App\Console\Commands;

use App\Infrastructure\OAuth\ClientProfileRegistry;
use Illuminate\Console\Command;
use Throwable;

final class ManageOAuthClientProfile extends Command
{
    protected $signature = 'gateway:oauth-client-profile
        {operation : list, register, disable, or enable}
        {key? : Exact immutable profile key}
        {--confirm : Explicitly acknowledge profile activation or token revocation}';

    protected $description = 'Inspect or explicitly change the durable OAuth client profile lifecycle';

    public function handle(ClientProfileRegistry $registry): int
    {
        $operation = (string) $this->argument('operation');
        $key = $this->argument('key');

        if ($operation === 'list') {
            if ($key !== null) {
                $this->error('The list operation does not accept a profile key.');

                return self::FAILURE;
            }
            try {
                $profiles = $registry->configured();
            } catch (Throwable $exception) {
                $this->error($exception->getMessage());

                return self::FAILURE;
            }

            $this->table(['Profile', 'Protocol client ID', 'Authentication', 'Configured enabled'], array_values(array_map(
                static fn (array $profile): array => [
                    $profile['key'],
                    $profile['client_id'],
                    $profile['strategy'],
                    $profile['enabled'] ? 'yes' : 'no',
                ],
                $profiles,
            )));

            return self::SUCCESS;
        }

        if (! in_array($operation, ['register', 'disable', 'enable'], true)
            || ! is_string($key) || $key === '' || strlen($key) > 48
            || ! $this->option('confirm')) {
            $this->error('Specify register, disable or enable, an exact profile key and --confirm.');

            return self::FAILURE;
        }

        try {
            match ($operation) {
                'register' => $registry->register($key),
                'disable' => $registry->disable($key),
                'enable' => $registry->enable($key),
            };
            $this->info('OAuth client profile '.$operation.' completed for '.$key.'.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('OAuth client profile operation refused: '.$exception->getMessage());

            return self::FAILURE;
        }
    }
}
