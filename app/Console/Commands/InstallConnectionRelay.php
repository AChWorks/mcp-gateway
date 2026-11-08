<?php

namespace App\Console\Commands;

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostService;
use App\Infrastructure\Connectors\Relay\ConnectionRelayOnboarding;
use Illuminate\Console\Command;
use Throwable;

final class InstallConnectionRelay extends Command
{
    protected $signature = 'gateway:relay-install {relay_id : Registered Relay ID}';

    protected $description = 'Install the registered OpenSSH Relay as a persistent host-local systemd service.';

    public function handle(ConnectionRelayOnboarding $identity, ConnectionRelayHostService $service): int
    {
        try {
            $relay = ConnectionRelay::query()->where('relay_id', (string) $this->argument('relay_id'))->firstOrFail();
            $private = $identity->privateKey($relay);
            $service->install($relay, $private);
            $this->info('Relay tunnel service is running and responded as SOCKS5: '.$service->unitName($relay));
            $this->line('The service is enabled after reboot. Verify actual Target SSH/SFTP/WordPress in Admin.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
    }
}
