<?php

namespace App\Console\Commands;

use App\Support\EnvironmentRequirements;
use Illuminate\Console\Command;

final class GatewayEnvironmentCheck extends Command
{
    protected $signature = 'gateway:check';

    protected $description = 'Validate the minimum MCP Gateway runtime and security environment.';

    public function handle(EnvironmentRequirements $requirements): int
    {
        $checks = [
            ...$requirements->checks(
                databaseDriver: (string) config('database.default'),
                applicationKey: config('app.key'),
                cipher: (string) config('app.cipher'),
            ),
            ...$requirements->deploymentSecurityChecks(
                environment: (string) config('app.env'),
                applicationUrl: (string) config('app.url'),
                oauthPrivateKeyPath: (string) config('oauth.keys.private'),
                oauthPublicKeyPath: (string) config('oauth.keys.public'),
                bridgePrivateKeyPath: (string) config('bridge.keys.private'),
                bridgePublicKeyPath: (string) config('bridge.keys.public'),
                publicRoot: public_path(),
                privateFilesystemServed: (bool) config('filesystems.disks.local.serve', false),
                sessionEncrypted: (bool) config('session.encrypt'),
                sessionSecure: (bool) config('session.secure'),
            ),
        ];

        foreach ($checks as $label => $passed) {
            $this->line(sprintf('%s %s', $passed ? '[OK]' : '[FAIL]', $label));
        }

        return in_array(false, $checks, true) ? self::FAILURE : self::SUCCESS;
    }
}
