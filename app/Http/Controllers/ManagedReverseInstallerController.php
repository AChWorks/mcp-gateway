<?php

namespace App\Http\Controllers;

use App\Application\Targets\SshManagedReverseInstallCommand;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

final class ManagedReverseInstallerController extends Controller
{
    public function __invoke(SshManagedReverseInstallCommand $installer): BinaryFileResponse
    {
        $installer->scriptDigest();

        return response()->file(
            (string) config('ssh.managed_reverse.installer_path'),
            [
                'Content-Type' => 'text/x-shellscript; charset=utf-8',
                'Cache-Control' => 'public, max-age=3600',
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }
}
