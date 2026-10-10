<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use phpseclib4\Net\SFTP;

/**
 * phpseclib 4.0.2 silently falls back to shell "exec sftp-server" when the
 * server rejects its SFTP subsystem request. Never execute that fallback:
 * file operations must require the actual SSH SFTP subsystem.
 */
final class SshSubsystemOnlySftp extends SFTP
{
    protected function send_binary_packet(
        #[\SensitiveParameter] string $data,
        ?string $logged = null,
    ): void {
        // SSH_MSG_CHANNEL_REQUEST = 98; string request type "exec" follows
        // the four-byte channel id. This guards the exact locked dependency.
        if (strlen($data) >= 13 && ord($data[0]) === 98
            && substr($data, 5, 8) === "\0\0\0\4exec") {
            throw new SshTargetConnectionException('sftp_unavailable');
        }

        parent::send_binary_packet($data, $logged);
    }
}
