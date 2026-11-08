<?php

namespace App\Infrastructure\Connectors\Relay;

use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use RuntimeException;
use Symfony\Component\Process\Process;

/** Host-local installer for a normal, private OpenSSH -D systemd service. */
final class ConnectionRelayHostService
{
    public function unitName(ConnectionRelay $relay): string
    {
        return 'mcp-gateway-relay-'.$this->safeId($relay->relay_id).'.service';
    }

    public function unitText(ConnectionRelay $relay): string
    {
        $id = $this->safeId($relay->relay_id);
        $base = '/etc/mcp-gateway-relays/'.$id;
        $alias = 'mcp-relay-'.$id;
        // Endpoints and usernames are validated at registration. Only
        // normalized printable ASCII is allowed in the systemd ExecStart line.
        foreach ([$relay->control_host, $relay->control_user] as $value) {
            if (str_starts_with($value, '-')
                || preg_match('/^[a-zA-Z0-9_.:+\[\]-]+$/D', $value) !== 1) {
                throw new RuntimeException('Unsafe Relay endpoint for systemd.');
            }
        }
        $port = (int) $relay->control_port;
        $socks = (int) $relay->local_socks_port;
        if ($port < 1 || $port > 65535 || $socks < 46000 || $socks > 60999) {
            throw new RuntimeException('Invalid saved Relay port.');
        }

        return '# Managed by MCP Gateway Relay '.$id."\n"
            ."[Unit]\nDescription=MCP Gateway OpenSSH Relay ".$id."\nAfter=network-online.target\nWants=network-online.target\n\n"
            ."[Service]\nType=simple\nExecStart=/usr/bin/ssh"
            .' -N -T -D 127.0.0.1:'.$socks
            .' -p '.$port
            .' -i '.$base.'/id_ed25519'
            .' -o IdentitiesOnly=yes'
            .' -o BatchMode=yes'
            .' -o StrictHostKeyChecking=yes'
            .' -o UserKnownHostsFile='.$base.'/known_hosts'
            .' -o HostKeyAlias='.$alias
            .' -o ExitOnForwardFailure=yes'
            .' -o ServerAliveInterval=30'
            .' -o ServerAliveCountMax=3'
            .' -l '.$relay->control_user.' '.$relay->control_host."\n"
            ."Restart=always\nRestartSec=5\nNoNewPrivileges=yes\n\n"
            ."[Install]\nWantedBy=multi-user.target\n";
    }

    public function install(ConnectionRelay $relay, string $privateKey): void
    {
        $this->requireRootAndSystemd();
        $id = $this->safeId($relay->relay_id);
        $unitName = $this->unitName($relay);
        $base = '/etc/mcp-gateway-relays/'.$id;
        $unitFile = '/etc/systemd/system/'.$unitName;
        $contents = $this->unitText($relay);
        $pin = SshHostKeyPin::fromLine((string) $relay->control_host_key)->canonicalLine();
        $knownHosts = 'mcp-relay-'.$id.' '.$pin."\n";
        $existing = is_file($unitFile) ? file_get_contents($unitFile) : null;
        $changed = $existing !== $contents
            || ! is_file($base.'/id_ed25519')
            || file_get_contents($base.'/id_ed25519') !== $privateKey
            || ! is_file($base.'/known_hosts')
            || file_get_contents($base.'/known_hosts') !== $knownHosts;
        if ($existing !== null && ! str_starts_with($existing, '# Managed by MCP Gateway Relay '.$id."\n")) {
            throw new RuntimeException('An unrelated service already occupies the Relay unit name; no changes made.');
        }
        if ($existing === null && $this->portResponds((int) $relay->local_socks_port)) {
            throw new RuntimeException('Local SOCKS port is already in use. Stop the old foreground tunnel first; nothing was changed.');
        }
        if (! is_executable('/usr/bin/ssh')) {
            throw new RuntimeException('OpenSSH client not found at /usr/bin/ssh.');
        }

        if (! is_dir($base) && ! mkdir($base, 0700, true) && ! is_dir($base)) {
            throw new RuntimeException('Could not create protected Relay identity directory.');
        }
        chmod($base, 0700);
        // Never expose the LOGIN private key in a generated web command,
        // command-line argv, unit file, logs, or the intermediary server.
        $this->write($base.'/id_ed25519', $privateKey, 0600);
        $this->write($base.'/known_hosts', $knownHosts, 0644);
        $this->write($unitFile, $contents, 0644);

        $this->run(['systemctl', 'daemon-reload']);
        $this->run(['systemctl', 'enable', '--now', $unitName]);
        if ($existing !== null && $changed) {
            $this->run(['systemctl', 'restart', $unitName]);
        }
        if (! $this->waitForSocks((int) $relay->local_socks_port)) {
            throw new RuntimeException('Relay service was installed but SOCKS5 is not responding. Check: systemctl status '
                .$unitName.' and journalctl -u '.$unitName.' --no-pager.');
        }
    }

    private function requireRootAndSystemd(): void
    {
        if (! function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            throw new RuntimeException('Run the Gateway Relay install command as root using sudo.');
        }
        if (! is_dir('/run/systemd/system') || ! is_executable('/usr/bin/systemctl')) {
            throw new RuntimeException('This Gateway host needs a running systemd service manager.');
        }
    }

    private function safeId(string $id): string
    {
        if (strlen($id) > 64 || preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $id) !== 1) {
            throw new RuntimeException('Invalid Relay ID.');
        }

        return $id;
    }

    private function write(string $path, string $contents, int $mode): void
    {
        $temp = tempnam(dirname($path), '.relay-install-');
        if ($temp === false) {
            throw new RuntimeException('Cannot stage protected Relay service file.');
        }
        try {
            if (file_put_contents($temp, $contents, LOCK_EX) === false || ! chmod($temp, $mode)
                || ! rename($temp, $path)) {
                throw new RuntimeException('Cannot install protected Relay service file.');
            }
        } finally {
            if (is_file($temp)) {
                unlink($temp);
            }
        }
    }

    /** @param list<string> $args */
    private function run(array $args): void
    {
        $result = new Process($args);
        $result->setTimeout(20)->run();
        if (! $result->isSuccessful()) {
            throw new RuntimeException('Could not operate Relay service: '.implode(' ', $args)
                .' (exit '.$result->getExitCode().'). Inspect systemctl status and journalctl.');
        }
    }

    private function portResponds(int $port): bool
    {
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errno, $error, 0.5);
        if (! is_resource($socket)) {
            return false;
        }
        fclose($socket);

        return true;
    }

    private function waitForSocks(int $port): bool
    {
        for ($attempt = 0; $attempt < 10; $attempt++) {
            $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errno, $error, 0.5);
            if (is_resource($socket)) {
                stream_set_timeout($socket, 1);
                $written = fwrite($socket, "\x05\x01\x00");
                $reply = $written === 3 ? fread($socket, 2) : false;
                fclose($socket);
                if ($reply === "\x05\x00") {
                    return true;
                }
            }
            usleep(500000);
        }

        return false;
    }
}
