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
        // A pre-existing unit file does not prove it owns a live listener:
        // an old foreground SSH -D or unrelated SOCKS server may have taken
        // over the port while that unit was stopped.
        $listeners = $this->listeningInodes((int) $relay->local_socks_port);
        if ($listeners !== [] && ($existing === null
            || ! $this->managedServiceOwnsSockets($unitName, $listeners))) {
            throw new RuntimeException('Local SOCKS port is occupied by a process other than the registered '
                .$unitName.'. Identify and stop only that conflicting process, then retry; no files or services were changed.');
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
        if (! $this->waitForManagedSocks($unitName, (int) $relay->local_socks_port)) {
            throw new RuntimeException('Relay service was installed, but its active OpenSSH process was not verified '
                .'as the owner of the expected SOCKS5 listener. Check: systemctl status '
                .$unitName.' and journalctl -u '.$unitName.' --no-pager. '
                .'If another process occupies this port, stop that exact process before retrying.');
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

    /**
     * Return actual kernel listening socket inodes on the exact IPv4 loopback
     * port, including wildcard binds that conflict with 127.0.0.1. This is
     * kernel-owned evidence, not an arbitrary SOCKS greeting or a stale unit.
     *
     * @return list<string>
     */
    private function listeningInodes(int $port): array
    {
        $lines = @file('/proc/net/tcp', FILE_IGNORE_NEW_LINES);
        if (! is_array($lines)) {
            throw new RuntimeException('Cannot inspect Linux TCP listeners in /proc/net/tcp.');
        }
        $inodes = [];
        foreach (array_slice($lines, 1) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (! is_array($parts) || count($parts) < 10 || $parts[3] !== '0A') {
                continue;
            }
            $address = explode(':', $parts[1], 2);
            if (count($address) !== 2 || strtoupper($address[1]) !== sprintf('%04X', $port)
                || ! in_array(strtoupper($address[0]), ['0100007F', '00000000'], true)) {
                continue;
            }
            $inodes[] = $parts[9];
        }

        return array_values(array_unique($inodes));
    }

    /**
     * Verify that the actual active systemd MainPID (our native SSH binary)
     * holds every local listener under examination. /proc/PID/net/tcp alone
     * is not sufficient: it enumerates a network namespace, not PID ownership.
     *
     * @param  list<string>  $inodes
     */
    private function managedServiceOwnsSockets(string $unitName, array $inodes): bool
    {
        if ($inodes === []) {
            return false;
        }
        $pid = $this->managedSshMainPid($unitName);
        if ($pid === null) {
            return false;
        }

        return $this->pidOwnsSockets($pid, $inodes);
    }

    private function managedSshMainPid(string $unitName): ?int
    {
        $process = new Process(['systemctl', 'show', '--no-pager',
            '--property=ActiveState,MainPID', $unitName]);
        $process->setTimeout(5);
        $process->run();
        if (! $process->isSuccessful()) {
            return null;
        }
        $output = $process->getOutput();
        if (preg_match('/^ActiveState=active$/m', $output) !== 1
            || preg_match('/^MainPID=([1-9][0-9]*)$/m', $output, $matches) !== 1) {
            return null;
        }
        $pid = (int) $matches[1];
        $exe = @readlink('/proc/'.$pid.'/exe');
        $expected = realpath('/usr/bin/ssh');
        if ($expected === false || $exe !== $expected) {
            return null;
        }

        return $pid;
    }

    /**
     * A true result requires the process itself to own the kernel socket
     * inodes, not merely to share their network namespace.
     *
     * @param  list<string>  $inodes
     */
    private function pidOwnsSockets(int $pid, array $inodes): bool
    {
        if ($pid <= 0 || $inodes === []) {
            return false;
        }
        $fdPaths = glob('/proc/'.$pid.'/fd/*');
        if (! is_array($fdPaths)) {
            return false;
        }
        $owned = [];
        foreach ($fdPaths as $path) {
            // A file descriptor can close between glob() and readlink().
            if (! is_link($path)) {
                continue;
            }
            $socket = @readlink($path);
            if ($socket !== false && preg_match('/^socket:\[([0-9]+)\]$/D', $socket, $match) === 1) {
                $owned[$match[1]] = true;
            }
        }
        foreach ($inodes as $inode) {
            if (! isset($owned[$inode])) {
                return false;
            }
        }

        return true;
    }

    private function waitForManagedSocks(string $unitName, int $port): bool
    {
        for ($attempt = 0; $attempt < 10; $attempt++) {
            $listeners = $this->listeningInodes($port);
            if ($listeners !== [] && $this->managedServiceOwnsSockets($unitName, $listeners)
                && $this->socksResponds($port)) {
                return true;
            }
            usleep(500000);
        }

        return false;
    }

    private function socksResponds(int $port): bool
    {
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errno, $error, 0.5);
        if (! is_resource($socket)) {
            return false;
        }
        stream_set_timeout($socket, 1);
        $written = fwrite($socket, "\x05\x01\x00");
        $reply = $written === 3 ? fread($socket, 2) : false;
        fclose($socket);

        return $reply === "\x05\x00";
    }
}
