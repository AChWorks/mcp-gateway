<?php

namespace App\Infrastructure\Connectors\Relay;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\PublicKeyLoader;
use RuntimeException;
use Throwable;

/**
 * Native SSH client identity for a single registered Relay. The Admin sees
 * only the public key and complete host-local commands, never private material.
 */
final class ConnectionRelayOnboarding
{
    public function prepare(ConnectionRelay $relay): void
    {
        if ($relay->login_public_key !== null || $relay->login_private_key_encrypted !== null) {
            throw new RuntimeException('This Relay already has an onboarding identity; it was not rotated.');
        }
        $key = EC::createKey('Ed25519');
        $private = $key->toString('OpenSSH');
        $public = $this->publicKey($key->getPublicKey()->toString('OpenSSH'));
        $encrypted = Crypt::encryptString(json_encode([
            'v' => 1, 'relay_record_id' => (string) $relay->getKey(),
            'relay_id' => $relay->relay_id, 'private' => $private,
        ], JSON_THROW_ON_ERROR));
        $written = DB::table('connection_relays')->where('id', $relay->getKey())
            ->whereNull('login_public_key')->whereNull('login_private_key_encrypted')
            ->update(['login_public_key' => $public, 'login_private_key_encrypted' => $encrypted]);
        if ($written !== 1) {
            throw new RuntimeException('Relay onboarding identity changed concurrently. Refresh the page.');
        }
    }

    public function privateKey(ConnectionRelay $relay): string
    {
        if (! is_string($relay->login_private_key_encrypted) || $relay->login_private_key_encrypted === '') {
            throw new RuntimeException('This Relay needs Owner onboarding preparation first.');
        }
        try {
            $value = json_decode(Crypt::decryptString($relay->login_private_key_encrypted), true, 8, JSON_THROW_ON_ERROR);
            if (! is_array($value) || ($value['v'] ?? null) !== 1
                || ! hash_equals((string) $relay->getKey(), (string) ($value['relay_record_id'] ?? ''))
                || ! hash_equals((string) $relay->relay_id, (string) ($value['relay_id'] ?? ''))
                || ! is_string($value['private'] ?? null)) {
                throw new RuntimeException('Relay identity does not match this registration.');
            }
            $key = PublicKeyLoader::loadPrivateKey($value['private']);
            if ($this->publicKey($key->getPublicKey()->toString('OpenSSH')) !== $relay->login_public_key) {
                throw new RuntimeException('Relay public key does not match its encrypted private key.');
            }

            return $value['private'];
        } catch (Throwable) {
            throw new RuntimeException('Relay onboarding identity cannot be decrypted or verified.');
        }
    }

    /** @return array{gateway:string,relay:string}|null */
    public function commands(ConnectionRelay $relay): ?array
    {
        if (! is_string($relay->login_public_key) || $relay->login_public_key === '') {
            return null;
        }
        $key = $this->publicKey($relay->login_public_key);
        $user = (string) $relay->control_user;

        // The intermediary already runs normal OpenSSH SSHD. This complete
        // command installs the public LOGIN key in the registered OS account;
        // it never edits sshd_config or installs a custom Relay daemon.
        $relayScript = 'set -eu'."\n"
            .'account='.escapeshellarg($user)."\n"
            .'key='.escapeshellarg($key)."\n"
            .'entry="$(getent passwd "$account")"'."\n"
            .'[ -n "$entry" ] || { echo "Relay SSH account does not exist" >&2; exit 1; }'."\n"
            .'home="$(printf "%s\\n" "$entry" | cut -d: -f6)"'."\n"
            .'[ -d "$home" ] && [ ! -L "$home/.ssh" ] || { echo "Relay home or SSH directory is unsafe" >&2; exit 1; }'."\n"
            .'install -d -m 700 -o "$account" "$home/.ssh"'."\n"
            .'authorized="$home/.ssh/authorized_keys"'."\n"
            .'[ ! -L "$authorized" ] || { echo "Refusing symlinked authorized_keys" >&2; exit 1; }'."\n"
            .'touch "$authorized"; chown "$account" "$authorized"; chmod 600 "$authorized"'."\n"
            .'if ! grep -Fqx -- "$key" "$authorized"; then'."\n"
            .'  if [ -s "$authorized" ]; then'."\n"
            .'    last="$(tail -c 1 "$authorized" | od -An -tu1 | tr -d "[:space:]")"'."\n"
            .'    [ "$last" = 10 ] || printf "\\n" >> "$authorized"'."\n"
            .'  fi'."\n"
            .'  printf "%s\\n" "$key" >> "$authorized"'."\n"
            .'fi'."\n"
            .'echo "Relay login key installed. SSHD must allow TCP forwarding for this account."';

        return [
            'relay' => 'sudo sh -c '.escapeshellarg($relayScript),
            'gateway' => $this->gatewayCommand($relay),
        ];
    }

    private function gatewayCommand(ConnectionRelay $relay): string
    {
        // aaPanel hosts may not have the application-compatible PHP on PATH.
        // Select a supported existing CLI PHP without installing a new runtime.
        $artisan = escapeshellarg(base_path('artisan'));
        $id = escapeshellarg((string) $relay->relay_id);
        $script = 'set -eu'."\n"
            .'for php in /www/server/php/85/bin/php /www/server/php/84/bin/php /usr/local/bin/php /usr/bin/php; do'."\n"
            .'  [ -x "$php" ] || continue'."\n"
            .'  if "$php" -r '.escapeshellarg('exit(version_compare(PHP_VERSION, "8.4.1", ">=") ? 0 : 1);').' >/dev/null 2>&1; then'."\n"
            .'    exec "$php" '.$artisan.' gateway:relay-install '.$id."\n"
            .'  fi'."\n"
            .'done'."\n"
            .'echo "No compatible PHP CLI (8.4.1+) was found on the Gateway host." >&2'."\n"
            .'exit 1';

        return 'sudo sh -c '.escapeshellarg($script);
    }

    private function publicKey(string $line): string
    {
        $parts = preg_split('/\s+/', trim($line));
        if (! is_array($parts) || count($parts) < 2 || $parts[0] !== 'ssh-ed25519'
            || ! preg_match('/^[A-Za-z0-9+\/=]+$/D', $parts[1])) {
            throw new InvalidArgumentException('Relay client public key is invalid.');
        }

        return $parts[0].' '.$parts[1];
    }
}
