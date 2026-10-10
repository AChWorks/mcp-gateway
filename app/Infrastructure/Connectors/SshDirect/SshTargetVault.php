<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;
use Throwable;

/** Connector- and exact-record-bound authenticated encryption. No secret projection. */
final class SshTargetVault
{
    public const PURPOSE = 'ssh_auth';

    public function seal(Target $target, SshTargetConfig $config, string $secret, ?string $passphrase): string
    {
        $this->assertBinding($target, $config);
        $this->validateSecret($config->auth_method, $secret, $passphrase);

        return Crypt::encryptString(json_encode([
            'v' => 1,
            'target_record_id' => (string) $target->getKey(),
            'target_id' => $target->target_id,
            'connector_type' => 'ssh_direct',
            'purpose' => self::PURPOSE,
            'binding' => $this->binding($target, $config),
            'auth_method' => $config->auth_method,
            'secret' => $secret,
            'passphrase' => $passphrase,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @return array{secret:string,passphrase:?string} */
    public function open(Target $target, SshTargetConfig $config, TargetCredential $credential): array
    {
        $this->assertBinding($target, $config);
        if ((string) $credential->target_record_id !== (string) $target->getKey()
            || $credential->connector_type !== 'ssh_direct'
            || $credential->purpose !== self::PURPOSE) {
            throw new RuntimeException('SSH credential binding is invalid.');
        }
        try {
            $payload = json_decode(Crypt::decryptString((string) $credential->encrypted_payload), true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new RuntimeException('SSH credential cannot be decrypted or verified.');
        }
        if (! is_array($payload) || ($payload['v'] ?? null) !== 1
            || ($payload['purpose'] ?? null) !== self::PURPOSE
            || ($payload['connector_type'] ?? null) !== 'ssh_direct'
            || ! hash_equals((string) $target->getKey(), (string) ($payload['target_record_id'] ?? ''))
            || ! hash_equals((string) $target->target_id, (string) ($payload['target_id'] ?? ''))
            || ! hash_equals($this->binding($target, $config), (string) ($payload['binding'] ?? ''))
            || ($payload['auth_method'] ?? null) !== $config->auth_method) {
            throw new RuntimeException('SSH credential ownership or endpoint binding is invalid.');
        }
        $secret = $payload['secret'] ?? null;
        $passphrase = $payload['passphrase'] ?? null;
        if (! is_string($secret) || ($passphrase !== null && ! is_string($passphrase))) {
            throw new RuntimeException('SSH credential material is invalid.');
        }
        $this->validateSecret($config->auth_method, $secret, $passphrase);

        return ['secret' => $secret, 'passphrase' => $passphrase];
    }

    private function assertBinding(Target $target, SshTargetConfig $config): void
    {
        if ($target->connector_type !== 'ssh_direct'
            || (string) $config->target_record_id !== (string) $target->getKey()) {
            throw new RuntimeException('SSH credential cannot be used with another Target.');
        }
    }

    private function binding(Target $target, SshTargetConfig $config): string
    {
        $pin = SshHostKeyPin::fromLine($config->pinned_host_key);

        return hash('sha256', implode("\0", [
            (string) $target->getKey(), $target->target_id, $config->host,
            (string) $config->port, $config->username, $config->auth_method, $pin->canonicalLine(),
        ]));
    }

    private function validateSecret(string $method, string $secret, ?string $passphrase): void
    {
        $max = $method === 'private_key' ? 16384 : 4096;
        if (! in_array($method, ['password', 'private_key'], true)
            || $secret === '' || strlen($secret) > $max
            || ($passphrase !== null && strlen($passphrase) > 4096)
            || ($method === 'password' && $passphrase !== null)) {
            throw new RuntimeException('SSH authentication material is invalid.');
        }
    }
}
