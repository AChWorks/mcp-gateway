<?php

namespace App\Infrastructure\Connectors\ArvanCloud;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;
use Throwable;

/** Encrypt an Arvan API key bound to one immutable Target and API base URL. */
final class ArvanApiTargetVault
{
    public const PURPOSE = 'arvan_api_key';

    public function seal(Target $target, ArvanApiTargetConfig $config, string $key): string
    {
        $this->assertBinding($target, $config);
        $this->validate($key);

        return Crypt::encryptString(json_encode([
            'v' => 1,
            'purpose' => self::PURPOSE,
            'connector_type' => 'arvancloud',
            'target_record_id' => (string) $target->getKey(),
            'target_id' => $target->target_id,
            'base_url' => $config->base_url,
            'api_key' => $key,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function open(Target $target, ArvanApiTargetConfig $config, TargetCredential $credential): string
    {
        $this->assertBinding($target, $config);
        if ((string) $credential->target_record_id !== (string) $target->getKey()
            || $credential->connector_type !== 'arvancloud'
            || $credential->purpose !== self::PURPOSE) {
            throw new RuntimeException('ArvanCloud key does not belong to the selected Target.');
        }
        try {
            $payload = json_decode(Crypt::decryptString((string) $credential->encrypted_payload), true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new RuntimeException('ArvanCloud key cannot be decrypted.');
        }
        if (! is_array($payload) || ($payload['v'] ?? null) !== 1
            || ($payload['purpose'] ?? null) !== self::PURPOSE
            || ($payload['connector_type'] ?? null) !== 'arvancloud'
            || ! hash_equals((string) $target->getKey(), (string) ($payload['target_record_id'] ?? ''))
            || ! hash_equals($target->target_id, (string) ($payload['target_id'] ?? ''))
            || ! hash_equals($config->base_url, (string) ($payload['base_url'] ?? ''))) {
            throw new RuntimeException('ArvanCloud key binding is invalid. Rotate the key for this API endpoint.');
        }
        $key = $payload['api_key'] ?? null;
        if (! is_string($key)) {
            throw new RuntimeException('ArvanCloud key is invalid.');
        }
        $this->validate($key);

        return $key;
    }

    private function assertBinding(Target $target, ArvanApiTargetConfig $config): void
    {
        if ($target->connector_type !== 'arvancloud'
            || (string) $config->target_record_id !== (string) $target->getKey()) {
            throw new RuntimeException('ArvanCloud credential and configuration Target mismatch.');
        }
    }

    private function validate(string $key): void
    {
        if ($key === '' || strlen($key) > 4096 || preg_match('/[\x00-\x20\x7f]/', $key) === 1) {
            throw new RuntimeException('ArvanCloud API key format is invalid.');
        }
    }
}
