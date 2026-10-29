<?php

namespace App\Infrastructure\Http;

use RuntimeException;

/**
 * Safe outbound policy rejection with a stable, non-secret reason.
 *
 * A reason describes the local Gateway decision, not a remote provider error.
 * Never place an untrusted URL, credential or response body in this exception.
 */
final class UnsafeOutboundTarget extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $reason = 'invalid_target',
        public readonly ?string $rejectedAddress = null,
    ) {
        parent::__construct($message);
    }

    /** @return array<string, mixed> */
    public function diagnostics(): array
    {
        $context = [
            'failure_origin' => 'gateway_admission',
            'failure_stage' => str_starts_with($this->reason, 'dns_') ? 'dns_lookup' : 'admission',
            'outbound_rejection_reason' => $this->reason,
            'gateway_error_message' => $this->getMessage(),
        ];

        if ($this->rejectedAddress !== null && filter_var($this->rejectedAddress, FILTER_VALIDATE_IP) !== false) {
            $context['outbound_rejected_address'] = $this->rejectedAddress;
            $context['outbound_address_class'] = $this->addressClass($this->rejectedAddress);
        }

        return $context;
    }

    private function addressClass(string $address): string
    {
        $packed = inet_pton($address);
        if ($packed === false) {
            return 'restricted';
        }
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\x00", 10)."\xff\xff") {
            $packed = substr($packed, 12);
        }

        if (strlen($packed) === 4) {
            $first = ord($packed[0]);
            $second = ord($packed[1]);

            return match (true) {
                $first === 127 => 'loopback',
                $first === 10, $first === 192 && $second === 168,
                $first === 172 && $second >= 16 && $second <= 31 => 'private',
                $first === 169 && $second === 254 => 'link_local',
                default => 'restricted',
            };
        }

        if ($packed === str_repeat("\x00", 15)."\x01") {
            return 'loopback';
        }
        if ((ord($packed[0]) & 0xFE) === 0xFC) {
            return 'private';
        }
        if (ord($packed[0]) === 0xFE && (ord($packed[1]) & 0xC0) === 0x80) {
            return 'link_local';
        }

        return 'restricted';
    }
}
