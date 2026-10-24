<?php

namespace App\Support;

use Illuminate\Support\Facades\DB;
use RuntimeException;

final class AdminLoginIdentity
{
    public function failureKey(string $normalizedEmail): string
    {
        $connection = DB::connection();

        // Use the same database collation weights for EVERY submitted email,
        // not a User ID for known accounts and raw text for unknown accounts.
        // This prevents Unicode-equivalent aliases from revealing account
        // existence through divergent rate-limit or lock behavior.
        $equivalence = match ($connection->getDriverName()) {
            'mariadb', 'mysql' => $connection->scalar('SELECT WEIGHT_STRING(?)', [$normalizedEmail]),
            // SQLite's default users.email column compares text byte-for-byte.
            'sqlite' => $normalizedEmail,
            default => throw new RuntimeException('Unsupported Admin login email collation.'),
        };

        if (! is_string($equivalence)) {
            throw new RuntimeException('Could not derive the Admin login collation key.');
        }

        return 'admin-login:failed-identity:weight:'.hash('sha256', $equivalence);
    }
}
