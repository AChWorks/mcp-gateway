<?php

return [
    // Only consumed by the intentional, destructive Site -> Target major upgrade.
    // The operator must confirm a consistent/restorable database backup before proceeding.
    'reset_acknowledged' => env('GATEWAY_TARGET_RESET_ACKNOWLEDGED', ''),
    'database_backup_verified' => env('GATEWAY_TARGET_RESET_DATABASE_BACKUP_VERIFIED', ''),
];
