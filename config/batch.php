<?php

return [
    // Concurrency is a resource policy, not a limit on registered or selected
    // Target count. Owner may adjust it to measured host/DB/SSH capacity.
    'max_parallelism' => max(1, (int) env('BATCH_MAX_PARALLELISM', 4)),
    'global_active' => max(1, (int) env('BATCH_GLOBAL_ACTIVE', 4)),
    'user_active' => max(1, (int) env('BATCH_USER_ACTIVE', 2)),
    // A claimed remote effect is UNKNOWN, not retryable, after an executor
    // loses its lease. Include the actual per-operation timeout and margin.
    'lease_margin_seconds' => max(30, (int) env('BATCH_LEASE_MARGIN_SECONDS', 90)),
    'worker_max_children' => max(1, (int) env('BATCH_WORKER_MAX_CHILDREN', 16)),
    'worker_max_seconds' => max(1, (int) env('BATCH_WORKER_MAX_SECONDS', 50)),
    // A crashed CLI scheduler lock must not persist for Laravel's 24h default.
    'scheduler_lock_minutes' => max(1, (int) env('BATCH_SCHEDULER_LOCK_MINUTES', 10)),
];
