<?php

return [
    'retention_days' => max(1, (int) env('ACTIVITY_RETENTION_DAYS', 30)),
    'max_rows' => max(1, (int) env('ACTIVITY_MAX_ROWS', 5000)),
    'page_size_max' => min(100, max(1, (int) env('ACTIVITY_PAGE_SIZE_MAX', 100))),
    // Preserve actionable observed errors; limits are configurable by the Owner
    // and explicit truncation is recorded rather than silently losing context.
    'diagnostic_code_max_bytes' => max(128, (int) env('ACTIVITY_DIAGNOSTIC_CODE_MAX_BYTES', 4096)),
    'diagnostic_message_max_bytes' => max(1024, (int) env('ACTIVITY_DIAGNOSTIC_MESSAGE_MAX_BYTES', 65536)),
    'diagnostic_details_max_bytes' => max(1024, (int) env('ACTIVITY_DIAGNOSTIC_DETAILS_MAX_BYTES', 131072)),
];
