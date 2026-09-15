<?php

return [
    'retention_days' => max(1, (int) env('ACTIVITY_RETENTION_DAYS', 30)),
    'max_rows' => max(1, (int) env('ACTIVITY_MAX_ROWS', 5000)),
    'page_size_max' => min(100, max(1, (int) env('ACTIVITY_PAGE_SIZE_MAX', 100))),
];
