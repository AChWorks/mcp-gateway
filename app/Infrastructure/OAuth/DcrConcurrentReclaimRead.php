<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;

/**
 * Internal signal: the pre-admission DCR orphan read needs a new DB snapshot.
 * A different query/phase must not be retried after uncertain effects.
 */
final class DcrConcurrentReclaimRead extends RuntimeException {}
