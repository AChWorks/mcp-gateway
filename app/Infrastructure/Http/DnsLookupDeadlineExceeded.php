<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class DnsLookupDeadlineExceeded extends RuntimeException {}
