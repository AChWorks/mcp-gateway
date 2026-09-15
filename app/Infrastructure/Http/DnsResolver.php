<?php

namespace App\Infrastructure\Http;

interface DnsResolver
{
    /** @return list<string> */
    public function resolve(string $host): array;
}
