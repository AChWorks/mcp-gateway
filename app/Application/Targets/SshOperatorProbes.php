<?php

namespace App\Application\Targets;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * Small, separately selectable diagnostics over the existing pinned SSH exec.
 * Remote observations are evidence, never a claim of strong read-only isolation.
 * All dynamic shell arguments are validated AND quoted before execution.
 */
final class SshOperatorProbes
{
    /** @var array<string,string> */
    private const SYSTEM_SOURCES = [
        'system' => 'uname',
        'uptime' => '/proc/uptime',
        'load' => '/proc/loadavg',
        'cpu' => 'getconf',
        'memory' => '/proc/meminfo',
        'storage' => 'df',
        'processes' => 'ps',
        'service' => 'systemctl',
        'listeners' => 'ss',
    ];

    /** @return list<string> */
    public static function systemSections(): array
    {
        return array_keys(self::SYSTEM_SOURCES);
    }

    /** @param list<string> $sections */
    public static function systemScript(array $sections, ?string $service): string
    {
        if ($sections === [] || array_diff($sections, self::systemSections()) !== []
            || count($sections) !== count(array_unique($sections))) {
            throw new InvalidArgumentException('Invalid or duplicate system section.');
        }
        if (in_array('service', $sections, true) && ($service === null || ! self::serviceNameValid($service))) {
            throw new InvalidArgumentException('Service must be a valid systemd unit name.');
        }

        $scripts = [
            'system' => 'uname -srm',
            'uptime' => 'cat /proc/uptime',
            'load' => 'cat /proc/loadavg',
            'cpu' => 'getconf _NPROCESSORS_ONLN; uname -m',
            'memory' => "awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print \$1, \$2, \$3}' /proc/meminfo",
            'storage' => 'df -Pk',
            'processes' => 'ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 12',
            'service' => 'systemctl is-active -- '.escapeshellarg((string) $service),
            'listeners' => 'ss -lntup',
        ];
        $parts = ['LC_ALL=C; export LC_ALL'];
        foreach ($sections as $section) {
            $parts[] = "printf '%s\\n' ".escapeshellarg('__GW_SECTION__:'.$section);
            $parts[] = 'if { '.$scripts[$section].'; } 2>&1; then printf "%s\n" "__GW_EXIT__:0"; else printf "__GW_EXIT__:%s\n" "$?"; fi';
        }

        return implode("\n", $parts);
    }

    /** @return array<string,mixed> */
    public static function parseSystem(string $stdout, bool $truncated): array
    {
        $sections = [];
        $current = null;
        foreach (explode("\n", $stdout) as $line) {
            if (str_starts_with($line, '__GW_SECTION__:')) {
                $current = substr($line, strlen('__GW_SECTION__:'));
                if (! array_key_exists($current, self::SYSTEM_SOURCES)) {
                    $current = null;

                    continue;
                }
                $sections[$current] = [
                    'source' => self::SYSTEM_SOURCES[$current],
                    'unit' => match ($current) {
                        'uptime' => 'seconds',
                        'memory' => 'kB',
                        'storage' => '1KiB_blocks',
                        'load' => 'load_average',
                        default => null,
                    },
                    'status' => 'partial',
                    'lines' => [],
                ];

                continue;
            }
            if ($current === null) {
                continue;
            }
            if (preg_match('/^__GW_EXIT__:([0-9]+)$/D', $line, $match) === 1) {
                $code = (int) $match[1];
                $sections[$current]['exit_code'] = $code;
                $sections[$current]['status'] = $code === 0 ? 'observed' : (
                    $code === 127 ? 'unsupported' : 'failed'
                );
                $current = null;

                continue;
            }
            if ($line !== '') {
                $sections[$current]['lines'][] = $line;
            }
        }

        // A truncated stdout may omit the last exit marker. Do not invent
        // success for an incomplete section or absent source.
        return [
            'sections' => $sections,
            'complete' => $sections !== [] && ! $truncated && ! array_any($sections, static fn (array $s): bool => $s['status'] === 'partial'),
            'stdout_truncated' => $truncated,
        ];
    }

    public static function serviceNameValid(string $service): bool
    {
        return strlen($service) <= 200
            && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.@:-]*$/D', $service) === 1;
    }

    public static function hostValid(string $host): bool
    {
        return $host !== '' && strlen($host) <= 253
            && (filter_var($host, FILTER_VALIDATE_IP) !== false
                || preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/D', $host) === 1);
    }

    public static function urlPathValid(string $path): bool
    {
        return $path !== '' && strlen($path) <= 1024
            && str_starts_with($path, '/')
            && preg_match('/[\x00-\x20\x7f#]/', $path) !== 1
            && mb_check_encoding($path, 'UTF-8');
    }

    public static function httpUrl(string $host, int $port, string $scheme, string $path): string
    {
        if (! self::hostValid($host) || ! in_array($scheme, ['http', 'https'], true)
            || $port < 1 || $port > 65535 || ! self::urlPathValid($path)) {
            throw new InvalidArgumentException('Invalid exact HTTP destination.');
        }
        $authority = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
            ? '['.$host.']' : $host;

        return $scheme.'://'.$authority.':'.$port.$path;
    }

    public static function networkScript(
        string $probe, string $host, ?int $port, string $scheme, string $path,
        ?string $dnsName, int $timeout,
    ): string {
        if (! self::hostValid($host) || $timeout < 1 || $timeout > 600
            || ($port !== null && ($port < 1 || $port > 65535))) {
            throw new InvalidArgumentException('Invalid destination or port.');
        }
        $qhost = escapeshellarg($host);
        $qport = (string) ($port ?? match ($probe) {
            'http' => $scheme === 'https' ? 443 : 80,
            'tls' => 443,
            'udp_dns', 'dns' => 53,
            default => 80,
        });
        $seconds = (string) $timeout;
        $parts = match ($probe) {
            'dns' => ['getent', "getent ahosts $qhost"],
            'route' => ['ip', "ip route get $qhost"],
            'tcp' => ['nc', "nc -z -w $seconds $qhost $qport && printf 'tcp_open\\n'"],
            'latency' => ['ping', "ping -n -c 1 -W $seconds $qhost"],
            'tls' => self::tlsScript($host, (int) $qport),
            'http' => [
                'curl',
                'curl --silent --show-error --max-time '.$seconds
                .' --connect-timeout '.$seconds
                ." --output /dev/null --write-out 'http_status=%{http_code}\\nremote_ip=%{remote_ip}\\n"
                ."time_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_total=%{time_total}\\n'"
                .' -- '.escapeshellarg(self::httpUrl($host, (int) $qport, $scheme, $path)),
            ],
            'udp_dns' => self::dnsUdpScript($qhost, $qport, $dnsName, $timeout),
            default => throw new InvalidArgumentException('Unsupported probe.'),
        };
        [$utility, $command] = $parts;

        return 'LC_ALL=C; export LC_ALL; if ! command -v '.$utility
            .' >/dev/null 2>&1; then printf "__GW_UNSUPPORTED__\\n"; exit 127; fi; '.$command;
    }

    /** @return array{string,string} */
    private static function tlsScript(string $host, int $port): array
    {
        $endpoint = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
            ? '['.$host.']:'.$port : $host.':'.$port;
        $verify = filter_var($host, FILTER_VALIDATE_IP) !== false ? '-verify_ip' : '-verify_hostname';

        return [
            'openssl',
            'openssl s_client -brief -verify_return_error '.$verify.' '.escapeshellarg($host)
            .' -connect '.escapeshellarg($endpoint)
            .(filter_var($host, FILTER_VALIDATE_IP) === false ? ' -servername '.escapeshellarg($host) : '')
            .' </dev/null',
        ];
    }

    /** @return array{string,string} */
    private static function dnsUdpScript(string $host, string $port, ?string $dnsName, int $timeout): array
    {
        if ($dnsName === null || ! self::hostValid($dnsName)) {
            throw new InvalidArgumentException('UDP DNS requires an exact query name.');
        }

        return ['dig', 'dig +notcp +tries=1 +time='.$timeout
            .' +noall +comments +answer @'.$host.' -p '.$port.' '.escapeshellarg($dnsName).' A'];
    }

    /** @param array<string,mixed> $raw
     * @return array<string,mixed>
     */
    public static function parseNetwork(string $probe, array $raw): array
    {
        $stdout = $raw['stdout_encoding'] === 'utf-8' ? (string) $raw['stdout'] : '';
        $stderr = $raw['stderr_encoding'] === 'utf-8' ? (string) $raw['stderr'] : '';
        $complete = $raw['status'] === 'completed';
        $truncated = $raw['stdout_truncated'] || $raw['stderr_truncated'];
        $unsupported = $complete && (int) ($raw['exit_code'] ?? -1) === 127
            && str_contains($stdout, '__GW_UNSUPPORTED__');
        $code = $raw['exit_code'];
        $verifiedResponse = $probe === 'udp_dns'
            ? preg_match('/\bstatus:\s*[A-Z]+\b/', $stdout) === 1
            : true;
        $status = ! $complete || $truncated ? 'unknown' : (
            $unsupported ? 'unsupported' : (
                $code === 0 && $verifiedResponse ? 'passed' : 'failed'
            )
        );
        $observed = [];
        if ($probe === 'http') {
            foreach (explode("\n", $stdout) as $line) {
                if (preg_match('/^(http_status|remote_ip|time_connect|time_appconnect|time_total)=(.*)$/D', $line, $match) === 1) {
                    $observed[$match[1]] = $match[1] === 'http_status' ? (int) $match[2] : $match[2];
                }
            }
            if ($status === 'passed' && empty($observed['http_status'])) {
                $status = 'unknown';
            }
        } elseif ($probe === 'dns') {
            if (trim($stdout) === '' && $status === 'passed') {
                $status = 'unknown';
            }
            $observed['addresses'] = array_values(array_unique(array_filter(array_map(
                static fn (string $line): string => trim(explode(' ', trim($line))[0]),
                explode("\n", $stdout),
            ))));
        } elseif ($probe === 'udp_dns') {
            preg_match('/\bstatus:\s*([A-Z]+)/', $stdout, $matches);
            $observed['dns_response_status'] = $matches[1] ?? null;
            $observed['protocol'] = 'DNS over UDP (protocol response, not arbitrary UDP port reachability)';
        } elseif ($probe === 'latency' && preg_match('/time=([0-9.]+)\s*ms/', $stdout, $matches) === 1) {
            $observed['latency_ms'] = (float) $matches[1];
        }

        return [
            'probe' => $probe,
            'status' => $status,
            'source' => match ($probe) {
                'dns' => 'getent', 'route' => 'iproute2', 'tcp' => 'netcat',
                'tls' => 'openssl', 'http' => 'curl', 'latency' => 'icmp_ping',
                'udp_dns' => 'dig',
                default => 'unknown',
            },
            'observed' => $observed,
            'stdout' => $stdout,
            'stderr' => $stderr,
            'exit_code' => $code,
            'complete' => $complete && ! $truncated,
            'truncated' => $truncated,
        ];
    }

    public static function journalScript(
        ?string $service, ?string $since, ?string $until, ?string $level,
        ?string $cursor, int $lines,
    ): string {
        if ($service !== null && ! self::serviceNameValid($service)) {
            throw new InvalidArgumentException('Invalid journal service.');
        }
        if ($lines < 1 || $lines > 100000
            || $level !== null && ! in_array($level, ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'], true)
            || $cursor !== null && ($cursor === '' || strlen($cursor) > 2048 || preg_match('/[\x00-\x1f\x7f]/', $cursor) === 1)) {
            throw new InvalidArgumentException('Invalid journal filter.');
        }
        foreach ([$since, $until] as $time) {
            if ($time !== null && (! preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/D', $time)
                || ! self::validTimestamp($time))) {
                throw new InvalidArgumentException('Journal timestamps require ISO 8601 with timezone.');
            }
        }
        $args = ['--no-pager', '--output=json', '--show-cursor', '--lines='.$lines];
        foreach (['--unit' => $service, '--since' => $since, '--until' => $until, '--priority' => $level, '--after-cursor' => $cursor] as $flag => $value) {
            if ($value !== null) {
                $args[] = $flag.'='.escapeshellarg($value);
            }
        }

        return 'LC_ALL=C; export LC_ALL; if ! command -v journalctl >/dev/null 2>&1; '
            .'then printf "__GW_UNSUPPORTED__\\n"; exit 127; fi; journalctl '.implode(' ', $args);
    }

    private static function validTimestamp(string $value): bool
    {
        try {
            new DateTimeImmutable($value);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** @param array<string,mixed> $raw
     * @return array<string,mixed>
     */
    public static function parseJournal(array $raw): array
    {
        $data = $raw['stdout_encoding'] === 'utf-8' ? $raw['stdout'] : '';
        $entries = [];
        $lastCursor = null;
        foreach (explode("\n", $data) as $line) {
            if ($line === '' || ! str_starts_with($line, '{')) {
                continue;
            }
            $item = json_decode($line, true);
            if (! is_array($item) || ! is_string($item['__CURSOR'] ?? null)) {
                continue;
            }
            $us = $item['__REALTIME_TIMESTAMP'] ?? null;
            $timestamp = is_numeric($us)
                ? gmdate('Y-m-d\TH:i:s', intdiv((int) $us, 1000000))
                    .sprintf('.%06dZ', (int) $us % 1000000)
                : null;
            $lastCursor = $item['__CURSOR'];
            $entries[] = [
                'cursor' => $lastCursor,
                'timestamp_utc' => $timestamp,
                'source_unit' => $item['_SYSTEMD_UNIT'] ?? null,
                'priority' => $item['PRIORITY'] ?? null,
                'message' => $item['MESSAGE'] ?? null,
            ];
        }
        $complete = $raw['status'] === 'completed'
            && ! $raw['stdout_truncated'] && ! $raw['stderr_truncated'];
        $unsupported = $raw['exit_code'] === 127 && str_contains($data, '__GW_UNSUPPORTED__');

        return [
            'status' => ! $complete ? 'unknown' : ($unsupported ? 'unsupported' : (
                $raw['exit_code'] === 0 ? 'observed' : 'failed'
            )),
            'source' => 'journald',
            'entries' => $entries,
            'next_cursor' => $lastCursor,
            'complete' => $complete,
            'truncated' => $raw['stdout_truncated'] || $raw['stderr_truncated'],
            'exit_code' => $raw['exit_code'],
            'stderr' => $raw['stderr_encoding'] === 'utf-8' ? $raw['stderr'] : null,
        ];
    }
}
