<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetConnectionException;
use App\Http\Controllers\Mcp\SshWholeFileController;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
use Tests\TestCase;

/**
 * Verify the EXISTING shared Target file admission used by whole-file calls;
 * new binary routes must not introduce separate/unmetered concurrency.
 */
final class SshWholeFileAdmissionTest extends TestCase
{
    public function test_same_target_is_serialized_without_blocking_another_target(): void
    {
        $admission = app(SshFileAdmission::class);
        $target = 'whole-file-'.bin2hex(random_bytes(8));
        $other = $target.'-other';

        $result = $admission->run($target, function () use ($admission, $target, $other): string {
            try {
                $admission->run($target, static fn (): bool => true);
                self::fail('Nested same-Target lease must fail closed.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('connection_busy', $exception->reason);
            }

            return $admission->run($other, static fn (): string => 'other-target-independent');
        });

        self::assertSame('other-target-independent', $result);
        self::assertSame('target-free-again', $admission->run($target,
            static fn (): string => 'target-free-again'));
    }

    public function test_binary_sidecar_maps_existing_admission_failures_to_actionable_http_codes(): void
    {
        $controller = app(SshWholeFileController::class);
        $failure = new \ReflectionMethod($controller, 'failure');
        $busy = $failure->invoke($controller, 'connection_busy');
        self::assertSame(409, $busy->getStatusCode());
        $unavailable = $failure->invoke($controller, 'admission_unavailable');
        self::assertSame(503, $unavailable->getStatusCode());
        $limited = $failure->invoke($controller, 'rate_limited');
        self::assertSame(429, $limited->getStatusCode());
        self::assertSame('60', $limited->headers->get('Retry-After'));
        self::assertSame('rate_limited', json_decode((string) $limited->getContent(), true)['error']['code']);
    }

    public function test_source_sftp_admission_limit_is_not_bypassed_by_new_binary_routes(): void
    {
        $admission = app(SshFileAdmission::class);
        $target = 'whole-file-rate-'.bin2hex(random_bytes(8));

        for ($index = 0; $index < 30; $index++) {
            self::assertSame($index, $admission->run($target, static fn (): int => $index));
        }

        try {
            $admission->run($target, static fn (): bool => true);
            self::fail('The existing 30-operations/minute SFTP budget must remain enforced.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('rate_limited', $exception->reason);
        }
    }
}
