<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use App\Support\CurrentReadTransaction;
use Closure;
use Illuminate\Support\Facades\DB;

/** Exact retained launch intent, not a new credential or permission policy. */
final readonly class SshJobLaunchAdmission
{
    public function __construct(
        private AccessControl $access,
        private string $jobId,
        private int $userId,
        private string $targetRecordId,
    ) {}

    /** @return Closure(Closure():void,string):bool */
    public function stage(string $stage): Closure
    {
        return function (Closure $verifyNative, string $boundary) use ($stage): bool {
            return CurrentReadTransaction::run(function () use ($stage, $boundary, $verifyNative): bool {
                // Same principal -> job order as start/reserve/cancel.
                $user = User::query()->whereKey($this->userId)->lockForUpdate()->first();
                $row = DB::table('ssh_command_jobs')->where('id', $this->jobId)->lockForUpdate()->first();
                $this->assertCurrent($row, $stage);
                $verifyNative();
                // Each stage remains part of a single launch requiring all
                // three existing grants. Native guard checks current live
                // request/OAuth authority and exact peer/material/route.
                $fresh = User::query()->find($this->userId);
                $target = Target::query()->find($this->targetRecordId);
                $permissions = $stage === 'cancel' ? [GatewayPermission::SshCommandRun] : [
                    GatewayPermission::SshCommandRun, GatewayPermission::SshFileRead, GatewayPermission::SshFileWrite,
                ];
                if (! $user instanceof User || ! $fresh instanceof User || ! $target instanceof Target
                    || in_array(false, $this->access->allowsTargetPermissions($fresh, $target, $permissions), true)) {
                    throw $this->denial('authorization_revoked');
                }
                $row = DB::table('ssh_command_jobs')->where('id', $this->jobId)->lockForUpdate()->first();
                $this->assertCurrent($row, $stage);
                if ($stage === 'launch' && $boundary === 'command') {
                    // Login alone does not admit systemd-run. Commit the
                    // irreversible possible-launch fence before exec, once.
                    $now = now();
                    $changed = DB::table('ssh_command_jobs')->where('id', $this->jobId)
                        ->where('status', 'launch_unknown')->where('launch_admitted', false)
                        ->where('admission_expires_at', '>', $now)
                        ->update(['launch_admitted' => true, 'updated_at' => $now]);
                    if ($changed !== 1) {
                        throw $this->denial('job_attempt_retired');
                    }
                }

                return true;
            });
        };
    }

    private function assertCurrent(?object $row, string $stage): void
    {
        $expected = match ($stage) {
            'probe' => 'preparing',
            'cancel' => 'cancel_requested',
            default => 'launch_unknown',
        };
        if ($row === null || (int) $row->user_id !== $this->userId
            || (int) $row->original_user_id !== $this->userId
            || (string) $row->target_record_id !== $this->targetRecordId
            || $row->status !== $expected
            || ($stage !== 'cancel' && ($row->launch_admitted === null || (bool) $row->launch_admitted))) {
            throw $this->denial('job_attempt_retired');
        }
        if ($stage !== 'cancel' && ($row->admission_expires_at === null || now()->gte($row->admission_expires_at)
            || ($stage === 'probe' && ($row->preparing_expires_at === null || now()->gte($row->preparing_expires_at))))) {
            throw $this->denial('dispatch_lease_expired');
        }
    }

    private function denial(string $reason): SshTargetConnectionException
    {
        return new SshTargetConnectionException($reason, [
            'failure_origin' => 'gateway_admission',
            'failure_stage' => 'admission',
            'request_not_sent' => true,
        ]);
    }
}
