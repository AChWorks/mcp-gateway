<?php

namespace App\Console\Commands;

use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

final class ReconcileSshJobs extends Command
{
    protected $signature = 'gateway:ssh-jobs-reconcile
        {operation=inspect : inspect or retire}
        {job? : Exact immutable 26-character Job ID}
        {--binding= : Expected original 64-character Target-binding digest from inspect}
        {--reason= : Operator explanation of independently verified cleanup}
        {--confirm= : Repeat the exact Job ID to confirm}
        {--attest-remote-cleaned : Attest original remote unit stopped AND spool deleted}';

    protected $description = 'Inspect durable SSH Jobs or explicitly attest already-verified cleanup; never SSH or re-launch.';

    public function handle(SshJobCoordinator $jobs): int
    {
        $operation = (string) $this->argument('operation');
        $job = $this->argument('job');
        if (! in_array($operation, ['inspect', 'retire'], true)
            || ($job !== null && preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/D', $job) !== 1)) {
            $this->error('Use inspect [job ID] or retire <exact Job ID>.');

            return self::FAILURE;
        }

        if ($operation === 'inspect') {
            if ($this->option('attest-remote-cleaned') || $this->option('confirm')
                || $this->option('binding') || $this->option('reason')) {
                $this->error('Inspect is read-only; remove mutation options.');

                return self::FAILURE;
            }
            $query = DB::table('ssh_command_jobs');
            if ($job !== null) {
                $query->where('id', $job);
            }
            $rows = $query->orderByDesc('created_at')->limit(30)->get();
            $this->table(
                [
                    'Job ID', 'Status', 'Original User ID', 'Original Target ID',
                    'Original host:port', 'Original OS user',
                    'Original host-key SHA-256', 'Original binding SHA-256',
                    'Admission until', 'Retain until',
                ],
                $rows->map(static fn ($row): array => [
                    $row->id, $row->status, $row->original_user_id ?? '(pre-snapshot unknown)',
                    $row->original_target_id ?? '(pre-snapshot unknown)',
                    $row->original_host !== null
                        ? $row->original_host.':'.$row->original_port : '(pre-snapshot unknown)',
                    $row->original_os_username ?? '(pre-snapshot unknown)',
                    $row->original_host_key_digest ?? '(pre-snapshot unknown)',
                    $row->target_binding_hash, $row->admission_expires_at ?? '(unknown)', $row->expires_at,
                ])->all(),
            );

            return self::SUCCESS;
        }

        if (! is_string($job) || $this->option('confirm') !== $job
            || $this->option('attest-remote-cleaned') !== true) {
            $this->error('Refusing: supply exact job, matching --confirm, and --attest-remote-cleaned.');
            $this->warn('First independently verify the ORIGINAL remote systemd unit stopped and private spool is gone.');
            $this->warn('A changed/deleted Target does not authorize cleanup on its replacement.');

            return self::FAILURE;
        }

        try {
            $result = $jobs->operatorRetire(
                $job, (string) $this->option('binding'), (string) $this->option('reason'),
            );
        } catch (SshTargetConnectionException $exception) {
            $this->error('Retirement refused: '.$exception->reason);

            return self::FAILURE;
        }

        $this->info('Locally retired '.$result['job_id'].' as '.$result['status'].'.');
        $this->warn('Operator-attested LOCAL retirement is not proof of remote script exit. Evidence remains until its retention deadline.');

        return self::SUCCESS;
    }
}
