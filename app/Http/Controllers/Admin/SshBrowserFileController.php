<?php

namespace App\Http\Controllers\Admin;

use App\Application\Files\SshWholeFileTransfer;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Session-authenticated browser fallback for selecting real local files.
 * Uses the SAME verified SFTP/whole-file implementation as the OAuth HTTP
 * transfer endpoint; it never mints bearer tokens or imports chat attachments.
 */
final class SshBrowserFileController extends Controller
{
    public function __construct(private readonly SshWholeFileTransfer $files) {}

    public function upload(Request $request, Target $target): RedirectResponse
    {
        $this->requireMode();
        $user = $this->user($request);
        Gate::authorize(GatewayPermission::SshFileWrite->value, $target);
        $target = $this->files->target($user, $target->target_id, GatewayPermission::SshFileWrite);
        $maxKiB = (int) ceil($this->files->limits()['max_bytes'] / 1024);
        $input = $request->validate([
            'local_file' => ['required', 'file', 'max:'.$maxKiB],
            'destination' => ['required', 'string', 'max:1024'],
            'private_staging_dir' => ['required', 'string', 'max:1024'],
            'overwrite' => ['sometimes', 'accepted'],
        ]);

        $file = $request->file('local_file');
        $sourcePath = $file?->getRealPath();
        if (! is_string($sourcePath) || $sourcePath === '') {
            return $this->failed('input_unavailable');
        }

        $size = filesize($sourcePath);
        $hash = hash_file('sha256', $sourcePath);
        if (! is_int($size) || $size > $this->files->limits()['max_bytes']
            || ! is_string($hash)) {
            return $this->failed('file_too_large');
        }

        $stream = fopen($sourcePath, 'rb');
        if (! is_resource($stream)) {
            return $this->failed('input_unavailable');
        }
        try {
            $result = $this->files->upload($user, $target, $input['destination'], $stream, [
                'size' => $size,
                'sha256' => $hash,
                'path' => $input['destination'],
                'private_staging_dir' => $input['private_staging_dir'],
                'overwrite' => isset($input['overwrite']),
            ]);
            if (($result['status'] ?? null) !== 'completed'
                || ($result['bytes_written'] ?? null) !== $size
                || ($result['sha256'] ?? null) !== $hash) {
                return $this->failed('outcome_unknown');
            }
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($exception->reason);
        } catch (Throwable) {
            return $this->failed('file_unavailable');
        } finally {
            fclose($stream);
        }

        return redirect()->route('admin.targets.show', $target)
            ->with('status', __('File uploaded and remote SHA-256 verified.'));
    }

    public function download(Request $request, Target $target): Response
    {
        $this->requireMode();
        $user = $this->user($request);
        Gate::authorize(GatewayPermission::SshFileRead->value, $target);
        $target = $this->files->target($user, $target->target_id, GatewayPermission::SshFileRead);
        $input = $request->validate([
            'path' => ['required', 'string', 'max:1024'],
        ]);
        try {
            $file = $this->files->download($user, $target, $input['path'], [
                'path' => $input['path'],
            ]);
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($exception->reason);
        } catch (Throwable) {
            return $this->failed('file_unavailable');
        }

        $stream = $file['stream'];
        $bytes = (int) $file['identity']['bytes_read'];
        $sha = (string) $file['identity']['sha256'];
        $basename = basename($input['path']);
        // Constant ASCII fallback; the RFC 5987 filename is URL-escaped.
        $disposition = 'attachment; filename="download.bin"; filename*=UTF-8\'\''.rawurlencode($basename);

        return response()->stream(static function () use ($stream): void {
            try {
                while (! feof($stream) && ! connection_aborted()) {
                    $chunk = fread($stream, 65536);
                    if (! is_string($chunk) || $chunk === '') {
                        break;
                    }
                    echo $chunk;
                }
            } finally {
                fclose($stream);
            }
        }, 200, [
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => $disposition,
            'Content-Length' => (string) $bytes,
            'X-Gateway-File-SHA256' => $sha,
            'X-Gateway-File-Bytes' => (string) $bytes,
            'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    private function user(Request $request): User
    {
        $user = $request->user();
        abort_unless($user instanceof User && $user->access_enabled, 403);

        return $user;
    }

    private function requireMode(): void
    {
        abort_unless(config('ssh.file_transfer.enabled', false) === true, 404);
    }

    private function failed(string $reason): RedirectResponse
    {
        OperationDiagnostics::failure('ssh-browser-file', $reason);

        // Never flash remote paths, file content or host error messages.
        return back()->withErrors(['file_exchange' => __('SSH file exchange failed (code: :code). Inspect the Target and avoid blind retries of writes.', [
            'code' => $reason,
        ])]);
    }
}
