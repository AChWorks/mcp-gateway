<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\TargetInventory;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Models\User;
use App\Support\CorrelationId;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;
use InvalidArgumentException;
use RuntimeException;

final class TargetController extends Controller
{
    public function index(Request $request, TargetInventory $inventory): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(TargetConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);

        $page = (int) ($validated['page'] ?? 1);
        $search = $this->trimmed($validated['search'] ?? null);
        $state = $this->trimmed($validated['connection_state'] ?? null);

        return view('admin.targets.index', [
            'inventory' => $inventory->adminPage($user, $page, $search, $state),
            'filters' => ['search' => $search, 'connection_state' => $state],
            'connectionStates' => TargetConnectionState::cases(),
            'baseQuery' => array_filter([
                'search' => $search,
                'connection_state' => $state,
            ], static fn (?string $value): bool => $value !== null),
        ]);
    }

    public function create(): View
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);

        // Only the WordPress connector has its initial registration path yet.
        // Do not present fake enrollment controls for Agent or SSH.
        return view('admin.targets.create');
    }

    public function store(
        Request $request,
        WpAiBridgeTargetRegistration $registration,
        SshTargetRegistration $sshRegistration,
        AccessControl $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsCreate->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'connector_type' => ['required', Rule::in(['wp_ai_bridge', 'ssh_direct'])],
            'target_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'display_name' => ['required', 'string', 'max:160'],
            'base_url' => ['required_if:connector_type,wp_ai_bridge', 'nullable', 'string', 'url:https', 'max:2048'],
            'ssh_host' => ['required_if:connector_type,ssh_direct', 'nullable', 'string', 'max:253'],
            'ssh_port' => ['required_if:connector_type,ssh_direct', 'nullable', 'integer', 'min:1', 'max:65535'],
            'ssh_username' => ['required_if:connector_type,ssh_direct', 'nullable', 'string', 'max:128'],
            'ssh_host_key' => ['required_if:connector_type,ssh_direct', 'nullable', 'string', 'max:4096'],
            'ssh_auth_method' => ['required_if:connector_type,ssh_direct', 'nullable', Rule::in(['password', 'private_key'])],
            'ssh_password' => ['required_if:ssh_auth_method,password', 'nullable', 'string', 'max:4096'],
            'ssh_private_key' => ['required_if:ssh_auth_method,private_key', 'nullable', 'string', 'max:16384'],
            'ssh_passphrase' => ['nullable', 'string', 'max:4096'],
            'ssh_trust_confirmed' => ['required_if:connector_type,ssh_direct', 'in:yes'],
        ]);

        if ($validated['connector_type'] === 'ssh_direct') {
            try {
                $method = (string) $validated['ssh_auth_method'];
                $target = $sshRegistration->register(
                    (string) $validated['target_id'],
                    (string) $validated['display_name'],
                    (string) $validated['ssh_host'],
                    (int) $validated['ssh_port'],
                    (string) $validated['ssh_username'],
                    (string) $validated['ssh_host_key'],
                    $method,
                    (string) ($validated[$method === 'password' ? 'ssh_password' : 'ssh_private_key'] ?? ''),
                    $method === 'private_key' ? ($validated['ssh_passphrase'] ?? null) : null,
                );
            } catch (InvalidArgumentException|RuntimeException) {
                return back()->withInput($request->except(['ssh_password', 'ssh_private_key', 'ssh_passphrase']))
                    ->withErrors(['ssh_host' => __('SSH registration could not be validated. Check the endpoint, trusted host key, authentication material and unique Target ID.')]);
            }
            $status = __('SSH Target registered with encrypted credentials and an out-of-band host-key pin. Authentication has NOT yet been verified.');
        } else {
            try {
                $target = $registration->register(
                    (string) $validated['target_id'],
                    (string) $validated['display_name'],
                    (string) $validated['base_url'],
                );
            } catch (BridgeDiscoveryException $exception) {
                return back()->withInput($request->except(['ssh_password', 'ssh_private_key', 'ssh_passphrase']))
                    ->withErrors(['base_url' => __('The WordPress connector metadata could not be verified (:reason).', ['reason' => $exception->reason])]);
            } catch (InvalidArgumentException) {
                return back()->withInput($request->except(['ssh_password', 'ssh_private_key', 'ssh_passphrase']))
                    ->withErrors(['target_id' => __('The Target ID or WordPress endpoint is invalid or already registered.')]);
            }
            $status = __('WordPress Target registered. Connection authorization is not yet configured.');
        }

        $access->includeCreatedTarget($user, $target);

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $status);
    }

    public function show(Target $target): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value, $target);

        $config = $target->connector_type === 'wp_ai_bridge'
            ? WpAiBridgeTargetConfig::query()->where('target_record_id', $target->getKey())->first()
            : null;

        $sshConfig = $target->connector_type === 'ssh_direct'
            ? SshTargetConfig::query()->where('target_record_id', $target->getKey())->first()
            : null;

        return view('admin.targets.show', [
            'target' => $target,
            'wpConfig' => $config,
            'sshConfig' => $sshConfig,
            'sshFingerprint' => $sshConfig instanceof SshTargetConfig ? SshHostKeyPin::fromLine($sshConfig->pinned_host_key)->fingerprint() : null,
            'sshHasCredential' => $target->connector_type === 'ssh_direct' && TargetCredential::query()
                ->where('target_record_id', $target->getKey())->where('connector_type', 'ssh_direct')
                ->where('purpose', 'ssh_auth')->exists(),
            'hasCredential' => $target->connector_type === 'wp_ai_bridge' && TargetCredential::query()
                ->where('target_record_id', $target->getKey())
                ->where('connector_type', 'wp_ai_bridge')
                ->where('purpose', 'wordpress_oauth')->exists(),
            'revocationPending' => $target->connector_type === 'wp_ai_bridge' && DB::table('wp_ai_bridge_revocation_intents')
                ->where('target_record_id', $target->getKey())->exists(),
            'refreshIntent' => $target->connector_type === 'wp_ai_bridge'
                ? DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $target->getKey())->first(['id', 'created_at'])
                : null,
            'refreshPending' => $target->connector_type === 'wp_ai_bridge' && DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $target->getKey())->exists(),
            'canRemoveSafely' => ! TargetCredential::query()->where('target_record_id', $target->getKey())->exists()
                && ! DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $target->getKey())->exists()
                && ! DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $target->getKey())->exists()
                && ! DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $target->getKey())->exists()
                && ! in_array($target->getAttribute('connection_state'), [
                    TargetConnectionState::Connected,
                    TargetConnectionState::Pending,
                    TargetConnectionState::Reassigning,
                ], true),
        ]);
    }

    public function edit(Target $target): View
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);

        return view('admin.targets.edit', ['target' => $target]);
    }

    public function update(Request $request, Target $target): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        $validated = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
        ]);

        DB::transaction(static function () use ($target, $validated): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $locked->forceFill(['display_name' => (string) $validated['display_name']])->save();
        });

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Target display name updated.'));
    }

    public function destroy(Request $request, Target $target, ActivityRecorder $activity): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsRemove->value, $target);
        $request->validate(['confirm_remove' => ['required', 'in:yes']]);

        try {
            DB::transaction(static function () use ($target, $activity): void {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
                $id = $locked->getKey();

                if (TargetCredential::query()->where('target_record_id', $id)->exists()
                    || DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $id)->exists()
                    || DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $id)->exists()
                    || DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $id)->exists()
                    || in_array($locked->getAttribute('connection_state'), [
                        TargetConnectionState::Connected,
                        TargetConnectionState::Pending,
                        TargetConnectionState::Reassigning,
                    ], true)) {
                    throw new DomainException('connection_cleanup_required');
                }

                $activity->recordRequired(CorrelationId::current(), 'target-remove', 'success', $locked);
                if (! $locked->delete()) {
                    throw new RuntimeException('target_delete_failed');
                }
            });
        } catch (DomainException) {
            return back()->withErrors([
                'target' => __('Disconnect and reconcile any pending connector credential or authorization before removing the Target.'),
            ]);
        }

        return redirect()->route('admin.targets.index')
            ->with('status', __('Target removed.'));
    }

    private function trimmed(?string $text): ?string
    {
        $trimmed = $text === null ? null : trim($text);

        return $trimmed === '' ? null : $trimmed;
    }
}
