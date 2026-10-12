<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayRole;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

final class OperationalSettingsController extends Controller
{
    public function index(Request $request, OperationalSettings $settings): View
    {
        $this->requireOwner($request);

        return view('admin.operations.index', [
            'state' => $settings->state(),
            'definitions' => OperationalSettings::allowed(),
            'defaults' => [
                'wp_response_kib' => (int) config('bridge.http.max_response_bytes', 65536) / 1024,
                'wp_readonly_response_kib' => (int) config('bridge.http.readonly_tool_max_response_bytes', 262144) / 1024,
                'wp_connect_timeout_seconds' => max(1, (int) config('bridge.http.connect_timeout_seconds', 2)),
                'wp_request_timeout_seconds' => max(
                    1,
                    (int) config('bridge.http.connect_timeout_seconds', 2),
                    (int) config('bridge.http.request_timeout_seconds', 5),
                ),
                'ssh_transfer_max_kib' => min(65536, max(1, (int) config('ssh.file_transfer.max_bytes', 8388608) / 1024)),
                'ssh_transfer_max_seconds' => min(40, max(1, (int) config('ssh.file_transfer.max_seconds', 30))),
            ],
        ]);
    }

    public function update(
        Request $request,
        OperationalSettings $settings,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        $this->requireOwner($request);
        $definitions = OperationalSettings::allowed();
        $rules = [
            'version' => ['required', 'integer', 'min:0'],
            'values' => ['required', 'array'],
        ];
        foreach ($definitions as $key => $definition) {
            $rules['values.'.$key] = [
                in_array($key, ['wp_response_kib', 'wp_readonly_response_kib'], true)
                    ? 'present' : 'sometimes',
                'nullable', 'integer',
                'min:'.$definition['minimum'], 'max:'.$definition['maximum'],
            ];
        }
        $validated = $request->validate($rules);
        $submitted = $validated['values'];
        $names = array_keys((array) $request->input('values', []));
        $all = array_keys($definitions);
        $legacy = array_slice($all, 0, 2);
        $preSsh = array_slice($all, 0, 4);
        sort($names);
        sort($all);
        sort($legacy);
        sort($preSsh);
        if ($names !== $all && $names !== $legacy && $names !== $preSsh) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }

        // Forms opened on the previous version still submit only the two
        // response budgets. Preserve both timeout overrides instead of
        // silently resetting them when an older tab is submitted.
        $saved = $names !== $all ? $settings->state()['overrides'] : [];
        $values = [];
        foreach ($definitions as $key => $definition) {
            $value = array_key_exists($key, $submitted) ? $submitted[$key] : ($saved[$key] ?? null);
            $values[$key] = $value === null || $value === '' ? null : (int) $value;
        }

        // The password is consumed only by the shared confirmation service,
        // never passed to a settings persistence class or written to audit.
        $actor = $confirmation->confirm($request);
        $settings->save($actor, $values, (int) $validated['version']);

        return redirect()->route('admin.operations.index')
            ->with('status', __('Operational settings saved. New requests use the updated limits.'));
    }

    private function requireOwner(Request $request): User
    {
        $user = $request->user();
        abort_unless($user instanceof User && (string) $user->getRawOriginal('role') === GatewayRole::Owner->value
            && $user->access_enabled, 403);

        return $user;
    }
}
