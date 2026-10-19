<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayRole;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Support\OutboundDnsCompatibility;
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
            'dnsCompatibility' => OutboundDnsCompatibility::snapshot(),
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
                'ssh_command_timeout_seconds' => 15,
                'ssh_command_max_kib' => 8,
                'ssh_job_max_active_per_user' => 2,
                'ssh_job_max_runtime_seconds' => 300,
                'ssh_job_retention_hours' => 24,
                'ssh_job_preparing_grace_seconds' => 120,
                'ssh_job_reconcile_grace_seconds' => 600,
                'ssh_job_max_script_kib' => 16,
                'ssh_command_stdout_kib' => 16,
                'ssh_command_stderr_kib' => 8,
                'ssh_job_output_window_kib' => 16,
                'ssh_file_read_window_kib' => 16,
                'ssh_file_write_window_kib' => 16,
                'ssh_file_list_name_kib' => 16,
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
        $preSshCommand = array_slice($all, 0, 6);
        $preSshJobs = array_slice($all, 0, 8);
        $preScriptBudget = array_slice($all, 0, 13);
        $prePayloadBudgets = array_slice($all, 0, 14);
        sort($names);
        sort($all);
        sort($legacy);
        sort($preSsh);
        sort($preSshCommand);
        sort($preSshJobs);
        sort($preScriptBudget);
        sort($prePayloadBudgets);
        if ($names !== $all && $names !== $legacy && $names !== $preSsh && $names !== $preSshCommand && $names !== $preSshJobs && $names !== $preScriptBudget && $names !== $prePayloadBudgets) {
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
