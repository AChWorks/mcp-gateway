<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayRole;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
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
            ],
        ]);
    }

    public function update(
        Request $request,
        OperationalSettings $settings,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        $this->requireOwner($request);
        $validated = $request->validate([
            'version' => ['required', 'integer', 'min:0'],
            'values' => ['required', 'array', 'size:2'],
            'values.wp_response_kib' => ['present', 'nullable', 'integer', 'min:16', 'max:1024'],
            'values.wp_readonly_response_kib' => ['present', 'nullable', 'integer', 'min:16', 'max:2048'],
        ]);
        $submitted = $validated['values'];
        $values = [];
        foreach (OperationalSettings::allowed() as $key => $definition) {
            $value = $submitted[$key] ?? null;
            $values[$key] = $value === null || $value === '' ? null : (int) $value;
        }

        // The password is consumed only by the shared confirmation service,
        // never passed to a settings persistence class or written to audit.
        $actor = $confirmation->confirm($request);
        $settings->save($actor, $values, (int) $validated['version']);

        return redirect()->route('admin.operations.index')
            ->with('status', __('Operational response limits saved. New requests use the updated budgets.'));
    }

    private function requireOwner(Request $request): User
    {
        $user = $request->user();
        abort_unless($user instanceof User && (string) $user->getRawOriginal('role') === GatewayRole::Owner->value
            && $user->access_enabled, 403);

        return $user;
    }
}
