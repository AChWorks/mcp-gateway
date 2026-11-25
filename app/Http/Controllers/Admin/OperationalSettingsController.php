<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Http\Controllers\Controller;
use App\Support\OutboundDnsCompatibility;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

final class OperationalSettingsController extends Controller
{
    public function index(OperationalSettings $settings): View
    {
        Gate::authorize(GatewayPermission::SecurityManage->value);

        return view('admin.operations.index', [
            'state' => $settings->state(),
            'definitions' => OperationalSettings::allowed(),
            'dnsCompatibility' => OutboundDnsCompatibility::snapshot(),
            'defaults' => $settings->defaults(),
        ]);
    }

    public function update(
        Request $request,
        OperationalSettings $settings,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $definitions = OperationalSettings::allowed();
        $rules = [
            'version' => ['required', 'integer', 'min:0'],
            'values' => ['required', 'array'],
        ];
        foreach ($definitions as $key => $definition) {
            $rules['values.'.$key] = [
                'sometimes',
                'nullable', 'integer',
                'min:'.$definition['minimum'], 'max:'.$definition['maximum'],
            ];
        }
        $validated = $request->validate($rules);
        $submitted = $validated['values'];
        $names = array_keys((array) $request->input('values', []));
        if (! OperationalSettings::acceptsFormKeys($names)) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }
        $values = array_map(
            static fn (mixed $value): ?int => $value === null || $value === '' ? null : (int) $value,
            $submitted,
        );

        // The password is consumed only by the shared confirmation service,
        // never passed to a settings persistence class or written to audit.
        $actor = $confirmation->confirm($request);
        $settings->save($actor, $values, (int) $validated['version']);

        return redirect()->route('admin.operations.index')
            ->with('status', __('Operational settings saved. New requests use the updated limits.'));
    }
}
