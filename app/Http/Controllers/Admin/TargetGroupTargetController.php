<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

final class TargetGroupTargetController extends Controller
{
    public function edit(
        TargetGroup $targetGroup,
        Target $target,
        TargetGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.targets.edit', [
            'targetGroup' => $targetGroup,
            'target' => $target,
            'assigned' => $groups->targetIsAssigned($targetGroup, $target),
        ]);
    }

    public function update(
        Request $request,
        TargetGroup $targetGroup,
        Target $target,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $request->validate(['assigned' => ['nullable', 'boolean']]);

        try {
            $groups->updateTargetMembership($targetGroup, $target, $request->boolean('assigned'),
                $request->boolean('confirm_ssh_group_changes'));
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'ssh_confirmation_required') {
                throw ValidationException::withMessages([
                    'confirm_ssh_group_changes' => __(
                        'Confirm changing SSH Target membership. It can enable SSH reachability or remove an existing SSH restriction.',
                    ),
                ]);
            }
            throw $exception;
        }

        return redirect()
            ->route('admin.target-groups.targets.edit', [
                'targetGroup' => $targetGroup->id,
                'target' => $target->target_id,
            ])
            ->with('status', __('Target group membership updated.'));
    }
}
