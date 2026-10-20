<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/** Owner-managed semantic grants, independent of whether the user connects AI. */
final class UserWordpressPublishGrantController extends Controller
{
    public function index(User $user): View
    {
        Gate::authorize(GatewayPermission::SecurityManage->value);

        $groups = TargetGroup::query()
            ->whereHas('users', static fn ($query) => $query->whereKey($user->getKey()))
            ->whereHas('targets', static fn ($query) => $query->where('connector_type', 'wp_ai_bridge'))
            ->orderBy('name')->limit(100)->get();

        $grants = DB::table('wordpress_publish_group_grants as grants')
            ->join('target_groups as groups', 'groups.id', '=', 'grants.target_group_id')
            ->where('grants.user_id', $user->getKey())
            ->orderBy('groups.name')->orderBy('grants.id')
            ->select(['grants.id', 'grants.target_group_id', 'groups.name as group_name'])->get();

        return view('admin.users.wordpress-publishing', [
            'managedUser' => $user, 'groups' => $groups, 'grants' => $grants,
            'canPublish' => $this->canPublishRole($user),
        ]);
    }

    public function store(
        Request $request,
        User $user,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $confirmation->confirm($request);
        $validated = $request->validate([
            'group_id' => ['required', 'string', Rule::exists('target_groups', 'id')],
        ]);

        DB::transaction(function () use ($user, $validated, $activity): void {
            $group = TargetGroup::query()->whereKey($validated['group_id'])->lockForUpdate()->firstOrFail();
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            if (! $this->canPublishRole($lockedUser) || ! $lockedUser->access_enabled
                || ! $group->users()->whereKey($lockedUser->getKey())->exists()
                || ! $group->targets()->where('connector_type', 'wp_ai_bridge')->exists()) {
                throw ValidationException::withMessages([
                    'group_id' => __('Select a WordPress Target Group assigned to an enabled Administrator or Operator.'),
                ]);
            }

            DB::table('wordpress_publish_group_grants')->updateOrInsert([
                'user_id' => $lockedUser->getKey(), 'target_group_id' => $group->getKey(),
            ], ['updated_at' => now(), 'created_at' => now()]);
            $activity->recordRequired(CorrelationId::current(), 'wordpress-publish-grant-create', 'success');
        });

        return redirect()->route('admin.users.publishing.index', ['user' => $user->getKey()])
            ->with('status', __('Scoped publishing authority updated. AI connectivity is configured separately.'));
    }

    public function destroy(
        Request $request,
        User $user,
        string $grant,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $confirmation->confirm($request);
        abort_unless(ctype_digit($grant) && strlen($grant) <= 20, 404);

        DB::transaction(static function () use ($user, $grant, $activity): void {
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $deleted = DB::table('wordpress_publish_group_grants')
                ->where('id', $grant)->where('user_id', $user->getKey())->delete();
            abort_unless($deleted === 1, 404);
            $activity->recordRequired(CorrelationId::current(), 'wordpress-publish-grant-revoke', 'success');
        });

        return redirect()->route('admin.users.publishing.index', ['user' => $user->getKey()])
            ->with('status', __('Publishing authority revoked.'));
    }

    private function canPublishRole(User $user): bool
    {
        return in_array((string) $user->getRawOriginal('role'), [
            GatewayRole::Operator->value, GatewayRole::Administrator->value,
        ], true);
    }
}
