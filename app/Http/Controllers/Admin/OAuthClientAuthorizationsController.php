<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Domain\Access\GatewayPermission;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Support\CorrelationId;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

final class OAuthClientAuthorizationsController extends Controller
{
    public function index(Request $request, ClientProfileRegistry $profiles): View
    {
        // Unlike individual MCP access, the registry spans every local user's
        // grants. View/revoke must not leak to ordinary Operators or Viewers.
        Gate::authorize(GatewayPermission::SecurityManage->value);

        $validated = $request->validate([
            'profile' => ['nullable', 'string', 'max:48', 'regex:/^[a-z][a-z0-9_-]*$/D'],
        ]);
        $profileKey = $validated['profile'] ?? null;
        $configured = $profiles->configured();
        $registered = DB::table('oauth_client_profiles')->get()->keyBy('profile_key');

        $authorizations = DB::table('oauth_authorizations as grants')
            ->join('users', 'users.id', '=', 'grants.user_id')
            ->select([
                'grants.id',
                'grants.client_id',
                'grants.client_profile_key',
                'grants.client_profile_generation',
                'grants.resource',
                'grants.revoked_at',
                'grants.created_at',
                'users.email as user_email',
            ])
            ->when(is_string($profileKey), static fn ($query) => $query->where('grants.client_profile_key', $profileKey))
            ->orderByDesc('grants.created_at')
            ->orderByDesc('grants.id')
            ->simplePaginate(50)
            ->withQueryString();

        return view('admin.oauth-clients.index', [
            'profiles' => $configured,
            'registered' => $registered,
            'authorizations' => $authorizations,
            'profileFilter' => $profileKey,
        ]);
    }

    public function revoke(
        Request $request,
        string $authorization,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $confirmation->confirm($request);

        if (preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/D', $authorization) !== 1) {
            throw new NotFoundHttpException;
        }

        DB::transaction(static function () use ($authorization, $request, $activity): void {
            $row = DB::table('oauth_authorizations')
                ->where('id', $authorization)
                ->lockForUpdate()
                ->first(['client_id', 'client_profile_key', 'revoked_at']);

            if ($row === null) {
                throw new NotFoundHttpException;
            }

            if ($row->revoked_at !== null) {
                return;
            }

            DB::table('oauth_authorizations')
                ->where('id', $authorization)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'updated_at' => now()]);

            $request->attributes->set('oauth_client_id', (string) $row->client_id);
            $request->attributes->set('oauth_client_profile_key', (string) $row->client_profile_key);
            $activity->recordRequired(
                CorrelationId::current(),
                'oauth-client-authorization-revoked',
                'success',
            );
        });

        return redirect()->route('admin.oauth-clients.index')
            ->with('status', __('Client authorization revoked; its tokens are no longer accepted.'));
    }
}
