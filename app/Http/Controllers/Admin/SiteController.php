<?php

namespace App\Http\Controllers\Admin;

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Support\Admin\SiteOperationMessage;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\View\View;
use InvalidArgumentException;

final class SiteController extends Controller
{
    public function __construct(private readonly SiteOperationMessage $messages) {}

    public function index(): View
    {
        $sites = Site::query()
            ->withExists(['credential', 'revocationIntent', 'targetReservation'])
            ->orderBy('display_name')
            ->get();

        return view('admin.sites.index', [
            'sites' => $sites->map(fn (Site $site): array => $this->present($site)),
        ]);
    }

    public function create(): View
    {
        return view('admin.sites.create');
    }

    public function store(Request $request, SiteRegistry $registry): RedirectResponse
    {
        $validated = $this->validatedSite($request);

        try {
            $site = $registry->create(
                'site-'.strtolower((string) Str::ulid()),
                (string) $validated['display_name'],
                (string) $validated['base_url'],
            );
        } catch (SiteConnectionException $exception) {
            return back()
                ->withInput()
                ->withErrors(['site' => $this->messages->forConnectionException($exception)]);
        } catch (InvalidArgumentException) {
            return back()
                ->withInput()
                ->withErrors(['site' => $this->messages->invalidSiteDetails()]);
        }

        return redirect()
            ->route('admin.sites.show', ['site' => $site->site_id])
            ->with('status', __('Site added. You can now authorize its WP AI Bridge connection.'));
    }

    public function show(Site $site): View
    {
        $site->loadExists(['credential', 'revocationIntent', 'targetReservation']);

        return view('admin.sites.show', [
            'siteView' => $this->present($site),
        ]);
    }

    public function update(Request $request, Site $site, SiteRegistry $registry): RedirectResponse
    {
        $validated = $this->validatedSite($request);

        try {
            $site = $registry->update(
                $site,
                (string) $validated['display_name'],
                (string) $validated['base_url'],
            );
        } catch (SiteConnectionException $exception) {
            return back()
                ->withInput()
                ->withErrors(['site' => $this->messages->forConnectionException($exception)]);
        } catch (InvalidArgumentException) {
            return back()
                ->withInput()
                ->withErrors(['site' => $this->messages->invalidSiteDetails()]);
        }

        return redirect()
            ->route('admin.sites.show', ['site' => $site->site_id])
            ->with('status', __('Site details updated.'));
    }

    public function destroy(Request $request, Site $site, SiteRegistry $registry): RedirectResponse
    {
        $validated = $request->validate([
            'confirm_site_id' => ['required', 'string', 'max:64'],
        ]);
        $confirmation = trim((string) $validated['confirm_site_id']);

        if (! hash_equals($site->site_id, $confirmation)) {
            return back()->withErrors([
                'confirm_site_id' => __('Type the exact site ID to confirm removal.'),
            ]);
        }

        try {
            $registry->remove($site);
        } catch (SiteConnectionException $exception) {
            return back()->withErrors([
                'site' => $this->messages->forConnectionException($exception),
            ]);
        }

        return redirect()
            ->route('admin.sites.index')
            ->with('status', __('Site removed after its credential lifecycle was finalized.'));
    }

    /** @return array{display_name:string,base_url:string} */
    private function validatedSite(Request $request): array
    {
        /** @var array{display_name:string,base_url:string} $validated */
        $validated = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
            'base_url' => ['required', 'string', 'max:2048'],
        ]);

        return $validated;
    }

    /** @return array{site:Site,status_label:string,status_tone:string,has_credential:bool,has_revocation_intent:bool,has_target_reservation:bool} */
    private function present(Site $site): array
    {
        [$statusLabel, $statusTone] = $this->status($site);

        return [
            'site' => $site,
            'status_label' => $statusLabel,
            'status_tone' => $statusTone,
            'has_credential' => (bool) $site->getAttribute('credential_exists'),
            'has_revocation_intent' => (bool) $site->getAttribute('revocation_intent_exists'),
            'has_target_reservation' => (bool) $site->getAttribute('target_reservation_exists'),
        ];
    }

    /** @return array{0:string,1:string} */
    private function status(Site $site): array
    {
        if ($site->connection_state === SiteConnectionState::Error) {
            return match ($site->last_error_code) {
                'network_failure', 'tls_failure' => [(string) __('Unreachable'), 'danger'],
                'missing_bridge', 'incompatible_metadata' => [(string) __('Incompatible'), 'danger'],
                default => [(string) __('Needs attention'), 'danger'],
            };
        }

        return match ($site->connection_state) {
            SiteConnectionState::Connected => [(string) __('Connected'), 'success'],
            SiteConnectionState::Pending => [(string) __('Authorization pending'), 'warning'],
            SiteConnectionState::ReconnectRequired => [(string) __('Reconnect required'), 'warning'],
            SiteConnectionState::Reassigning => [(string) __('Updating target'), 'warning'],
            SiteConnectionState::Disconnected => [(string) __('Configured'), 'neutral'],
            SiteConnectionState::Error => [(string) __('Needs attention'), 'danger'],
        };
    }
}
