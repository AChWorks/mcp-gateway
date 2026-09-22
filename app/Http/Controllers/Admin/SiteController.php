<?php

namespace App\Http\Controllers\Admin;

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteInventory;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Support\Admin\SiteOperationMessage;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\View\View;
use InvalidArgumentException;

final class SiteController extends Controller
{
    public function __construct(private readonly SiteOperationMessage $messages) {}

    public function index(Request $request, SiteInventory $inventory): View
    {
        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(SiteConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);
        $search = $this->nullableTrim($validated['search'] ?? null);
        $connectionState = $this->nullableTrim($validated['connection_state'] ?? null);
        $page = (int) ($validated['page'] ?? 1);
        $inventoryPage = $inventory->adminPage($page, $search, $connectionState);

        return view('admin.sites.index', [
            'sites' => collect($inventoryPage['items'])
                ->map(fn (Site $site): array => $this->presentInventory($site)),
            'pagination' => [
                'page' => $inventoryPage['page'],
                'per_page' => $inventoryPage['per_page'],
                'has_more' => $inventoryPage['has_more'],
            ],
            'filters' => [
                'search' => $search,
                'connection_state' => $connectionState,
            ],
            'connectionStates' => $this->connectionStateOptions(),
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

    /** @return array{site:Site,status_label:string,status_tone:string} */
    private function presentInventory(Site $site): array
    {
        [$statusLabel, $statusTone] = $this->status($site);

        return [
            'site' => $site,
            'status_label' => $statusLabel,
            'status_tone' => $statusTone,
        ];
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

    /** @return array<string,string> */
    private function connectionStateOptions(): array
    {
        $options = [];

        foreach (SiteConnectionState::cases() as $state) {
            $options[$state->value] = match ($state) {
                SiteConnectionState::Connected => (string) __('Connected'),
                SiteConnectionState::Pending => (string) __('Authorization pending'),
                SiteConnectionState::ReconnectRequired => (string) __('Reconnect required'),
                SiteConnectionState::Reassigning => (string) __('Updating target'),
                SiteConnectionState::Disconnected => (string) __('Configured'),
                SiteConnectionState::Error => (string) __('Needs attention'),
            };
        }

        return $options;
    }

    /** @return array{0:string,1:string} */
    private function status(Site $site): array
    {
        $state = (string) $site->getRawOriginal('connection_state');

        if ($state === SiteConnectionState::Error->value) {
            return match ($site->last_error_code) {
                'network_failure', 'tls_failure' => [(string) __('Unreachable'), 'danger'],
                'missing_bridge', 'incompatible_metadata' => [(string) __('Incompatible'), 'danger'],
                default => [(string) __('Needs attention'), 'danger'],
            };
        }

        return match ($state) {
            SiteConnectionState::Connected->value => [(string) __('Connected'), 'success'],
            SiteConnectionState::Pending->value => [(string) __('Authorization pending'), 'warning'],
            SiteConnectionState::ReconnectRequired->value => [(string) __('Reconnect required'), 'warning'],
            SiteConnectionState::Reassigning->value => [(string) __('Updating target'), 'warning'],
            SiteConnectionState::Disconnected->value => [(string) __('Configured'), 'neutral'],
            default => [(string) __('Needs attention'), 'danger'],
        };
    }
    private function nullableTrim(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }

}
