<?php

namespace App\Http\Controllers\Admin;

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Http\Controllers\Controller;
use App\Support\Admin\SiteOperationMessage;
use Illuminate\Http\RedirectResponse;

final class SiteConnectionController extends Controller
{
    public function __construct(private readonly SiteOperationMessage $messages) {}

    public function connect(Site $site, SiteConnectionService $connections): RedirectResponse
    {
        try {
            return redirect()->away($connections->begin($site));
        } catch (SiteConnectionException $exception) {
            return $this->failed($site, $exception);
        }
    }

    public function reconnect(Site $site, SiteConnectionService $connections): RedirectResponse
    {
        try {
            if ($site->credential()->exists()) {
                $connections->disconnect($site);
            }

            return redirect()->away($connections->begin($site->refresh()));
        } catch (SiteConnectionException $exception) {
            return $this->failed($site, $exception);
        }
    }

    public function disconnect(Site $site, SiteConnectionService $connections): RedirectResponse
    {
        try {
            $connections->disconnect($site);
        } catch (SiteConnectionException $exception) {
            return $this->failed($site, $exception);
        }

        return redirect()
            ->route('admin.sites.show', ['site' => $site->site_id])
            ->with('status', __('Site disconnected and its credential was revoked.'));
    }

    public function test(Site $site, SiteRegistry $registry): RedirectResponse
    {
        try {
            $registry->test($site);
        } catch (SiteConnectionException $exception) {
            return $this->failed($site, $exception);
        }

        return redirect()
            ->route('admin.sites.show', ['site' => $site->site_id])
            ->with('status', __('WP AI Bridge metadata is reachable and compatible.'));
    }

    private function failed(Site $site, SiteConnectionException $exception): RedirectResponse
    {
        return redirect()
            ->route('admin.sites.show', ['site' => $site->site_id])
            ->withErrors(['site' => $this->messages->forConnectionException($exception)]);
    }
}
