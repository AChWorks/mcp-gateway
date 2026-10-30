<?php

namespace App\Http\Controllers\Admin;

use App\Application\Admin\AdminNavigation;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

final readonly class AdministrationAccessController
{
    public function __invoke(Request $request, AdminNavigation $navigation): View|RedirectResponse
    {
        $user = $request->user();
        abort_unless($user instanceof User, 401);
        $destination = $navigation->landingUrl($user);

        return $destination === route('admin.access')
            ? view('admin.no-access')
            : redirect()->to($destination);
    }
}
