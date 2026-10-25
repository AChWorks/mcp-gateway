@extends('admin.layout')

@section('title', __('AI clients'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Security') }}</div>
        <h1>{{ __('Approved AI client applications') }}</h1>
        <p class="muted">{{ __('Profiles identify authenticated MCP applications, not individual AI accounts. Client labels never grant Target permissions.') }}</p>
    </div>
</div>

<section class="panel panel-wide">
    <h2>{{ __('Supported client profiles') }}</h2>
    <div class="table-wrap">
        <table>
            <thead><tr>
                <th scope="col">{{ __('Profile') }}</th>
                <th scope="col">{{ __('Protocol client ID') }}</th>
                <th scope="col">{{ __('Authentication') }}</th>
                <th scope="col">{{ __('Lifecycle') }}</th>
            </tr></thead>
            <tbody>
            @foreach ($profiles as $profile)
                @php
                    $stored = $registered[$profile['key']] ?? null;
                    $identityMatches = $stored !== null
                        && $stored->client_id === $profile['client_id']
                        && $stored->auth_strategy === $profile['strategy'];
                    $isRetired = (bool) ($profile['retired'] ?? false);
                    $isActive = $profile['enabled'] && !$isRetired && $identityMatches && $stored->disabled_at === null;
                @endphp
                <tr>
                    <td>
                        <strong>{{ $profile['display_name'] }}</strong>
                        <code>{{ $profile['key'] }}</code>
                    </td>
                    <td><code class="small-code">{{ $profile['client_id'] }}</code></td>
                    <td><code>{{ $profile['strategy'] }}</code></td>
                    <td>
                        <span class="badge badge-{{ $isActive ? 'success' : 'danger' }}">{{ $isRetired ? __('Retired (permanent)') : ($isActive ? __('Enabled') : __('Disabled / unregistered')) }}</span>
                    </td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
    <nav class="pagination" aria-label="{{ __('DCR client profile pages') }}">
        {{ $dcrPage->links() }}
    </nav>
    <p class="muted">{{ __('Configured profiles always appear above. DCR profiles are paginated and the Exact profile key filter below can find an older record. Registered identities remain immutable; only never-authorized clients older than 24 hours may be retired automatically under admission pressure. The administrator CLI can explicitly disable a DCR client and retire its unused registration after consent revocation. Retirement frees one slot without deleting identity history or restoring credentials; it cannot be reversed.') }}</p>
</section>

<section class="panel panel-wide ai-client-authorizations">
    <h2>{{ __('Client authorizations') }}</h2>
    <form class="filter-grid" method="get" action="{{ route('admin.oauth-clients.index') }}">
        <div class="field">
            <label for="profile">{{ __('Exact profile key') }}</label>
            <input id="profile" name="profile" type="text" maxlength="48" value="{{ $profileFilter ?? '' }}">
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.oauth-clients.index') }}">{{ __('Clear') }}</a>
        </div>
    </form>
    @if ($authorizations->isEmpty())
        <p class="empty-state">{{ __('No authorization records match this filter.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th scope="col">{{ __('Profile / ID') }}</th>
                    <th scope="col">{{ __('Gateway user') }}</th>
                    <th scope="col">{{ __('Authorized resource') }}</th>
                    <th scope="col">{{ __('Status') }}</th>
                    <th scope="col">{{ __('Created') }}</th>
                    <th scope="col">{{ __('Revoke') }}</th>
                </tr></thead>
                <tbody>
                @foreach ($authorizations as $grant)
                    <tr>
                        <td>
                            <code>{{ $grant->client_profile_key ?? 'unknown' }}</code>
                            <small><code class="small-code">{{ $grant->client_id }}</code></small>
                        </td>
                        <td>{{ $grant->user_email }}</td>
                        <td><code class="small-code">{{ $grant->resource }}</code></td>
                        <td>
                            <span class="badge badge-{{ $grant->revoked_at === null ? 'success' : 'danger' }}">
                                {{ $grant->revoked_at === null ? __('Not revoked') : __('Revoked') }}
                            </span>
                        </td>
                        <td><time datetime="{{ $grant->created_at }}">{{ $grant->created_at }}</time></td>
                        <td>
                            @if ($grant->revoked_at === null)
                                <form class="client-grant-revoke-form" method="post" action="{{ route('admin.oauth-clients.revoke', ['authorization' => $grant->id]) }}">
                                    @csrf
                                    @method('DELETE')
                                    <label for="password-{{ $grant->id }}">{{ __('Current Owner password') }}</label>
                                    <input id="password-{{ $grant->id }}" name="current_password" type="password" autocomplete="current-password" required maxlength="255">
                                    <button class="button button-secondary" type="submit">{{ __('Revoke this grant') }}</button>
                                </form>
                            @else
                                <span class="muted">{{ __('Already revoked') }}</span>
                            @endif
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif

    <nav class="pagination" aria-label="{{ __('Authorization pages') }}">
        {{ $authorizations->links() }}
    </nav>
</section>
@endsection
