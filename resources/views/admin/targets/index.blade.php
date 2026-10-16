@extends('admin.layout')

@section('title', __('Targets'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Connectors') }}</div>
        <h1>{{ __('Gateway Targets') }}</h1>
        <p class="muted">{{ __('One stable Target ID per connector endpoint. Results are limited to your permitted Targets.') }}</p>
    </div>
    @can('targets.create')
        <a class="button button-primary" href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
    @endcan
</div>

<section class="panel panel-wide" aria-labelledby="targets-list-title">
    <h2 id="targets-list-title" class="sr-only">{{ __('Registered Targets') }}</h2>
    <form method="get" action="{{ route('admin.targets.index') }}" class="filter-grid">
        <div class="field">
            <label for="search">{{ __('Search Target name, ID, SSH host or IP') }}</label>
            <input id="search" name="search" type="search" maxlength="160" value="{{ $filters['search'] ?? '' }}">
        </div>
        <div class="field">
            <label for="connection_state">{{ __('Connection state') }}</label>
            <select id="connection_state" name="connection_state">
                <option value="">{{ __('Any state') }}</option>
                @foreach ($connectionStates as $state)
                    <option value="{{ $state->value }}" @selected($filters['connection_state'] === $state->value)>{{ str_replace('_', ' ', ucfirst($state->value)) }}</option>
                @endforeach
            </select>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.targets.index') }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($inventory['items'] === [])
        <p class="empty-state">{{ __('No permitted Targets match the selected filters.') }}</p>
    @else
        <div class="table-wrap targets-table-wrap">
            <table class="targets-table">
                <colgroup>
                    <col class="targets-col-identity">
                    <col class="targets-col-connector">
                    <col class="targets-col-connection">
                    <col class="targets-col-operations">
                    <col class="targets-col-actions">
                </colgroup>
                <thead>
                    <tr>
                        <th scope="col">{{ __('Target') }}</th>
                        <th scope="col">{{ __('Connector') }}</th>
                        <th scope="col">{{ __('Connection') }}</th>
                        <th scope="col">{{ __('Gateway operations') }}</th>
                        <th scope="col">{{ __('Actions') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($inventory['items'] as $target)
                        @php($recovery = $recoveries[$target->target_id] ?? null)
                        @php($sshIdentity = $target->connector_type === 'ssh_direct' && $target->sshConfig !== null
                            ? \App\Infrastructure\Connectors\SshDirect\SshTargetIdentity::safeMetadata($target) : null)
                        @php($connectionTone = match ($target->connection_state->value) {
                            'connected' => 'success',
                            'error' => 'danger',
                            'pending', 'reassigning', 'reconnect_required' => 'warning',
                            default => 'neutral',
                        })
                        <tr>
                            <td>
                                <span class="targets-mobile-label" aria-hidden="true">{{ __('Target') }}</span>
                                <div class="target-cell target-cell-identity">
                                    <strong class="target-display-name">{{ $target->display_name }}</strong>
                                    <code class="small-code">{{ $target->target_id }}</code>
                                    @if ($sshIdentity !== null)
                                        <code class="small-code target-meta">{{ $sshIdentity['destination_label'] }}</code>
                                        <span class="target-meta">{{ __('SSH IP status') }}: {{ str_replace('_', ' ', $sshIdentity['ip_status']) }}</span>
                                    @endif
                                </div>
                            </td>
                            <td>
                                <span class="targets-mobile-label" aria-hidden="true">{{ __('Connector') }}</span>
                                <div class="target-cell">
                                    <strong>{{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress') : __('Direct SSH') }}</strong>
                                    <code class="small-code">{{ $target->connector_type }}</code>
                                </div>
                            </td>
                            <td>
                                <span class="targets-mobile-label" aria-hidden="true">{{ __('Connection') }}</span>
                                <div class="target-cell target-cell-status">
                                    <span><span class="badge badge-{{ $connectionTone }}">{{ str_replace('_', ' ', ucfirst($target->connection_state->value)) }}</span></span>
                                    @if ($target->connector_type === 'wp_ai_bridge' && $recovery !== null)
                                        <span class="target-meta target-auth-status {{ $recovery['tone'] === 'caution' || ! $recovery['credential_present'] ? 'target-status-attention' : '' }}">
                                            <strong>{{ __('OAuth') }}:</strong> {{ $recovery['title'] }}
                                        </span>
                                        @if ($recovery['canFinish'])
                                            <span class="target-meta">{{ __('Safe completion available — inspect Target') }}</span>
                                        @endif
                                    @elseif ($sshIdentity !== null)
                                        <span class="target-meta">{{ __('SSH connection last verified; not a live check') }}</span>
                                        @if (! empty($sshIdentity['observed_at']))
                                            <time class="target-meta" datetime="{{ $sshIdentity['observed_at'] }}">{{ $sshIdentity['observed_at'] }}</time>
                                        @endif
                                    @endif
                                </div>
                            </td>
                            <td>
                                <span class="targets-mobile-label" aria-hidden="true">{{ __('Gateway operations') }}</span>
                                <div class="target-cell target-cell-status">
                                    <span><span class="badge badge-{{ $target->operations_paused ? 'warning' : 'neutral' }}">{{ $target->operations_paused ? __('Paused') : __('Enabled') }}</span></span>
                                    <span class="target-meta">{{ $target->operations_paused ? __('New Target operations are blocked') : __('Subject to access permissions') }}</span>
                                </div>
                            </td>
                            <td class="table-action targets-actions-cell">
                                <span class="targets-mobile-label" aria-hidden="true">{{ __('Actions') }}</span>
                                <div class="target-actions">
                                    <a class="button button-secondary target-action-button" href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Inspect') }}</a>
                                    @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
                                        <details class="target-action-confirm">
                                            <summary class="button button-secondary target-action-button">{{ $target->operations_paused ? __('Resume') : __('Pause') }}</summary>
                                            <div class="target-action-confirm-body">
                                                <p>{{ $target->operations_paused
                                                    ? __('Resume new Gateway operations for this Target?')
                                                    : __('Block new Gateway operations for this Target?') }}
                                                    <strong>{{ $target->display_name }}</strong>
                                                </p>
                                                <form method="post" action="{{ route('admin.targets.operations.update', ['target' => $target->target_id]) }}">
                                                    @csrf
                                                    <input type="hidden" name="state" value="{{ $target->operations_paused ? 'enabled' : 'paused' }}">
                                                    <button class="button {{ $target->operations_paused ? 'button-primary' : 'button-secondary' }} target-action-button" type="submit">{{ $target->operations_paused ? __('Confirm Resume') : __('Confirm Pause') }}</button>
                                                </form>
                                            </div>
                                        </details>
                                    @endif
                                </div>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endif

    <nav class="pagination" aria-label="{{ __('Target pages') }}">
        @if ($inventory['page'] > 1)
            <a class="button button-secondary" rel="prev" href="{{ route('admin.targets.index', [...$baseQuery, 'page' => $inventory['page'] - 1]) }}">{{ __('Previous') }}</a>
        @else
            <span></span>
        @endif
        <span>{{ __('Page :page', ['page' => $inventory['page']]) }}</span>
        @if ($inventory['has_more'])
            <a class="button button-secondary" rel="next" href="{{ route('admin.targets.index', [...$baseQuery, 'page' => $inventory['page'] + 1]) }}">{{ __('Next') }}</a>
        @endif
    </nav>
</section>
@endsection
