@extends('admin.layout')

@section('title', __($labels['noun']).' · '.$data['subject']['name'])

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ str_starts_with($context, 'group-') ? __('Target group') : __('User access') }}</div>
        <h1>{{ $data['subject']['name'] }}</h1>
        <p class="muted reading-width">{{ $data['subject']['detail'] }}</p>
    </div>
    <a href="{{ str_starts_with($context, 'group-') ? route('admin.target-groups.index') : route('admin.users.index') }}">{{ str_starts_with($context, 'group-') ? __('Back to groups') : __('Back to users') }}</a>
</div>

@include('admin.access-batches.context-nav', ['subject' => $data['subject']])

@if ($data['subject']['unrestricted'] ?? false)
    <p class="alert alert-success" role="status">{{ __('This user is an owner. Owners always have unrestricted all-target access and do not accept target overrides or narrowing group assignments.') }}</p>
@elseif (($data['subject']['scope_mode'] ?? null) === 'all')
    <p class="alert alert-info">{{ __('This user already has All targets scope, except direct denies. Assignments do not change that scope; group restrictions and direct exceptions still matter.') }}</p>
@endif
@if (($data['subject']['access_enabled'] ?? true) === false)
    <p class="alert alert-error" role="status">{{ __('This account is disabled. Editing its configured assignments does not enable sign-in or AI access.') }}</p>
@endif

<section class="panel panel-wide" aria-labelledby="access-members-title">
    <div class="section-heading">
        <div>
            <h2 id="access-members-title">{{ $filters['membership'] === 'available' ? __($labels['add']) : ($filters['membership'] === 'selected' ? __('Selected items') : __($labels['noun'])) }}</h2>
            <p class="muted reading-width">{{ $context === 'user-targets' ? __('Scope source describes reachability, not a grant of capabilities. Existing role, global, group and individual restrictions remain in effect.') : __('Manage explicit memberships. Removing a membership does not guarantee that every other access path is removed.') }}</p>
        </div>
        @unless ($data['subject']['unrestricted'] ?? false)
            @if ($filters['membership'] !== 'available')
                <a class="button button-primary" href="{{ $addUrl }}">{{ __($labels['add']) }}</a>
            @else
                <a class="button button-secondary" href="{{ $membersUrl }}">{{ __('View current members') }}</a>
            @endif
        @endunless
    </div>

    @error('selection')<p class="alert alert-error" role="alert">{{ $message }}</p>@enderror

    <form method="post" action="{{ route('admin.access-batches.selection', ['context' => $context, 'subject' => $subjectId]) }}"
          data-access-selection data-off-page-count="{{ $offPageCount }}" data-selection-count-label="{{ __(':count selected') }}">
        @csrf
        <input type="hidden" name="page" value="{{ $data['page'] }}">
        <input type="hidden" name="shown_intent" value="{{ $intent }}">
        <input type="hidden" name="shown_membership" value="{{ $filters['membership'] }}">
        <div class="filter-grid">
            <div class="field">
                <label for="access-search">{{ __('Search') }}</label>
                <input id="access-search" name="search" type="search" maxlength="160" value="{{ $filters['search'] }}" placeholder="{{ __('Name or identifier') }}" @error('search') aria-invalid="true" aria-describedby="access-search-error" @enderror>
                @error('search')<p class="field-error" id="access-search-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="access-membership">{{ __('Show') }}</label>
                <select id="access-membership" name="membership">
                    <option value="members" @selected($filters['membership'] === 'members')>{{ __('Current members') }}</option>
                    <option value="available" @selected($filters['membership'] === 'available')>{{ __('Available to add') }}</option>
                    <option value="all" @selected($filters['membership'] === 'all')>{{ __('All') }}</option>
                    <option value="selected" @selected($filters['membership'] === 'selected')>{{ __('Selected only') }}</option>
                </select>
            </div>
            @if ($connectorOptions !== [])
                <div class="field">
                    <label for="access-connector">{{ __('Connector') }}</label>
                    <select id="access-connector" name="connector_type">
                        <option value="">{{ __('All connectors') }}</option>
                        @foreach ($connectorOptions as $type => $label)
                            <option value="{{ $type }}" @selected($filters['connector_type'] === $type)>{{ $label }}</option>
                        @endforeach
                    </select>
                </div>
            @endif
            <div class="filter-actions">
                <button class="button button-secondary" name="action" value="filter" type="submit">{{ __('Search and filter') }}</button>
            </div>
        </div>

        @if ($context === 'user-targets' && !($data['subject']['unrestricted'] ?? false))
            <div class="field access-intent">
                <label for="access-intent">{{ __('Action for selected Targets') }}</label>
                <select id="access-intent" name="intent" aria-describedby="access-intent-help">
                    <option value="allow" @selected($intent === 'allow')>{{ __('Allow direct reachability') }}</option>
                    <option value="deny" @selected($intent === 'deny')>{{ __('Deny direct reachability') }}</option>
                    <option value="inherit" @selected($intent === 'inherit')>{{ __('Use inherited reachability') }}</option>
                </select>
                <p id="access-intent-help" class="field-help">{{ __('Changing the action starts a new selection from this page. Each action keeps individual capability denials. A direct Deny is not silently replaced by bulk Allow; review that exception in its individual editor.') }}</p>
            </div>
        @else
            <input type="hidden" name="intent" value="{{ $intent }}">
            @unless ($data['subject']['unrestricted'] ?? false)
                <p class="field-help">{{ $intent === 'add' ? __('Selected items will be added to this membership.') : __('Selected items will be removed from this membership only.') }}</p>
            @endunless
        @endif

        @unless ($data['subject']['unrestricted'] ?? false)
        <div class="selection-toolbar">
            <p role="status" aria-live="polite" aria-atomic="true" data-selection-count>{{ __('Saved selection: :count', ['count' => count($selectedIds)]) }}</p>
            <div class="action-row">
                <button class="button button-primary" type="submit" name="action" value="review">{{ __('Review selection') }}</button>
                <button class="button button-secondary" type="submit" name="action" value="select-page" data-select-page>{{ __('Select this page') }}</button>
                <button class="button button-secondary" type="submit" name="action" value="selected">{{ __('View selected') }}</button>
                <button class="button button-secondary" type="submit" name="action" value="clear">{{ __('Clear selection') }}</button>
            </div>
        </div>
        <p class="field-help access-selection-help">{{ __('Choose up to 100 explicit items. Search, paging and Review save the checkboxes on this page and preserve choices on other pages. Unchecked or unseen rows are never removal requests.') }}</p>
        @endunless

        @if ($data['items'] === [])
            <p class="empty-state">
                @if ($filters['membership'] === 'selected' && $selectedIds === [])
                    {{ __('No items are selected. Return to the members or available list to choose items.') }}
                @elseif ($filters['search'] !== '' || $filters['connector_type'] !== '')
                    {{ __('No items match these filters. Your saved selection is kept.') }}
                @elseif ($filters['membership'] === 'members')
                    {{ __('No members are assigned here yet. Use Add to choose members.') }}
                @else
                    {{ __('No items are available in this view.') }}
                @endif
            </p>
        @else
            <p id="access-table-scroll-help" class="field-help">{{ __('Scroll horizontally to view all columns on smaller screens.') }}</p>
            <div class="table-wrap" tabindex="0" role="region" aria-label="{{ __(':items for :name', ['items' => __($labels['noun']), 'name' => $data['subject']['name']]) }}" aria-describedby="access-table-scroll-help">
                <table class="access-selection-table">
                    <thead>
                    <tr>
                        <th scope="col"><span class="sr-only">{{ __('Select') }}</span></th>
                        <th scope="col">{{ __($labels['noun']) }}</th>
                        <th scope="col">{{ $context === 'user-targets' ? __('Direct rule and scope source') : __('Membership') }}</th>
                        <th scope="col"><span class="sr-only">{{ __('Details') }}</span></th>
                    </tr>
                    </thead>
                    <tbody>
                    @foreach ($data['items'] as $item)
                        @php($isSelected = in_array($item['id'], $selectedIds, true))
                        <tr>
                            <td>
                                @if ($item['eligible'] || $isSelected)
                                    <input type="hidden" name="page_ids[]" value="{{ $item['id'] }}">
                                    @if ($item['eligible'])<input type="hidden" name="selectable_ids[]" value="{{ $item['id'] }}">@endif
                                    <label class="selection-control">
                                        <input type="checkbox" name="selected_ids[]" value="{{ $item['id'] }}" @checked($isSelected) aria-label="{{ __('Select :name', ['name' => $item['label']]) }}" @if ($item['eligible']) data-selectable @endif @if (!$item['eligible'] && !$isSelected) disabled @endif>
                                    </label>
                                @else
                                    <span class="muted">{{ __('Unavailable') }}</span>
                                @endif
                            </td>
                            <td class="access-item-identity">
                                <strong>{{ $item['label'] }}</strong>
                                <span class="muted">{{ $item['detail'] }}</span>
                                @if ($item['connector_type'] !== null)<code dir="ltr">{{ $item['connector_type'] }}</code>@endif
                                @if ($item['unavailable_reason'] !== null)<span class="field-help">{{ $item['unavailable_reason'] }}</span>@endif
                            </td>
                            <td>
                                @if ($context === 'user-targets')
                                    <span class="badge badge-{{ $item['access_rule'] === 'deny' ? 'danger' : 'neutral' }}">{{ \Illuminate\Support\Str::headline($item['access_rule'] ?? 'inherit') }}</span>
                                    <p class="field-help">{{ $item['scope_path'] }}</p>
                                    <span class="field-help">{{ __(':count capability restrictions', ['count' => $item['restriction_count']]) }}</span>
                                @else
                                    <span class="badge badge-{{ $item['member'] ? 'success' : 'neutral' }}">{{ $item['member'] ? __('Assigned') : __('Not assigned') }}</span>
                                @endif
                            </td>
                            <td class="table-action">
                                @if ($context === 'user-targets' && $item['target_id'] !== null && !($data['subject']['unrestricted'] ?? false))
                                    <a href="{{ route('admin.users.targets.edit', ['user' => $subjectId, 'target' => $item['target_id']]) }}">{{ __('Individual restrictions') }}</a>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
            </div>
        @endif

        @if (($data['unavailable_ids'] ?? []) !== [])
            <fieldset class="permission-fieldset access-unavailable">
                <legend>{{ __('Unavailable saved selections') }}</legend>
                <p class="field-help">{{ __('These exact saved identifiers are no longer available. Uncheck them to remove them from this draft; they cannot be applied.') }}</p>
                @foreach ($data['unavailable_ids'] as $unavailableId)
                    <input type="hidden" name="unavailable_ids[]" value="{{ $unavailableId }}">
                    <label class="checkbox-option">
                        <input type="checkbox" name="selected_ids[]" value="{{ $unavailableId }}" checked aria-label="{{ __('Keep unavailable selection :id', ['id' => $unavailableId]) }}">
                        <code dir="ltr">{{ $unavailableId }}</code>
                    </label>
                @endforeach
            </fieldset>
        @endif

        @unless ($data['subject']['unrestricted'] ?? false)
        <div class="action-row">
            <button class="button button-primary" type="submit" name="action" value="review">{{ __('Review selected changes') }}</button>
            <button class="button button-secondary" type="submit" name="action" value="save">{{ __('Save selection') }}</button>
        </div>
        @endunless
        @if ($data['page'] > 1 || $data['has_more'])
            <nav class="pagination" aria-label="{{ __('Membership pages') }}">
                @if ($data['page'] > 1)
                    <button class="button button-secondary" type="submit" name="action" value="previous">{{ __('Previous') }}</button>
                @else
                    <span></span>
                @endif
                <span>{{ __('Page :page', ['page' => $data['page']]) }}</span>
                @if ($data['has_more'])
                    <button class="button button-secondary" type="submit" name="action" value="next">{{ __('Next') }}</button>
                @endif
            </nav>
        @endif
    </form>
</section>
@endsection
