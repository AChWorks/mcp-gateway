@extends('admin.layout')

@section('title', __('Review access changes').' · '.$preview['subject']['name'])
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Review before applying') }}</div>
        <h1>{{ $preview['subject']['name'] }}</h1>
        <p class="muted reading-width">{{ __('Review the exact selected items and consequences. These changes are applied together or nothing is changed.') }}</p>
    </div>
    <a href="{{ $collectionUrl }}">{{ __('Back to selection') }}</a>
</div>

@include('admin.access-batches.context-nav', ['subject' => $preview['subject']])

<section class="panel panel-wide" aria-labelledby="access-review-title">
    <h2 id="access-review-title">{{ __(':changed changes · :unchanged already in the requested state', ['changed' => $preview['changed_count'], 'unchanged' => $preview['unchanged_count']]) }}</h2>
    <p class="field-help">{{ __('Review valid until :time. A change to relevant saved access settings requires a new review.', ['time' => $preview['expires_at']]) }}</p>

    @foreach ($preview['warnings'] as $warning)
        <p class="alert alert-info">{{ $warning }}</p>
    @endforeach

    <div class="table-wrap">
        <table>
            <thead>
            <tr>
                <th scope="col">{{ __('Selected item') }}</th>
                <th scope="col">{{ __('Current') }}</th>
                <th scope="col">{{ __('Requested') }}</th>
            </tr>
            </thead>
            <tbody>
            @foreach ($preview['items'] as $item)
                <tr>
                    <td class="access-item-identity">
                        <strong>{{ $item['label'] }}</strong>
                        <span class="muted">{{ $item['detail'] }}</span>
                        @if ($item['blocked'] !== null)
                            <p class="field-error">{{ $item['blocked'] }}</p>
                            @if ($context === 'user-targets')
                                @php($individualRulesUrl = isset($item['target_id'])
                                    ? route('admin.users.targets.edit', ['user' => $subjectId, 'target' => $item['target_id']])
                                    : route('admin.users.targets.index', ['user' => $subjectId, 'membership' => 'all', 'search' => $item['label']]))
                                <a href="{{ $individualRulesUrl }}">{{ __('Open individual Target rules') }}</a>
                            @endif
                        @endif
                    </td>
                    <td>{{ \Illuminate\Support\Str::headline($item['before']) }}</td>
                    <td>{{ \Illuminate\Support\Str::headline($item['after']) }}</td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>

    @unless ($preview['can_apply'])
        <p class="alert alert-error" role="alert">{{ __('This review contains a blocked change. Return to the selection and resolve it before applying. Nothing has been changed.') }}</p>
    @endunless

    <p class="field-help">{{ __('If a request does not confirm completion, return to the member list and check the saved state before creating a new review.') }}</p>

    <form class="form-stack" method="post" action="{{ route('admin.access-batches.apply', ['context' => $context, 'subject' => $subjectId]) }}">
        @csrf
        <input type="hidden" name="review_id" value="{{ $reviewId }}">
        @if ($preview['requires_ssh_confirmation'])
            <label class="checkbox-option" for="confirm_ssh_changes">
                <input id="confirm_ssh_changes" name="confirm_ssh_changes" value="1" type="checkbox" @error('confirm_ssh_changes') aria-invalid="true" aria-describedby="confirm_ssh_changes-error" @enderror>
                <span>
                    @if ($context === 'user-targets')
                        {{ __('I reviewed the SSH impact of these direct Target scope changes. Allow or Deny changes the direct reachability rule; Inherit may restore another already-approved access path. Existing capability restrictions still apply.') }}
                    @else
                        {{ __('I reviewed the SSH impact of these exact changes. Adding or removing memberships can change SSH reachability or lift a group restriction through another access path.') }}
                    @endif
                </span>
            </label>
            @error('confirm_ssh_changes')<p id="confirm_ssh_changes-error" class="field-error" role="alert">{{ $message }}</p>@enderror
        @endif
        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="current_password-error" @enderror>
            @error('current_password')<p id="current_password-error" class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="action-row">
            <button class="button button-primary" type="submit" @disabled(!$preview['can_apply'])>{{ __('Apply reviewed changes') }}</button>
            <a class="button button-secondary" href="{{ $collectionUrl }}">{{ __('Edit selection') }}</a>
        </div>
    </form>
</section>
@endsection
