@extends('admin.layout')

@section('title', __('Edit site access'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site-specific restriction') }}</div>
        <h1>{{ $site->display_name }}</h1>
        <p class="muted">{{ $managedUser->name }} · <code>{{ $site->site_id }}</code></p>
    </div>
    <a href="{{ route('admin.users.sites.index', ['user' => $managedUser->id]) }}">{{ __('Back to site access') }}</a>
</div>

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners always retain unrestricted site access for recovery. Change the role first if this account should accept restrictions.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.users.sites.update', ['user' => $managedUser->id, 'site' => $site->site_id]) }}">
            @csrf
            @method('PUT')

            <div class="field">
                <label for="access_rule">{{ __('Explicit scope rule') }}</label>
                <select id="access_rule" name="access_rule" required>
                    @foreach (['inherit', 'allow', 'deny'] as $rule)
                        <option value="{{ $rule }}" @selected(old('access_rule', $siteRule['access_rule']) === $rule)>{{ \Illuminate\Support\Str::headline($rule) }}</option>
                    @endforeach
                </select>
                <p class="field-help">{{ __('inherit follows the user scope mode; allow/deny records a direct site rule. Direct denials remain the final narrowing layer for future group support.') }}</p>
                @error('access_rule')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Capability restrictions on this site') }}</legend>
                <p class="field-help">{{ __('Checked capabilities are denied only on this site. They can never grant authority missing from the user role.') }}</p>
                @php($selectedDenials = old('denied_permissions', $siteRule['denied_permissions']))
                <div class="checkbox-grid">
                    @foreach ($sitePermissions as $permission)
                        @include('admin.partials.permission-option', [
                            'permission' => $permission,
                            'checked' => in_array($permission->value, $selectedDenials, true),
                        ])
                    @endforeach
                </div>
            </fieldset>

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
                <p class="field-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
                @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <button class="button button-primary" type="submit">{{ __('Save site rule') }}</button>
        </form>
    @endif
</section>
@endsection
