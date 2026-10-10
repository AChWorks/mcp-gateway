@extends('admin.layout')

@section('title', __('Edit target access'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target-specific restriction') }}</div>
        <h1>{{ $target->display_name }}</h1>
        <p class="muted">{{ $managedUser->name }} · <code>{{ $target->target_id }}</code></p>
    </div>
    <a href="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">{{ __('Back to target access') }}</a>
</div>

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners always retain unrestricted target access for recovery. Change the role first if this account should accept restrictions.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.users.targets.update', ['user' => $managedUser->id, 'target' => $target->target_id]) }}">
            @csrf
            @method('PUT')

            <div class="field">
                <label for="access_rule">{{ __('Explicit scope rule') }}</label>
                <select id="access_rule" name="access_rule" required>
                    @foreach (['inherit', 'allow', 'deny'] as $rule)
                        <option value="{{ $rule }}" @selected(old('access_rule', $targetRule['access_rule']) === $rule)>{{ \Illuminate\Support\Str::headline($rule) }}</option>
                    @endforeach
                </select>
                <p class="field-help">{{ __('inherit follows the user scope mode; allow/deny records a direct target rule. Direct denials remain the final narrowing layer for future group support.') }}</p>
                @error('access_rule')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Capability restrictions on this target') }}</legend>
                <p class="field-help">{{ __('Checked capabilities are denied only on this target. They can never grant authority missing from the user role.') }}</p>
                @php($selectedDenials = old('denied_permissions', $targetRule['denied_permissions']))
                <div class="checkbox-grid">
                    @foreach ($targetPermissions as $permission)
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

            <button class="button button-primary" type="submit">{{ __('Save target rule') }}</button>
        </form>
    @endif
</section>
@endsection
