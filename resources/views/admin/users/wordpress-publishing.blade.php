@extends('admin.layout')

@section('title', __('WordPress publisher grants'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('WordPress publisher grants') }}</h1>
        <p class="muted reading-width">{{ $managedUser->name }} · {{ $managedUser->email }}</p>
    </div>
    <a href="{{ route('admin.users.edit', ['user' => $managedUser->id]) }}">{{ __('Back to user') }}</a>
</div>

<section class="panel panel-wide">
    <h2>{{ __('Explicit scoped publication authority') }}</h2>
    <p class="field-help">{{ __('An explicitly authorized Administrator or Operator can create published WordPress posts on an assigned Target Group, through the restricted AI/MCP operation when AI access is separately enabled. The shared service is prepared for a future authenticated Admin publishing action, but this page only manages grants; it does not publish content. This grant never permits updates or generic WordPress Ability execution, and existing role, direct and group denials still apply. Adding a Target to the group expands the permitted scope.') }}</p>
    @unless ($canPublish)
        <p class="alert alert-error" role="alert">{{ __('This user is not an Administrator or Operator. Ordinary publishing grants are only available to these roles. The Owner retains recovery permissions.') }}</p>
    @endunless

    @if ($grants->isEmpty())
        <p class="empty-state">{{ __('No explicit publisher grants. This user cannot use restricted publication.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th scope="col">{{ __('Target Group') }}</th>
                    <th scope="col">{{ __('Action') }}</th>
                </tr></thead>
                <tbody>
                    @foreach ($grants as $grant)
                        <tr>
                            <td>{{ $grant->group_name }}</td>
                            <td>
                                <form method="post" action="{{ route('admin.users.publishing.destroy', ['user' => $managedUser->id, 'grant' => $grant->id]) }}">
                                    @csrf
                                    @method('DELETE')
                                    <div class="field">
                                        <label for="revoke-password-{{ $grant->id }}">{{ __('Current Owner password') }}</label>
                                        <input id="revoke-password-{{ $grant->id }}" name="current_password" type="password" required maxlength="255" autocomplete="current-password"
                                            @error('current_password') aria-invalid="true" aria-describedby="revoke-password-{{ $grant->id }}-error" @enderror>
                                        @error('current_password')<p class="field-error" id="revoke-password-{{ $grant->id }}-error" role="alert">{{ $message }}</p>@enderror
                                    </div>
                                    <button class="button button-danger" type="submit">{{ __('Revoke grant') }}</button>
                                </form>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endif
</section>

<section class="panel panel-wide">
    <h2>{{ __('Authorize publication in one Target Group') }}</h2>
    @if (!$canPublish || $groups->isEmpty())
        <p class="empty-state">{{ __('An enabled Administrator or Operator assigned to a WordPress Target Group is required. Configure the User and Target Group first.') }}</p>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.users.publishing.store', ['user' => $managedUser->id]) }}">
            @csrf
            <div class="form-grid">
                <div class="field">
                    <label for="group_id">{{ __('Authorized Target Group') }}</label>
                    <select id="group_id" name="group_id" required @error('group_id') aria-invalid="true" aria-describedby="group_id-error" @enderror>
                        @foreach ($groups as $group)
                            <option value="{{ $group->getKey() }}" @selected(old('group_id') === $group->getKey())>{{ $group->name }}</option>
                        @endforeach
                    </select>
                    @error('group_id')<p class="field-error" id="group_id-error" role="alert">{{ $message }}</p>@enderror
                </div>
            </div>
            <div class="field">
                <label for="current_password">{{ __('Current Owner password') }}</label>
                <input id="current_password" type="password" name="current_password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="current_password-error" @enderror>
                @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <button class="button button-primary" type="submit">{{ __('Grant scoped publication') }}</button>
        </form>
    @endif
</section>
@endsection
