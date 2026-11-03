@extends('admin.layout')

@section('title', __('Add managed Reverse SSH Target'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Add Target via managed Reverse SSH') }}</h1>
        <p class="muted">{{ __('Create a Pending Setup enrollment, copy one installer command and run it on the Target. Real SSH identity and login are verified later.') }}</p>
    </div>
    <a href="{{ route('admin.targets.create', ['connector_type' => 'ssh_direct']) }}">{{ __('Back to Add Target') }}</a>
</div>
<section class="panel panel-wide" aria-labelledby="managed-reverse-create">
    <h2 id="managed-reverse-create">{{ __('Pending Target enrollment') }}</h2>
    @if (! $configured)
        <div class="alert alert-error" role="alert">
            {{ __('Managed Reverse SSH is disabled or not configured.') }}
            <a href="{{ route('admin.reverse-ssh.index') }}">{{ __('Open Reverse SSH settings') }}</a>
        </div>
    @endif
    @if ($errors->any())
        <div class="alert alert-error" role="alert" tabindex="-1">
            <p>{{ __('Enrollment could not be created. Review the fields and try again. No installer command was issued.') }}</p>
            <ul>@foreach ($errors->all() as $message)<li>{{ $message }}</li>@endforeach</ul>
        </div>
    @endif
    <form method="post" action="{{ route('admin.reverse-ssh.targets.store') }}" class="form-stack">
        @csrf
        <div class="target-field-grid">
            <div class="field">
                <label for="managed_target_id">{{ __('Stable Target ID') }}</label>
                <input id="managed_target_id" name="target_id" required maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" value="{{ old('target_id') }}" autocomplete="off" @error('target_id') aria-invalid="true" @enderror>
                @error('target_id')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="managed_display_name">{{ __('Display name') }}</label>
                <input id="managed_display_name" name="display_name" required maxlength="160" value="{{ old('display_name') }}" @error('display_name') aria-invalid="true" @enderror>
                @error('display_name')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="managed_ssh_host">{{ __('Real Target SSH hostname or IP') }}</label>
                <input id="managed_ssh_host" name="ssh_host" required maxlength="253" value="{{ old('ssh_host') }}" autocomplete="off" @error('ssh_host') aria-invalid="true" @enderror>
                @error('ssh_host')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="managed_ssh_port">{{ __('Real Target SSH port') }}</label>
                <input id="managed_ssh_port" name="ssh_port" type="number" required min="1" max="65535" value="{{ old('ssh_port', 22) }}">
                @error('ssh_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="managed_ssh_user">{{ __('Existing Target SSH login username') }}</label>
                <input id="managed_ssh_user" name="ssh_username" required maxlength="128" autocomplete="off" value="{{ old('ssh_username') }}">
                @error('ssh_username')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                <p class="field-help">{{ __('The installer adds only one scoped public LOGIN key to this existing OS user. It does not grant sudo or create a root login.') }}</p>
            </div>
            <div class="field">
                <label for="managed_ssh_key">{{ __('Independently verified Target SSHD public host key') }}</label>
                <textarea id="managed_ssh_key" name="ssh_host_key" required maxlength="4096" rows="3" spellcheck="false" autocomplete="off">{{ old('ssh_host_key') }}</textarea>
                @error('ssh_host_key')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field target-span-all">
                <label for="managed_guidance">{{ __('AI guidance (optional)') }}</label>
                <textarea id="managed_guidance" name="ai_guidance" maxlength="800" rows="2">{{ old('ai_guidance') }}</textarea>
                @error('ai_guidance')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>
        <label class="target-trust-confirmation">
            <input type="checkbox" name="ssh_trust_confirmed" value="yes" required @checked(old('ssh_trust_confirmed') === 'yes')>
            <span>{{ __('I verified this exact Target SSH host public key over a separate trusted channel, not by unverified ssh-keyscan output.') }}</span>
        </label>
        @error('ssh_trust_confirmed')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        <div class="field">
            <label for="managed_owner_password">{{ __('Current Owner password') }}</label>
            <input id="managed_owner_password" type="password" name="current_password" required maxlength="255" autocomplete="current-password">
            @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="target-create-actions">
            <button class="button button-primary" type="submit" @disabled(! $configured)>{{ __('Create Pending Setup and installer command') }}</button>
        </div>
    </form>
</section>
@endsection
