@extends('admin.layout')

@php($site = $siteView['site'])

@section('title', $site->display_name)

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site') }}</div>
        <h1>{{ $site->display_name }}</h1>
        <p class="muted"><code>{{ $site->site_id }}</code></p>
    </div>
    <a href="{{ route('admin.sites.index') }}">{{ __('Back to sites') }}</a>
</div>

<div class="content-grid">
    <section class="panel panel-wide" aria-labelledby="site-status-title">
        <div class="section-heading">
            <div>
                <div class="eyebrow">{{ __('Connection') }}</div>
                <h2 id="site-status-title">{{ __('Site status') }}</h2>
            </div>
            <span class="badge badge-{{ $siteView['status_tone'] }}">{{ $siteView['status_label'] }}</span>
        </div>

        <dl class="summary-list">
            <div><dt>{{ __('WordPress URL') }}</dt><dd><a href="{{ $site->base_url }}" rel="noreferrer">{{ $site->base_url }}</a></dd></div>
            <div><dt>{{ __('MCP resource') }}</dt><dd><code>{{ $site->mcp_resource_url }}</code></dd></div>
            <div><dt>{{ __('Last tested') }}</dt><dd>{{ $site->last_tested_at?->format('Y-m-d H:i:s') ?? __('Never') }}</dd></div>
            <div><dt>{{ __('Last error code') }}</dt><dd><code>{{ $site->last_error_code ?? '—' }}</code></dd></div>
        </dl>

        @if ($siteView['has_revocation_intent'])
            <div class="alert alert-error" role="alert">{{ __('Credential revocation is pending. Retry the relevant disconnect or removal operation before changing the target.') }}</div>
        @elseif ($siteView['has_target_reservation'])
            <div class="alert alert-error" role="alert">{{ __('Target reassignment is pending. Complete that operation before starting another connection change.') }}</div>
        @endif

        <p class="muted">{{ __('Reconnect first revokes the current credential before starting a new authorization. Disconnect revokes the remote credential before removing it locally.') }}</p>

        <div class="action-row" aria-label="{{ __('Connection actions') }}">
            @if ($siteView['has_credential'])
                <form method="post" action="{{ route('admin.sites.reconnect', ['site' => $site->site_id]) }}">
                    @csrf
                    <button class="button button-primary" type="submit">{{ __('Reconnect') }}</button>
                </form>
                <form method="post" action="{{ route('admin.sites.disconnect', ['site' => $site->site_id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Disconnect') }}</button>
                </form>
            @else
                <form method="post" action="{{ route('admin.sites.connect', ['site' => $site->site_id]) }}">
                    @csrf
                    <button class="button button-primary" type="submit">{{ __('Connect') }}</button>
                </form>
            @endif

            <form method="post" action="{{ route('admin.sites.test', ['site' => $site->site_id]) }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Test connection') }}</button>
            </form>
        </div>
    </section>

    <section class="panel" aria-labelledby="edit-site-title">
        <div class="eyebrow">{{ __('Configuration') }}</div>
        <h2 id="edit-site-title">{{ __('Edit site') }}</h2>
        <p class="muted">{{ __('Changing the WordPress target uses the existing safe reassignment lifecycle and can disconnect the current credential.') }}</p>

        <form class="form-stack" method="post" action="{{ route('admin.sites.update', ['site' => $site->site_id]) }}">
            @csrf
            @method('PUT')

            <div class="field">
                <label for="display_name">{{ __('Display name') }}</label>
                <input id="display_name" name="display_name" type="text" maxlength="160" required autocomplete="off" value="{{ old('display_name', $site->display_name) }}" @error('display_name') aria-invalid="true" aria-describedby="display-name-error" @enderror>
                @error('display_name')<p class="field-error" id="display-name-error">{{ $message }}</p>@enderror
            </div>

            <div class="field">
                <label for="base_url">{{ __('WordPress HTTPS URL') }}</label>
                <input id="base_url" name="base_url" type="url" maxlength="2048" required inputmode="url" value="{{ old('base_url', $site->base_url) }}" @error('base_url') aria-invalid="true" aria-describedby="base-url-error" @enderror>
                @error('base_url')<p class="field-error" id="base-url-error">{{ $message }}</p>@enderror
            </div>

            <button class="button button-primary" type="submit">{{ __('Save changes') }}</button>
        </form>
    </section>
</div>

<section class="panel panel-danger" aria-labelledby="remove-site-title">
    <div class="eyebrow">{{ __('Danger zone') }}</div>
    <h2 id="remove-site-title">{{ __('Remove site') }}</h2>
    <p>{{ __('Removal first finalizes remote credential revocation when a credential exists. If revocation cannot be confirmed, the site is preserved for safe recovery.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.sites.destroy', ['site' => $site->site_id]) }}">
        @csrf
        @method('DELETE')
        <div class="field">
            <label for="confirm_site_id">{{ __('Type :site_id to confirm removal', ['site_id' => $site->site_id]) }}</label>
            <input id="confirm_site_id" name="confirm_site_id" type="text" maxlength="64" required autocomplete="off" @error('confirm_site_id') aria-invalid="true" aria-describedby="confirm-site-error" @enderror>
            @error('confirm_site_id')<p class="field-error" id="confirm-site-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-danger" type="submit">{{ __('Remove site') }}</button>
    </form>
</section>
@endsection
