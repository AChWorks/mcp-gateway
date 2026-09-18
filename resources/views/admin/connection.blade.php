@extends('admin.layout')

@section('title', __('Connection information'))

@section('content')
<section class="panel" aria-labelledby="connection-title">
    <div class="eyebrow">{{ __('Gateway') }}</div>
    <h1 id="connection-title">{{ __('Connection information') }}</h1>
    <p class="muted">{{ __('Use the MCP endpoint as the remote server URL. OAuth discovery is published automatically through the metadata endpoints below.') }}</p>

    <dl class="summary-list">
        <div>
            <dt>{{ __('Gateway MCP endpoint') }}</dt>
            <dd><code>{{ config('oauth.resource') }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Protected resource metadata') }}</dt>
            <dd><code>{{ rtrim((string) config('oauth.issuer'), '/').'/.well-known/oauth-protected-resource/mcp' }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Authorization server metadata') }}</dt>
            <dd><code>{{ rtrim((string) config('oauth.issuer'), '/').'/.well-known/oauth-authorization-server' }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Gateway OAuth client metadata') }}</dt>
            <dd><code>{{ config('bridge.client.id') }}</code></dd>
            <dd class="muted">{{ __('Approve or configure this client metadata URL in WP AI Bridge when connecting the Gateway.') }}</dd>
        </div>
        <div>
            <dt>{{ __('Required MCP scope') }}</dt>
            <dd><code>{{ config('oauth.scope') }}</code></dd>
        </div>
    </dl>

    <p><a href="{{ route('admin.dashboard') }}">{{ __('Back to administration') }}</a></p>
</section>
@endsection
