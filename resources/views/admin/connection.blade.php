@extends('admin.layout')

@section('title', __('Connection information'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Gateway') }}</div>
        <h1 id="connection-title">{{ __('Connection information') }}</h1>
        <p class="muted reading-width">{{ __('Use the MCP endpoint as the remote server URL. OAuth discovery is published automatically through the metadata endpoints below.') }}</p>
    </div>
    <a href="{{ route('admin.dashboard') }}">{{ __('Back to administration') }}</a>
</div>

<section class="panel panel-wide" aria-labelledby="connection-details-title">
    <h2 id="connection-details-title">{{ __('Client setup endpoints') }}</h2>
    <dl class="summary-list">
        <div>
            <dt>{{ __('Gateway MCP endpoint') }}</dt>
            <dd><code dir="ltr">{{ config('oauth.resource') }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Protected resource metadata') }}</dt>
            <dd><code dir="ltr">{{ rtrim((string) config('oauth.issuer'), '/').'/.well-known/oauth-protected-resource/mcp' }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Authorization server metadata') }}</dt>
            <dd><code dir="ltr">{{ rtrim((string) config('oauth.issuer'), '/').'/.well-known/oauth-authorization-server' }}</code></dd>
        </div>
        <div>
            <dt>{{ __('Gateway OAuth client metadata') }}</dt>
            <dd><code dir="ltr">{{ config('bridge.client.id') }}</code></dd>
            <dd class="muted">{{ __('Approve or configure this client metadata URL in WP AI Bridge when connecting the Gateway.') }}</dd>
        </div>
        <div>
            <dt>{{ __('Required MCP scope') }}</dt>
            <dd dir="ltr"><code>{{ config('oauth.scope') }}</code></dd>
        </div>
    </dl>

</section>
@endsection
