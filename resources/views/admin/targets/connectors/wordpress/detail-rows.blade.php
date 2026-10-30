@if ($wpConfig !== null)
    <dt>{{ __('WordPress origin') }}</dt><dd><code class="small-code">{{ $wpConfig->base_url }}</code></dd>
    <dt>{{ __('MCP resource') }}</dt><dd><code class="small-code">{{ $wpConfig->mcp_resource_url }}</code></dd>
    <dt>{{ __('OAuth issuer') }}</dt><dd><code class="small-code">{{ $wpConfig->oauth_issuer_url }}</code></dd>
@endif
