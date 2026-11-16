@if($arvanConfig !== null)
    <dt>{{ __('ArvanCloud API root') }}</dt><dd><code class="small-code">{{ $arvanConfig->base_url }}</code></dd>
    <dt>{{ __('OpenAPI description') }}</dt><dd>{{ $arvanConfig->spec_url ?? __('Not configured') }}</dd>
    <dt>{{ __('Authenticated GET probe') }}</dt><dd><code>{{ $arvanConfig->probe_path ?? __('Not configured') }}</code></dd>
    <dt>{{ __('Machine User credential') }}</dt><dd>{{ $arvanHasCredential ? __('Encrypted key stored (never displayed)') : __('No credential; add one before testing') }}</dd>
    <dt>{{ __('Remote revocation') }}</dt><dd>{{ __('Disconnect only erases the Gateway copy; revoke the Machine User API key in ArvanCloud when necessary.') }}</dd>
@endif
