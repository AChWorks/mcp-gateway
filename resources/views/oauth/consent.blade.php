<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize {{ $clientName }}</title>
</head>
<body>
<main>
    <h1>Authorize {{ $clientName }}</h1>
    <p>This client is requesting access to the MCP Gateway resource.</p>
    <dl>
        <dt>Client</dt>
        <dd><code>{{ $clientId }}</code></dd>
        <dt>Redirect</dt>
        <dd><code>{{ $redirectUri }}</code></dd>
        <dt>Scope</dt>
        <dd><code>{{ $scope }}</code></dd>
        <dt>Resource</dt>
        <dd><code>{{ config('oauth.resource') }}</code></dd>
    </dl>

    <form method="post" action="{{ url('/oauth/authorize') }}">
        @csrf
        @foreach ($parameters as $name => $value)
            <input type="hidden" name="{{ $name }}" value="{{ $value }}">
        @endforeach
        <button type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
    </form>
</main>
</body>
</html>
