<?php

/**
 * Executable compatibility contract for the exact pinned WP AI Bridge OAuth client-auth path.
 *
 * This file is owned by MCP Gateway and is copied into an isolated WordPress instance that
 * runs the exact pinned Bridge commit. It deliberately calls the real Bridge classes instead
 * of reproducing their error mapping in a Gateway fixture.
 */

use WP_AI_Bridge\Auth\Approved_OAuth_Clients;
use WP_AI_Bridge\Auth\Client_Assertion_Validator;
use WP_AI_Bridge\Auth\OAuth_Server;
use WP_AI_Bridge\Auth\OAuth_Store;

function gateway_bridge_contract_assert($condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

function gateway_bridge_contract_data($response): array
{
    $data = json_decode(wp_json_encode($response->get_data()), true);

    return is_array($data) ? $data : [];
}

function gateway_bridge_contract_b64(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function gateway_bridge_contract_key(string $kid): array
{
    $private = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    gateway_bridge_contract_assert($private !== false, 'Could not generate the contract RSA key.');

    $details = openssl_pkey_get_details($private);
    gateway_bridge_contract_assert(
        is_array($details) && ! empty($details['rsa']['n']) && ! empty($details['rsa']['e']),
        'Contract RSA public-key details are unavailable.'
    );

    return [
        'private' => $private,
        'jwk' => [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => gateway_bridge_contract_b64($details['rsa']['n']),
            'e' => gateway_bridge_contract_b64($details['rsa']['e']),
        ],
    ];
}

function gateway_bridge_contract_assertion(string $clientId, string $audience, array $key): string
{
    $header = [
        'alg' => 'RS256',
        'kid' => $key['jwk']['kid'],
        'typ' => 'JWT',
    ];
    $claims = [
        'iss' => $clientId,
        'sub' => $clientId,
        'aud' => $audience,
        'iat' => time(),
        'exp' => time() + 120,
        'jti' => bin2hex(random_bytes(16)),
    ];
    $input = gateway_bridge_contract_b64(wp_json_encode($header)).'.'.gateway_bridge_contract_b64(wp_json_encode($claims));
    $signature = '';
    gateway_bridge_contract_assert(
        openssl_sign($input, $signature, $key['private'], OPENSSL_ALGO_SHA256),
        'Could not sign the contract client assertion.'
    );

    return $input.'.'.gateway_bridge_contract_b64($signature);
}

function gateway_bridge_contract_auth(WP_REST_Request $request, string $assertion): void
{
    $request->set_param('client_assertion_type', Client_Assertion_Validator::ASSERTION_TYPE);
    $request->set_param('client_assertion', $assertion);
}

function gateway_bridge_contract_http_response(int $status, array $body = []): array
{
    return [
        'headers' => ['content-type' => 'application/json'],
        'body' => wp_json_encode($body),
        'response' => ['code' => $status, 'message' => $status === 200 ? 'OK' : 'Service Unavailable'],
        'cookies' => [],
        'filename' => null,
    ];
}

gateway_bridge_contract_assert(get_current_user_id() > 0, 'Run the contract smoke as an authenticated WordPress user.');
gateway_bridge_contract_assert(function_exists('openssl_pkey_new'), 'OpenSSL is required for the contract smoke.');

$registry = new Approved_OAuth_Clients;
$store = new OAuth_Store;
$oauth = new OAuth_Server($store, $registry);
$userId = get_current_user_id();
$resource = $oauth->mcp_endpoint_url();

$scenarios = [
    'refresh_metadata_503' => ['operation' => 'refresh', 'fault' => 'metadata_503'],
    'refresh_jwks_503' => ['operation' => 'refresh', 'fault' => 'jwks_503'],
    'revoke_metadata_503' => ['operation' => 'revoke', 'fault' => 'metadata_503'],
    'revoke_jwks_503' => ['operation' => 'revoke', 'fault' => 'jwks_503'],
];

$clients = [];
foreach (array_keys($scenarios) as $name) {
    $clients[$name] = [
        'client_id' => 'https://www.example.com/wp-ai-bridge/gateway-contract-'.$name.'.json',
        'redirect_uri' => 'https://www.example.com/wp-ai-bridge/gateway-contract-'.$name.'-callback',
        'jwks_uri' => 'https://www.example.com/wp-ai-bridge/gateway-contract-'.$name.'-jwks.json',
        'key' => gateway_bridge_contract_key('gateway-contract-'.$name),
        'mode' => $scenarios[$name]['fault'],
    ];
}

$originalClients = get_option(Approved_OAuth_Clients::OPTION_NAME, null);
$originalRevision = get_option(Approved_OAuth_Clients::REVISION_OPTION, null);
$approved = $registry->sanitize(array_column($clients, 'client_id'));
update_option(Approved_OAuth_Clients::OPTION_NAME, $approved, false);
$revision = $registry->revision();

gateway_bridge_contract_assert(count($approved) === count($clients), 'Pinned Bridge rejected a controlled approved-client identity.');

$httpMock = static function ($preempt, $args, $url) use (&$clients) {
    foreach ($clients as $client) {
        if ($url === $client['client_id']) {
            if ($client['mode'] === 'metadata_503') {
                return gateway_bridge_contract_http_response(503, ['error' => 'fixture_metadata_unavailable']);
            }

            return gateway_bridge_contract_http_response(200, [
                'client_id' => $client['client_id'],
                'client_name' => 'MCP Gateway contract fixture',
                'redirect_uris' => [$client['redirect_uri']],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks_uri' => $client['jwks_uri'],
            ]);
        }

        if ($url === $client['jwks_uri']) {
            if ($client['mode'] === 'jwks_503') {
                return gateway_bridge_contract_http_response(503, ['error' => 'fixture_jwks_unavailable']);
            }

            return gateway_bridge_contract_http_response(200, ['keys' => [$client['key']['jwk']]]);
        }
    }

    return $preempt;
};
add_filter('pre_http_request', $httpMock, 10, 3);

try {
    foreach ($scenarios as $name => $scenario) {
        $client = &$clients[$name];
        $claims = [
            'user_id' => $userId,
            'client_id' => $client['client_id'],
            'client_revision' => $revision,
            'resource' => $resource,
            'scope' => OAuth_Server::SCOPE_MCP.' '.OAuth_Server::SCOPE_OFFLINE,
        ];

        if ($scenario['operation'] === 'refresh') {
            $refresh = $store->issue(OAuth_Store::TYPE_REFRESH, $claims, OAuth_Server::REFRESH_TTL);
            $request = new WP_REST_Request('POST', '/wp-ai-bridge/v1/oauth/token');
            $request->set_param('grant_type', 'refresh_token');
            $request->set_param('refresh_token', $refresh);
            $request->set_param('client_id', $client['client_id']);
            $request->set_param('resource', $resource);
            gateway_bridge_contract_auth(
                $request,
                gateway_bridge_contract_assertion($client['client_id'], $oauth->token_endpoint_url(), $client['key'])
            );

            $failed = $oauth->handle_token_request($request);
            $failedData = gateway_bridge_contract_data($failed);
            gateway_bridge_contract_assert($failed->get_status() === 400, $name.': dependency failure did not fail OAuth client authentication.');
            gateway_bridge_contract_assert(($failedData['error'] ?? '') === 'invalid_client', $name.': dependency HTTP 503 did not map to invalid_client.');
            gateway_bridge_contract_assert(is_array($store->read(OAuth_Store::TYPE_REFRESH, $refresh)), $name.': failed client authentication consumed the refresh token.');

            $client['mode'] = 'normal';
            $retry = new WP_REST_Request('POST', '/wp-ai-bridge/v1/oauth/token');
            $retry->set_param('grant_type', 'refresh_token');
            $retry->set_param('refresh_token', $refresh);
            $retry->set_param('client_id', $client['client_id']);
            $retry->set_param('resource', $resource);
            gateway_bridge_contract_auth(
                $retry,
                gateway_bridge_contract_assertion($client['client_id'], $oauth->token_endpoint_url(), $client['key'])
            );
            $recovered = $oauth->handle_token_request($retry);
            gateway_bridge_contract_assert($recovered->get_status() === 200, $name.': the same refresh token did not recover after dependency restoration.');
            gateway_bridge_contract_assert($store->read(OAuth_Store::TYPE_REFRESH, $refresh) === false, $name.': successful retry did not rotate the original refresh token.');
        } else {
            $access = $store->issue(OAuth_Store::TYPE_ACCESS, $claims, OAuth_Server::ACCESS_TTL);
            $request = new WP_REST_Request('POST', '/wp-ai-bridge/v1/oauth/revoke');
            $request->set_param('token', $access);
            gateway_bridge_contract_auth(
                $request,
                gateway_bridge_contract_assertion($client['client_id'], $oauth->revocation_endpoint_url(), $client['key'])
            );

            $failed = $oauth->handle_revoke_request($request);
            $failedData = gateway_bridge_contract_data($failed);
            gateway_bridge_contract_assert($failed->get_status() === 400, $name.': dependency failure did not fail revocation client authentication.');
            gateway_bridge_contract_assert(($failedData['error'] ?? '') === 'invalid_client', $name.': dependency HTTP 503 did not map to invalid_client.');
            gateway_bridge_contract_assert(is_array($store->read(OAuth_Store::TYPE_ACCESS, $access)), $name.': failed client authentication revoked the access token.');

            $client['mode'] = 'normal';
            $retry = new WP_REST_Request('POST', '/wp-ai-bridge/v1/oauth/revoke');
            $retry->set_param('token', $access);
            gateway_bridge_contract_auth(
                $retry,
                gateway_bridge_contract_assertion($client['client_id'], $oauth->revocation_endpoint_url(), $client['key'])
            );
            $recovered = $oauth->handle_revoke_request($retry);
            gateway_bridge_contract_assert($recovered->get_status() === 200, $name.': revocation did not recover after dependency restoration.');
            gateway_bridge_contract_assert($store->read(OAuth_Store::TYPE_ACCESS, $access) === false, $name.': successful retry did not revoke the access token.');
        }
        unset($client);
    }
} finally {
    remove_filter('pre_http_request', $httpMock, 10);
    if ($originalClients === null) {
        delete_option(Approved_OAuth_Clients::OPTION_NAME);
    } else {
        update_option(Approved_OAuth_Clients::OPTION_NAME, $originalClients, false);
    }
    if ($originalRevision === null) {
        delete_option(Approved_OAuth_Clients::REVISION_OPTION);
    } else {
        update_option(Approved_OAuth_Clients::REVISION_OPTION, $originalRevision, false);
    }
}

echo "PASS: exact pinned WP AI Bridge dependency failures occur before refresh consumption/revocation.\n";
