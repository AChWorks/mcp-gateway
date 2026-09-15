<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\UnsafeOutboundTarget;

final class WpAiBridgeDiscovery
{
    public function __construct(
        private readonly OutboundTargetPolicy $targets,
        private readonly SafeHttpClient $http,
    ) {}

    public function discover(string $baseUrl): BridgeDiscovery
    {
        try {
            $baseUrl = $this->targets->canonicalBaseUrl($baseUrl);
            $protectedUrl = $this->targets->appendPath($baseUrl, '/.well-known/oauth-protected-resource');
            $protected = $this->http->get($protectedUrl);
        } catch (UnsafeOutboundTarget $exception) {
            throw new BridgeDiscoveryException('unsafe_target', 'The WordPress site is not a safe public HTTPS target.');
        } catch (OutboundRequestException $exception) {
            throw $this->transportFailure($exception);
        }

        if ($protected->status === 404 || $protected->status === 410) {
            throw new BridgeDiscoveryException('missing_bridge', 'WP AI Bridge protected-resource metadata was not found.');
        }
        if ($protected->status !== 200) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge protected-resource metadata returned an unexpected status.');
        }

        try {
            $resourceMetadata = $protected->json();
        } catch (OutboundRequestException $exception) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge protected-resource metadata is not valid JSON.');
        }

        $resource = $this->requiredString($resourceMetadata, 'resource', 'protected-resource resource');
        $authorizationServers = $resourceMetadata['authorization_servers'] ?? null;
        $scopes = $resourceMetadata['scopes_supported'] ?? null;
        $bearerMethods = $resourceMetadata['bearer_methods_supported'] ?? null;

        if (! is_array($authorizationServers) || count($authorizationServers) !== 1 || ! is_string($authorizationServers[0])) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge must advertise one exact authorization server.');
        }
        if (! is_array($scopes) || ! in_array('mcp:use', $scopes, true)) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge does not advertise the required mcp:use scope.');
        }
        if (! is_array($bearerMethods) || ! in_array('header', $bearerMethods, true)) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge does not advertise header bearer authentication.');
        }

        try {
            $resource = $this->targets->assertSameOrigin($resource, $baseUrl)->url;
            $issuer = $this->targets->canonicalBaseUrl($authorizationServers[0]);
        } catch (UnsafeOutboundTarget $exception) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge metadata points outside the configured public site origin.');
        }

        if (! hash_equals($baseUrl, $issuer)) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge issuer does not match the configured WordPress base URL.');
        }

        try {
            $serverUrl = $this->targets->appendPath($issuer, '/.well-known/oauth-authorization-server');
            $server = $this->http->get($serverUrl);
        } catch (UnsafeOutboundTarget $exception) {
            throw new BridgeDiscoveryException('unsafe_target', 'WP AI Bridge authorization metadata target is unsafe.');
        } catch (OutboundRequestException $exception) {
            throw $this->transportFailure($exception);
        }

        if ($server->status !== 200) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge authorization-server metadata returned an unexpected status.');
        }

        try {
            $authorizationMetadata = $server->json();
        } catch (OutboundRequestException $exception) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge authorization-server metadata is not valid JSON.');
        }

        $metadataIssuer = $this->requiredString($authorizationMetadata, 'issuer', 'authorization-server issuer');
        $authorizationUrl = $this->requiredString($authorizationMetadata, 'authorization_endpoint', 'authorization endpoint');
        $tokenUrl = $this->requiredString($authorizationMetadata, 'token_endpoint', 'token endpoint');
        $revocationUrl = $this->requiredString($authorizationMetadata, 'revocation_endpoint', 'revocation endpoint');

        if (! hash_equals($issuer, rtrim($metadataIssuer, '/'))) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge authorization-server issuer is inconsistent.');
        }

        $this->requireCapability($authorizationMetadata, 'token_endpoint_auth_methods_supported', 'private_key_jwt');
        $this->requireCapability($authorizationMetadata, 'token_endpoint_auth_signing_alg_values_supported', 'RS256');
        $this->requireCapability($authorizationMetadata, 'revocation_endpoint_auth_methods_supported', 'private_key_jwt');
        $this->requireCapability($authorizationMetadata, 'revocation_endpoint_auth_signing_alg_values_supported', 'RS256');
        $this->requireCapability($authorizationMetadata, 'grant_types_supported', 'authorization_code');
        $this->requireCapability($authorizationMetadata, 'grant_types_supported', 'refresh_token');
        $this->requireCapability($authorizationMetadata, 'response_types_supported', 'code');
        $this->requireCapability($authorizationMetadata, 'code_challenge_methods_supported', 'S256');
        $this->requireCapability($authorizationMetadata, 'scopes_supported', 'mcp:use');
        $this->requireCapability($authorizationMetadata, 'scopes_supported', 'offline_access');

        if (($authorizationMetadata['client_id_metadata_document_supported'] ?? false) !== true) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge does not support Client ID Metadata Documents.');
        }
        if (($authorizationMetadata['authorization_response_iss_parameter_supported'] ?? false) !== true) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge does not advertise authorization response issuer binding.');
        }

        try {
            $authorizationUrl = $this->targets->assertSameOrigin($authorizationUrl, $baseUrl)->url;
            $tokenUrl = $this->targets->assertSameOrigin($tokenUrl, $baseUrl)->url;
            $revocationUrl = $this->targets->assertSameOrigin($revocationUrl, $baseUrl)->url;
        } catch (UnsafeOutboundTarget $exception) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge OAuth endpoints must remain on the configured public site origin.');
        }

        return new BridgeDiscovery(
            $baseUrl,
            $resource,
            $issuer,
            $authorizationUrl,
            $tokenUrl,
            $revocationUrl,
        );
    }

    /** @param array<string, mixed> $document */
    private function requiredString(array $document, string $key, string $label): string
    {
        $value = $document[$key] ?? null;
        if (! is_string($value) || $value === '' || strlen($value) > 2048) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge '.$label.' is missing or invalid.');
        }

        return $value;
    }

    /** @param array<string, mixed> $metadata */
    private function requireCapability(array $metadata, string $key, string $required): void
    {
        $values = $metadata[$key] ?? null;
        if (! is_array($values) || ! in_array($required, $values, true)) {
            throw new BridgeDiscoveryException('incompatible_metadata', 'WP AI Bridge OAuth capability '.$required.' is not advertised.');
        }
    }

    private function transportFailure(OutboundRequestException $exception): BridgeDiscoveryException
    {
        $reason = in_array($exception->reason, ['tls_failure', 'network_failure'], true)
            ? $exception->reason
            : 'network_failure';

        return new BridgeDiscoveryException($reason, 'WP AI Bridge metadata could not be reached safely.');
    }
}
