<?php

namespace App\Support\Admin;

use App\Application\Sites\SiteConnectionException;

final class SiteOperationMessage
{
    public function forConnectionException(SiteConnectionException $exception): string
    {
        return match ($exception->reason) {
            'unsafe_target' => (string) __('Use a public HTTPS WordPress URL that is reachable from the Gateway.'),
            'missing_bridge' => (string) __('WP AI Bridge was not found at this WordPress site.'),
            'incompatible_metadata' => (string) __('WP AI Bridge is present but its OAuth/MCP metadata is not compatible with this Gateway.'),
            'network_failure', 'tls_failure' => (string) __('The WordPress site could not be reached securely. Check DNS, TLS and network availability.'),
            'target_busy', 'target_conflict' => (string) __('That WordPress target is already assigned to another site or is being changed.'),
            'revocation_pending', 'disconnect_pending', 'removal_pending', 'revocation_failed' => (string) __('Credential revocation is incomplete. Retry after the remote site is reachable and can confirm revocation.'),
            'target_reassignment_pending', 'target_reassignment_lost' => (string) __('The site target is still being reassigned. Complete or retry that operation before continuing.'),
            'already_connected' => (string) __('This site already has a credential. Use Reconnect or Disconnect instead.'),
            'missing_credential' => (string) __('This site has no active credential. Use Connect to authorize it.'),
            'authorization_denied' => (string) __('WordPress authorization was not completed.'),
            'credential_unavailable' => (string) __('The stored site credential cannot be opened with the current application key. Restore the matching key material before reconnecting.'),
            default => (string) __('The site operation could not be completed safely. Retry the operation or review the bounded site status code.'),
        };
    }

    public function invalidSiteDetails(): string
    {
        return (string) __('The site details could not be accepted. Check the display name and WordPress URL, and make sure the target is not already registered.');
    }
}
