<?php

namespace App\Support;

use App\Domain\Targets\Target;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

/**
 * Operator-safe diagnostics for every connector and transport.
 *
 * Error codes are stable machine identities; explanations and next steps are
 * UI-only guidance. Only an explicit allowlist of scalar diagnostics is logged.
 * Never pass exception messages, request URLs, headers, bodies, shell commands,
 * tokens, paths, credentials or remote response content into this reporter.
 */
final class OperationDiagnostics
{
    /**
     * Best-effort report. Reporting must not change a remote operation outcome.
     *
     * @param  array<string,mixed>  $details
     */
    public static function failure(
        string $operation, string $code, ?Target $target = null, array $details = [],
        ?string $correlationId = null,
    ): string {
        $reference = is_string($correlationId) && Str::isUuid($correlationId)
            ? $correlationId : CorrelationId::current();
        $safe = [
            'correlation_id' => $reference,
            'operation' => self::identifier($operation, 128),
            'error_code' => self::identifier($code, 64),
            'target_id' => $target?->target_id,
            'connector_type' => $target?->connector_type,
        ];
        $stage = $details['failure_stage'] ?? null;
        if (is_string($stage) && in_array($stage, [
            'dns_lookup', 'dns_timeout', 'deadline_before_dispatch',
            'tcp_connect', 'tls_handshake', 'request_timeout',
            'connection_setup', 'response_transfer', 'response_body',
            'remote_http', 'operation', 'unknown',
        ], true)) {
            $safe['failure_stage'] = $stage;
        }
        $status = $details['http_status'] ?? null;
        if (is_int($status) && $status >= 100 && $status <= 599) {
            $safe['remote_http_status'] = $status;
        }
        if (is_bool($details['pre_dispatch'] ?? null)) {
            $safe['request_not_sent'] = $details['pre_dispatch'];
        }
        if (is_bool($details['retry_safe'] ?? null)) {
            $safe['retry_safe'] = $details['retry_safe'];
        }

        try {
            Log::warning('Gateway operation failure.', $safe);
        } catch (Throwable) {
            // Logging failures must not change OAuth/SSH side effects or responses.
        }

        return $reference;
    }

    public static function summary(string $code): string
    {
        return match ($code) {
            'network_failure' => __('HTTPS communication with the remote service failed. The exact cause must be identified from the failure stage in the Gateway log.'),
            'tls_failure' => __('The remote TLS certificate, hostname or secure handshake could not be verified.'),
            'unsafe_target' => __('The outbound security policy rejected this destination.'),
            'missing_bridge' => __('The WordPress Bridge discovery endpoint was not found.'),
            'incompatible_metadata' => __('The WordPress OAuth or MCP metadata is incompatible or returned an unexpected response.'),
            'revocation_pending', 'disconnect_pending' => __('WordPress credential revocation has not been confirmed. The existing credential remains blocked, not forgotten.'),
            'revocation_failed' => __('WordPress did not confirm the OAuth credential revocation.'),
            'revocation_conflict' => __('The credential or revocation state changed while the operation was running.'),
            'revocation_uncertain' => __('A previous WordPress token revoke may have reached the server; no safe replay or cancellation proof exists.'),
            'cancel_not_safe', 'cancel_verification_failed', 'cancel_verification_unavailable' => __('The old WordPress authorization has not been independently verified and the pending disconnect remains in force.'),
            'operation_unconfirmed' => __('Gateway could not confirm durable completion. The remote operation may already have executed.'),
            'refresh_unavailable' => __('WordPress credential renewal is temporarily unavailable. Remote authorization has not necessarily been lost.'),
            'refresh_ambiguous', 'refresh_pending' => __('The outcome of a remote token rotation is uncertain; automatic replay is unsafe.'),
            'credential_unavailable' => __('The stored credential could not be opened with the current Gateway encryption configuration.'),
            'missing_credential', 'reconnect_required' => __('This Target has no currently usable authorization.'),
            'authentication_failed', 'credential_invalid' => __('SSH login authentication failed or the stored login credential is invalid.'),
            'host_key_mismatch', 'tcp_peer_mismatch' => __('The SSH server identity did not match the trusted endpoint.'),
            'tcp_unreachable', 'egress_denied' => __('The SSH endpoint could not be reached under the approved network policy.'),
            'connection_busy', 'rate_limited', 'admission_unavailable' => __('The connector is temporarily busy or its safety limits are active.'),
            'connection_unavailable', 'ssh_handshake_failed' => __('The SSH connection could not be established securely.'),
            'outcome_unknown' => __('A remote command or file write may have occurred; do not retry automatically.'),
            'response_too_large', 'file_too_large' => __('The data exceeds the configured safe resource limit.'),
            'transfer_timed_out' => __('The file transfer exceeded its allowed execution time.'),
            'invalid_input' => __('Some input fields or tool arguments are invalid.'),
            'forbidden', 'target_not_found' => __('This operation or Target is not available to the current user.'),
            'target_paused' => __('Gateway operations on this Target are temporarily paused by the Owner.'),
            'server_error', 'file_unavailable' => __('An internal or downstream operation failed. Consult the server diagnostic log.'),
            default => __('The operation did not complete safely. Consult the error code and server diagnostic log.'),
        };
    }

    public static function nextStep(string $code): string
    {
        return match ($code) {
            'network_failure' => __('Check the failure stage and the Owner Operations → Outbound DNS compatibility preflight. On OpenLiteSpeed LSAPI, a VHost php_admin_value open_basedir may block /etc/resolv.conf or /etc/hosts even if WordPress is healthy. Otherwise check public A/AAAA DNS, outbound TCP 443, TLS, WAF and timeout. Never disable SSRF/TLS protections.'),
            'tls_failure' => __('Check certificate validity, hostname/SNI and full certificate chain from the Gateway host. Do not disable TLS verification.'),
            'unsafe_target' => __('Use a public HTTPS origin and review its DNS records and the Gateway outbound policy. Do not bypass SSRF protections.'),
            'missing_bridge' => __('Check that WP AI Bridge is installed, active and exposes its well-known OAuth metadata routes.'),
            'incompatible_metadata' => __('Compare the WordPress Bridge version, advertised OAuth endpoints and exact issuer/resource metadata.'),
            'revocation_pending', 'disconnect_pending', 'revocation_failed', 'revocation_uncertain' => __('Open Target Details → Connection and recovery. Resume only a step explicitly marked proven-not-sent. For unknown results, the Owner must remove the Gateway client approval in WordPress and complete attested reconciliation. A green Metadata check does not change this.'),
            'cancel_not_safe', 'cancel_verification_failed', 'cancel_verification_unavailable' => __('Do not assume Cancel succeeded. The Owner can finish a proven-not-sent revoke or independently reconcile the authorization at WordPress.'),
            'operation_unconfirmed' => __('Reload Target Details to inspect the durable intent phase and use only the action offered there. Do not blindly resubmit remote operations.'),
            'revocation_conflict' => __('Reload current Target details and reconcile the existing pending operation before another attempt.'),
            'refresh_unavailable' => __('Check the Gateway signing configuration and remote HTTPS reachability, then retry after the defined backoff.'),
            'refresh_ambiguous', 'refresh_pending' => __('Do not rotate the old token again. Follow the documented Owner-only remote-revocation and recovery procedure.'),
            'credential_unavailable' => __('Restore the correct Gateway encryption key or safely reauthorize according to the recovery procedure.'),
            'missing_credential', 'reconnect_required' => __('Complete the explicit authorization workflow for this Target.'),
            'authentication_failed', 'credential_invalid' => __('Review the SSH username and login secret in the Target configuration; verify the server host-key pin independently.'),
            'host_key_mismatch', 'tcp_peer_mismatch' => __('Verify the server host key and numeric destination out of band before trusting or reconnecting.'),
            'tcp_unreachable', 'egress_denied' => __('Check route, firewall, configured host and port, and the Gateway outbound SSH policy.'),
            'connection_busy', 'rate_limited', 'admission_unavailable' => __('Wait for the existing attempt or the advertised limit to clear; avoid parallel retries.'),
            'outcome_unknown' => __('Inspect the remote state and any transfer receipt before deciding whether another command or write is safe.'),
            'response_too_large', 'file_too_large' => __('Reduce the payload or use a supported bounded transfer mode. Do not disable resource limits.'),
            'transfer_timed_out' => __('Check network performance and supported operation budgets before a safe new attempt.'),
            'invalid_input' => __('Correct the indicated input or tool parameters.'),
            'forbidden', 'target_not_found' => __('Ask the Owner to review user capability and selected Target scope; do not expose an unauthorized Target.'),
            'target_paused' => __('Ask the Owner to resume this Target. Stored connection and permissions are unchanged.'),
            'server_error', 'file_unavailable' => __('Look up the matching diagnostic reference in the server logs, then inspect the owning component.'),
            default => __('Find the matching operation, error code, time and diagnostic reference in the Gateway logs.'),
        };
    }

    private static function identifier(string $value, int $max): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9_.-]+/', '_', $value) ?? '';

        return substr($safe, 0, $max) ?: 'unspecified';
    }
}
