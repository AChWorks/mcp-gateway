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
 * UI-only guidance, never replacements for original observed error codes/text.
 * Preserve useful provider/transport detail for permissioned diagnostics;
 * redact secret values instead of blindly hiding paths, messages or URLs.
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
        try {
            // An error during redaction must not fall back to logging raw
            // upstream evidence, nor change an already completed remote effect.
            $safe = [
                'correlation_id' => $reference,
                'operation' => self::identifier($operation, 128),
                'error_code' => self::identifier($code, 64),
                'target_id' => $target?->target_id,
                'connector_type' => $target?->connector_type,
                ...self::safeContext($details),
            ];
            Log::warning('Gateway operation failure.', $safe);
        } catch (Throwable) {
            // Logging failures must not change OAuth/SSH side effects or responses.
        }

        return $reference;
    }

    /**
     * Canonical redacted diagnostic context shared by Activity, MCP, Admin and logs.
     * Keep source messages/codes as received, marking configured truncation.
     * The same selective redaction applies on both storage and retrieval.
     *
     * @param  array<string,mixed>  $details
     * @return array<string,mixed>
     */
    public static function safeContext(array $details): array
    {
        $safe = [];
        $origin = $details['failure_origin'] ?? null;
        if (is_string($origin) && in_array($origin, [
            'gateway_admission', 'gateway_transport', 'gateway_response',
            'downstream_http', 'downstream_mcp', 'unknown',
        ], true)) {
            $safe['failure_origin'] = $origin;
        }
        $stage = $details['failure_stage'] ?? null;
        if (is_string($stage) && in_array($stage, [
            'dns_lookup', 'dns_timeout', 'deadline_before_dispatch',
            'tcp_connect', 'tls_handshake', 'request_timeout',
            'connection_setup', 'response_transfer', 'response_body',
            'remote_http', 'operation', 'admission', 'unknown',
        ], true)) {
            $safe['failure_stage'] = $stage;
        }
        $status = $details['http_status'] ?? $details['remote_http_status'] ?? null;
        if (is_int($status) && $status >= 100 && $status <= 599) {
            $safe['remote_http_status'] = $status;
        }
        $notSent = $details['pre_dispatch'] ?? $details['request_not_sent'] ?? null;
        if (is_bool($notSent)) {
            $safe['request_not_sent'] = $notSent;
        }
        if (is_bool($details['retry_safe'] ?? null)) {
            $safe['retry_safe'] = $details['retry_safe'];
        }
        if (is_bool($details['effect_unconfirmed'] ?? null)) {
            $safe['effect_unconfirmed'] = $details['effect_unconfirmed'];
        }
        if (($details['provider_cause_unknown'] ?? null) === true
            || ($details['provider_cause'] ?? null) === 'unknown') {
            $safe['provider_cause'] = 'unknown';
        }
        $phase = $details['phase'] ?? $details['response_phase'] ?? null;
        if (is_string($phase) && in_array($phase, [
            'content_length', 'collected_body', 'decoded_body',
        ], true)) {
            $safe['response_phase'] = $phase;
        }
        foreach (['limit_bytes', 'observed_bytes'] as $key) {
            $value = $details[$key] ?? null;
            if (is_int($value) && $value >= 0 && $value <= 1099511627776) {
                $safe[$key] = $value;
            }
        }

        // Timings are server-derived, numeric and bounded. Never accept
        // arbitrary stage labels, URLs or payload-shaped diagnostic fields.
        $timing = $details['timing'] ?? null;
        if (is_array($timing)) {
            $allowed = ['total_ms', ...OperationTiming::STAGES, 'outbound_calls', 'curl_observed_calls'];
            $safeTiming = [];
            foreach ($allowed as $name) {
                $value = $timing[$name] ?? null;
                $limit = str_ends_with($name, '_calls') ? 128 : OperationTiming::MAX_MS;
                if (is_int($value) && $value >= 0 && $value <= $limit) {
                    $safeTiming[$name] = $value;
                }
            }
            if ($safeTiming !== []) {
                $safe['timing'] = $safeTiming;
            }
        }

        // Preserve observed native codes and messages *alongside* classifications,
        // rather than forcing unknown provider errors into Gateway's code vocabulary.
        foreach (['source_error_code', 'source_error_message', 'source_error_structured_message', 'gateway_error_message'] as $key) {
            $value = $details[$key] ?? null;
            if (! is_string($value) && ! is_int($value)) {
                continue;
            }

            if (is_int($value)) {
                $safe[$key] = $value;

                continue;
            }

            $redacted = DiagnosticRedactor::text($value);
            $limit = (int) config('activity.'.($key === 'source_error_code'
                ? 'diagnostic_code_max_bytes' : 'diagnostic_message_max_bytes'), 65536);
            $limit = max(128, $limit);
            $safe[$key] = strlen($redacted) > $limit
                ? mb_strcut($redacted, 0, $limit, 'UTF-8') : $redacted;
            if (strlen($redacted) > $limit || ($details[$key.'_truncated'] ?? false) === true) {
                $safe[$key.'_truncated'] = true;
            }
        }

        $exceptionClass = $details['exception_class'] ?? null;
        if (is_string($exceptionClass) && strlen($exceptionClass) <= 256
            && ctype_alnum(str_replace(['\\', '_'], '', $exceptionClass))) {
            $safe['exception_class'] = $exceptionClass;
        }

        if (array_key_exists('source_error_details', $details)) {
            $redacted = DiagnosticRedactor::value($details['source_error_details']);
            $json = json_encode($redacted, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (is_string($json)) {
                $limit = max(1024, (int) config('activity.diagnostic_details_max_bytes', 131072));
                if (strlen($json) > $limit) {
                    $safe['source_error_details_excerpt'] = mb_strcut($json, 0, $limit, 'UTF-8');
                    $safe['source_error_details_truncated'] = true;
                } else {
                    $safe['source_error_details'] = $redacted;
                }
            }
        } elseif (is_string($details['source_error_details_excerpt'] ?? null)) {
            $limit = max(1024, (int) config('activity.diagnostic_details_max_bytes', 131072));
            $value = DiagnosticRedactor::text($details['source_error_details_excerpt']);
            $safe['source_error_details_excerpt'] = mb_strcut($value, 0, $limit, 'UTF-8');
            $safe['source_error_details_truncated'] = true;
        }

        return $safe;
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
            'timeout_unsupported' => __('The PHP worker deadline is shorter than the selected SSH command timeout. No command was dispatched.'),
            'ssh_output_collector_unavailable' => __('The installed SSH library is incompatible with safe bounded command output capture. No command was dispatched.'),
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
            'timeout_unsupported' => __('Ask the Owner to qualify and adjust the PHP worker, reverse-proxy and MCP client deadlines before selecting a long synchronous command. Use retained SSH Jobs if those hops cannot support it.'),
            'ssh_output_collector_unavailable' => __('Review the installed phpseclib SSH2 stdout/stderr callback contract and restore the supported library version before retrying.'),
            'outcome_unknown' => __('Inspect the remote state and any transfer receipt before deciding whether another command or write is safe.'),
            'downstream_rejected' => __('A downstream MCP Tool reported an error but its provider cause may be unavailable. Use the diagnostic reference in authorized Admin Activity or the operation-diagnostics-read MCP Tool to inspect the original observed error. If the upstream Adapter stripped the provider cause, inspect Bridge/WordPress. Reconcile uncertain remote effects before any retry.'),
            'response_too_large', 'file_too_large' => __('Reduce the payload or use a supported bounded transfer mode. Do not disable resource limits.'),
            'transfer_timed_out' => __('Check network performance and supported operation budgets before a safe new attempt.'),
            'invalid_input' => __('Correct the indicated input or tool parameters.'),
            'forbidden', 'target_not_found' => __('Ask the Owner to review user capability and selected Target scope; do not expose an unauthorized Target.'),
            'target_paused' => __('Ask the Owner to resume this Target. Stored connection and permissions are unchanged.'),
            'server_error', 'file_unavailable' => __('Look up the diagnostic reference in authorized Admin Activity or operation-diagnostics-read. Inspect the owning component if its original cause was not received.'),
            default => __('Find the matching operation, error code, time and diagnostic reference in the Gateway logs.'),
        };
    }

    private static function identifier(string $value, int $max): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9_.-]+/', '_', $value) ?? '';

        return substr($safe, 0, $max) ?: 'unspecified';
    }
}
