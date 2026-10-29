<?php

namespace App\Support;

use App\Domain\Targets\Target;
use App\Infrastructure\Http\PublicIpAddressPolicy;
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
        // Shared SSRF rejection context. Only policy-defined reason names and
        // literal numeric IPs enter the operator log or browser diagnostics.
        $rejection = $details['outbound_rejection_reason'] ?? null;
        if (is_string($rejection) && in_array($rejection, [
            'invalid_target', 'invalid_url', 'https_required', 'unsupported_url_components',
            'invalid_host', 'invalid_path', 'origin_not_allowed', 'origin_mismatch',
            'dns_no_address', 'dns_non_public', 'dns_too_many_addresses', 'dns_invalid_address',
        ], true)) {
            $safe['outbound_rejection_reason'] = $rejection;
            if ($rejection === 'dns_non_public') {
                $address = $details['outbound_rejected_address'] ?? null;
                if (is_string($address) && strlen($address) <= 45
                    && filter_var($address, FILTER_VALIDATE_IP) !== false
                    && ! (new PublicIpAddressPolicy)->isPublic($address)) {
                    $safe['outbound_rejected_address'] = $address;
                }
                $addressSource = $details['outbound_address_source'] ?? null;
                if (isset($safe['outbound_rejected_address']) && is_string($addressSource)
                    && in_array($addressSource, ['literal', 'dns'], true)) {
                    $safe['outbound_address_source'] = $addressSource;
                }
                $addressClass = $details['outbound_address_class'] ?? null;
                if (is_string($addressClass) && in_array($addressClass, [
                    'loopback', 'private', 'link_local', 'restricted',
                ], true)) {
                    $safe['outbound_address_class'] = $addressClass;
                }
            }
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

    /** @param array<string, mixed> $details */
    public static function summary(string $code, array $details = []): string
    {
        return match ($code) {
            'network_failure' => self::networkSummary($details),
            'tls_failure' => __('The remote TLS certificate, hostname or secure handshake could not be verified.'),
            'unsafe_target' => self::outboundSummary($details),
            'missing_bridge' => __('The WordPress Bridge discovery endpoint was not found.'),
            'incompatible_metadata' => isset(self::safeContext($details)['outbound_rejection_reason'])
                ? __('The WordPress OAuth/MCP metadata violates the Target outbound policy: :reason', ['reason' => self::outboundSummary($details)])
                : __('The WordPress OAuth or MCP metadata is incompatible or returned an unexpected response.'),
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
            'tcp_unreachable' => __('The SSH endpoint could not be reached under the approved network policy.'),
            'egress_denied' => isset($details['outbound_rejection_reason'])
                ? self::outboundSummary($details)
                : __('The SSH endpoint could not be reached under the approved network policy.'),
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

    /** @param array<string, mixed> $details */
    public static function nextStep(string $code, array $details = []): string
    {
        return match ($code) {
            'network_failure' => self::networkNextStep($details),
            'tls_failure' => __('Check certificate validity, hostname/SNI and full certificate chain from the Gateway host. Do not disable TLS verification.'),
            'unsafe_target' => self::outboundNextStep($details),
            'missing_bridge' => __('Check that WP AI Bridge is installed, active and exposes its well-known OAuth metadata routes.'),
            'incompatible_metadata' => isset(self::safeContext($details)['outbound_rejection_reason'])
                ? self::outboundNextStep($details)
                : __('Compare the WordPress Bridge version, advertised OAuth endpoints and exact issuer/resource metadata.'),
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
            'tcp_unreachable' => __('Check route, firewall, configured host and port, and the Gateway outbound SSH policy.'),
            'egress_denied' => isset($details['outbound_rejection_reason'])
                ? self::outboundNextStep($details)
                : __('Check route, firewall, configured host and port, and the Gateway outbound SSH policy.'),
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

    /** @param array<string, mixed> $details */
    private static function networkSummary(array $details): string
    {
        return match (self::safeContext($details)['failure_stage'] ?? null) {
            'dns_lookup' => __('Gateway DNS resolution failed before the destination could be reached.'),
            'dns_timeout' => __('Gateway DNS resolution timed out before the destination could be reached.'),
            'tcp_connect' => __('The Gateway could not establish a TCP connection to the remote destination.'),
            default => __('Network communication with the remote service failed. Check the recorded failure stage for the observed cause.'),
        };
    }

    /** @param array<string, mixed> $details */
    private static function networkNextStep(array $details): string
    {
        return match (self::safeContext($details)['failure_stage'] ?? null) {
            'dns_lookup', 'dns_timeout' => __('Check the Gateway host DNS settings, effective A/AAAA records and local resolver access (/etc/resolv.conf and /etc/hosts). On restricted LSAPI hosting, open_basedir may block those files. Do not bypass destination protections.'),
            'tcp_connect' => __('Check the Target host and port, the Gateway outbound firewall and actual network route. Do not bypass destination policy.'),
            'request_timeout' => __('Check the Gateway request deadline, downstream service responsiveness, proxy and network latency before retrying an operation known to be safe.'),
            default => __('Inspect the logged failure stage and Gateway DNS for the selected connector. HTTPS needs outbound TCP 443 and valid TLS; SSH uses the registered TCP port and independently pinned host key. Review network routing and timeouts without weakening trust protections.'),
        };
    }

    /** @param array<string, mixed> $details */
    private static function outboundSummary(array $details): string
    {
        $safe = self::safeContext($details);
        $reason = $safe['outbound_rejection_reason'] ?? null;

        if ($reason === 'dns_non_public') {
            $address = $safe['outbound_rejected_address'] ?? null;
            $kind = match ($safe['outbound_address_class'] ?? null) {
                'loopback' => __('loopback'),
                'private' => __('private-network'),
                'link_local' => __('link-local'),
                default => __('non-public'),
            };

            if (($safe['outbound_address_source'] ?? null) === 'literal') {
                return is_string($address)
                    ? __('The configured :kind IP address (:address) is blocked by Gateway policy.', ['kind' => $kind, 'address' => $address])
                    : __('The configured :kind IP address is blocked by Gateway policy.', ['kind' => $kind]);
            }

            return is_string($address)
                ? __('Gateway DNS resolved this hostname to a blocked :kind IP address (:address).', [
                    'kind' => $kind, 'address' => $address,
                ])
                : __('Gateway DNS resolved this hostname to a blocked :kind IP address.', ['kind' => $kind]);
        }

        return match ($reason) {
            'dns_no_address' => __('The Gateway resolver returned no A or AAAA address for this hostname.'),
            'dns_too_many_addresses' => __('The Gateway resolver returned more addresses than the connector safety policy permits.'),
            'dns_invalid_address' => __('The Gateway DNS result includes an invalid numeric address.'),
            'https_required' => __('The destination must use HTTPS.'),
            'unsupported_url_components' => __('The URL includes credentials, query parameters or a fragment that cannot be used for a Target origin.'),
            'invalid_url', 'invalid_host', 'invalid_path' => __('The URL or hostname is invalid or contains an ambiguous path.'),
            'origin_mismatch' => __('The remote endpoint advertises a different origin than the configured Target.'),
            'origin_not_allowed' => __('The remote URL origin is not authorized for this operation.'),
            default => __('The outbound security policy rejected this destination.'),
        };
    }

    /** @param array<string, mixed> $details */
    private static function outboundNextStep(array $details): string
    {
        $safe = self::safeContext($details);
        $reason = $safe['outbound_rejection_reason'] ?? null;

        return match ($reason) {
            'dns_non_public' => ($safe['outbound_address_source'] ?? null) === 'literal'
                ? __('Replace the configured numeric IP with a verified public address, or correct the intended endpoint. No DNS lookup occurred for this literal. Do not bypass SSRF protections.')
                : (($safe['outbound_address_class'] ?? null) === 'loopback'
                ? __('The destination is loopback. Replace a configured localhost IP or correct a Gateway /etc/hosts override after verifying the intended public address. Do not bypass SSRF protections.')
                : __('Check the Gateway host DNS resolver, local overrides (including /etc/hosts), and the authoritative A/AAAA records. Every returned IP must be publicly routable. Do not bypass SSRF protections.')),
            'dns_no_address' => __('Verify public A/AAAA records and the Gateway host DNS configuration. An empty answer does not prove the site is offline; fix DNS before retrying.'),
            'dns_too_many_addresses' => __('Review the hostname DNS records and reduce the answer set to the connector limit. Do not disable the public-IP policy.'),
            'dns_invalid_address' => __('Review the DNS answer set and Gateway resolver. Every permitted address must be a valid public IPv4 or IPv6 address.'),
            'https_required' => __('Enter the canonical https:// URL and configure a valid TLS certificate on the Target.'),
            'unsupported_url_components', 'invalid_url', 'invalid_host', 'invalid_path' => __('Enter only the canonical public HTTPS origin or supported site path; remove credentials, query strings, fragments and ambiguous path segments.'),
            'origin_mismatch', 'origin_not_allowed' => __('Verify that the advertised remote endpoint uses the same approved HTTPS origin as the configured Target. Do not follow an untrusted cross-origin redirect.'),
            default => __('Use a public HTTPS origin and review its DNS records and the Gateway outbound policy. Do not bypass SSRF protections.'),
        };
    }

    private static function identifier(string $value, int $max): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9_.-]+/', '_', $value) ?? '';

        return substr($safe, 0, $max) ?: 'unspecified';
    }
}
