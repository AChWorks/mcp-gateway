<?php

declare(strict_types=1);

use GuzzleHttp\Client as Http;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;

/**
 * Independent SDK measurements through the registered native Relay, with
 * directly reachable end Targets as discriminating no-fallback controls.
 */
function qualifyInstalledRelay(
    array $state,
    string $phase,
    Client $client,
    Http $http,
    Closure $connect,
    Closure $call,
    Closure $check,
): array {
    $check(in_array($phase, ['online', 'offline', 'recovered'], true), 'Unexpected Relay probe phase.');
    $relaySsh = $state['relay_ssh_target'];
    $wp = $state['wp_target'];
    $check($relaySsh === 'mixed-relay-ssh' && $wp === 'mixed-wp', 'Unexpected disposable Relay Targets.');
    $direct = Client::builder()->setClientInfo('installed-relay-direct-control', '1')
        ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
    $wpInput = str_repeat('x', $phase === 'online' ? 1000000 : 64);
    $expected = ['bytes' => strlen($wpInput), 'sha256' => hash('sha256', $wpInput), 'principal_id' => 1];
    try {
        $client->connect($connect($state['owner_token']));
        $direct->connect(new HttpTransport(
            endpoint: $state['wp_direct']['resource'],
            headers: ['Authorization' => 'Bearer '.$state['wp_direct']['access_token']],
            httpClient: $http,
        ));
        $ability = 'gateway-mixed-test/digest-read';
        $native = $call($direct, 'mcp-adapter-execute-ability', [
            'ability_name' => $ability, 'parameters' => ['payload' => $wpInput],
        ], 'relay_wp_direct_control');
        $check(($native['success'] ?? false) === true && ($native['data'] ?? null) === $expected,
            'Direct provider control did not return the expected principal and digest.');
        $routed = $call($client, 'wordpress-ability-execute', [
            'target_id' => $wp, 'ability' => $ability, 'input' => ['payload' => $wpInput],
        ], 'relay_wp_routed');
        $command = "printf 'relay-exact-command'; exit 7";
        $directSsh = $call($client, 'ssh-command-run', [
            'target_id' => $state['ssh_target'], 'command' => $command,
        ], 'relay_ssh_direct_control');
        $check(($directSsh['ok'] ?? false) === true
            && ($directSsh['result']['stdout'] ?? null) === 'relay-exact-command'
            && ($directSsh['result']['exit_code'] ?? null) === 7, 'Direct SSH control failed.');
        $viaRelay = $call($client, 'ssh-command-run', [
            'target_id' => $relaySsh, 'command' => $command,
        ], 'relay_ssh_command');
        if ($phase === 'offline') {
            $wpCode = $routed['error']['code'] ?? null;
            $sshCode = $viaRelay['error']['code'] ?? null;
            $check(($routed['ok'] ?? true) === false && $wpCode === 'network_failure',
                'WordPress silently fell back or returned unexpected Relay failure: '.($wpCode ?? 'none'));
            $check(($viaRelay['ok'] ?? true) === false && $sshCode === 'relay_unavailable',
                'SSH silently fell back or returned unexpected Relay failure: '.($sshCode ?? 'none'));

            return ['phase' => $phase, 'direct_wp_control' => true, 'direct_ssh_control' => true,
                'wp_error' => $wpCode, 'ssh_error' => $sshCode,
                'direct_fallback_observed' => false];
        }
        $check(($routed['ok'] ?? false) === true && ($routed['result'] ?? null) === $expected,
            'WordPress Relay same-grant digest mismatch.');
        $check(($viaRelay['ok'] ?? false) === true
            && ($viaRelay['result']['stdout'] ?? null) === 'relay-exact-command'
            && ($viaRelay['result']['exit_code'] ?? null) === 7, 'Native Relay SSH command/exit mismatch.');
        $result = ['phase' => $phase, 'wp_same_grant_digest' => $expected,
            'direct_ssh_control' => true, 'ssh_command_exit' => 7];
        if ($phase === 'recovered') {
            return $result;
        }
        // Reuse exactly the Direct representative workloads and assertions.
        $result['sftp'] = qualifyInstalledInlineSftp($client, $relaySsh, 'relay_', $call, $check);
        $result['staged_script'] = qualifyInstalledStagedScript($client, $relaySsh, 'relay_', $call, $check);

        return $result;
    } finally {
        $direct->disconnect();
        $client->disconnect();
    }
}
