<?php

declare(strict_types=1);

/** Real HTTPS WordPress login and explicit nonce-protected OAuth consent. */
$root = (string) getenv('MIXED_ROOT');
$state = json_decode((string) file_get_contents($root.'/secrets/state.json'), true, 512, JSON_THROW_ON_ERROR);
$authorize = (string) $state['authorize_url'];
$site = 'https://11.22.33.44';
$jar = $root.'/secrets/cookies.txt';
$cert = $root.'/secrets/tls.crt';
$send = static function (string $url, ?array $post = null) use ($site, $cert, $jar): array {
    if (! str_starts_with($url, $site.'/')) {
        throw new RuntimeException('Unexpected browser OAuth navigation outside disposable WordPress.');
    }
    $handle = curl_init($url);
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CAINFO => $cert,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_NOPROXY => '*',
    ]);
    if ($post !== null) {
        curl_setopt($handle, CURLOPT_POST, true);
        curl_setopt($handle, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $raw = curl_exec($handle);
    if (! is_string($raw)) {
        throw new RuntimeException('Real OAuth browser HTTP failed: '.curl_error($handle));
    }
    $headerLen = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
    $code = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    $headers = substr($raw, 0, $headerLen);
    $body = substr($raw, $headerLen);
    preg_match('/^Location:\s*(.*?)\r?$/mi', $headers, $matches);

    return [$code, $body, trim($matches[1] ?? '')];
};
[$getLogin] = $send($site.'/wp-login.php');
if ($getLogin !== 200) {
    throw new RuntimeException('WordPress login page unavailable.');
}
[$loginCode, , $loginLocation] = $send($site.'/wp-login.php', [
    'log' => 'mixedadmin', 'pwd' => trim((string) file_get_contents($root.'/secrets/wp-password')),
    'wp-submit' => 'Log In', 'redirect_to' => $site.'/wp-admin/', 'testcookie' => '1',
]);
if ($loginCode !== 302 || ! str_contains($loginLocation, '/wp-admin/')) {
    throw new RuntimeException('Disposable WordPress authenticated login failed.');
}
[$consentCode, $page] = $send($authorize);
if ($consentCode !== 200 || ! str_contains($page, 'consent_id')) {
    throw new RuntimeException('WordPress real OAuth consent form not returned (status '.$consentCode.').');
}
if (! preg_match('/name="consent_id" value="([^"]+)"/', $page, $id)
    || ! preg_match('/name="_wpnonce" value="([^"]+)"/', $page, $nonce)) {
    throw new RuntimeException('WordPress OAuth consent form nonce or ID unavailable.');
}
[$approveCode, , $location] = $send($site.'/wp-ai-bridge/oauth/authorize', [
    'consent_id' => html_entity_decode($id[1], ENT_QUOTES),
    '_wpnonce' => html_entity_decode($nonce[1], ENT_QUOTES),
    'decision' => 'approve',
]);
if ($approveCode !== 302 || ! str_starts_with($location, 'https://11.22.33.45/oauth/targets/callback?')) {
    throw new RuntimeException('WordPress real nonce-protected consent did not redirect to Gateway callback.');
}
parse_str((string) parse_url($location, PHP_URL_QUERY), $callback);
if (! isset($callback['code'], $callback['state'], $callback['iss'])) {
    throw new RuntimeException('WordPress OAuth authorization response missing signed callback bindings.');
}
file_put_contents($root.'/secrets/callback.json', json_encode([
    'code' => $callback['code'], 'state' => $callback['state'], 'iss' => $callback['iss'],
], JSON_THROW_ON_ERROR), LOCK_EX);
chmod($root.'/secrets/callback.json', 0600);
echo "Real WordPress login, user consent and authorization code obtained over verified HTTPS.\n";
