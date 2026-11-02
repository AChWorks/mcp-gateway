<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\View;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Uri;
use Illuminate\Support\ViewErrorBag;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Deliver native Admin POST/redirect/GET and GET-originated redirect feedback
 * to its own destination, not whichever tab next shares the session cookie.
 *
 * The URL carries only an unpredictable identifier. The result is encrypted in
 * the shared server cache, bound to the current user, session and exact path,
 * claimed under a cache lock, and never replayed after its first GET.
 */
final class CorrelatedAdminFeedback
{
    private const PARAMETER = '_admin_feedback';

    private const LIFETIME_SECONDS = 600;

    // Keep the existing key for in-flight POST redirects across an upgrade.
    private const REDIRECT_FLASH_SOURCE = 'admin.feedback.post_flash_source';

    private const SESSION_BINDING = 'admin.feedback.session_binding';

    // Only existing browser-facing flash data is transported. Never capture
    // session auth, OAuth handoffs, access-batch snapshots or arbitrary keys.
    private const FIELDS = [
        'status', 'errors', '_old_input', 'target_connection_failed',
        'target_endpoint_preflight', 'target_preflight_validation_failed',
        'diagnostic_code', 'diagnostic_stage', 'diagnostic_context', 'diagnostic_reference',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        // The OAuth callback remains publicly routable for protocol reasons.
        // Do not silently change that access boundary or force a guest's
        // previously native-flashed result through an authenticated-only claim.
        if ($request->is('oauth/targets/callback') && $request->user() === null) {
            return $next($request);
        }

        // Stable session-held nonce rather than a browser cookie or a request-
        // local session ID, which can change on authentication rotation.
        // Created on the first Admin GET, before any valid form can POST.
        if (! is_string($request->session()->get(self::SESSION_BINDING))) {
            $request->session()->put(self::SESSION_BINDING, bin2hex(random_bytes(20)));
        }

        if ($request->isMethod('GET') && ! $request->expectsJson()) {
            $response = $this->display($request, $next);

            // A controller may generate NEW flash data on a GET: OAuth
            // callbacks and single-use external-authorization handoffs do.
            // Bind that result to its exact redirect before StartSession
            // commits the native flash, as for authenticated POST results.
            if ($response instanceof RedirectResponse) {
                $this->routeFeedback($request, $response);
            }

            return $response;
        }

        if (! in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $next($request);
        }

        // Old pending notices belong to their previous redirect token. They
        // must not be merged into a second operation's flashed error bag.
        $this->forgetFields($request);
        $request->session()->forget(self::REDIRECT_FLASH_SOURCE);
        try {
            $response = $next($request);
        } catch (ValidationException $exception) {
            // Laravel normally converts this exception to a redirect outside
            // route middleware. Handle it here through the *same* framework
            // exception handler, so both manual and automatic validation
            // failures receive an operation-correlated, one-use result.
            $response = app(ExceptionHandler::class)->render($request, $exception);
        }

        if ($response instanceof RedirectResponse) {
            $this->routeFeedback($request, $response);
        }

        return $response;
    }

    private function display(Request $request, Closure $next): Response
    {
        $token = $request->query(self::PARAMETER);
        $hasToken = is_string($token) && preg_match('/\A[a-f0-9]{40}\z/D', $token) === 1;
        // The one-request source tag is shared by POST and GET-generated
        // redirect notices. A later unrelated GET removes only native flash
        // from that result; the encrypted token remains claimable by its tab.
        // No long-lived session-wide suppression marker is needed.
        $routed = is_string($request->session()->get(self::REDIRECT_FLASH_SOURCE));

        if (! $hasToken && ! $routed) {
            return $next($request);
        }

        // ShareErrorsFromSession runs before route middleware; replace its
        // captured bag as well as the request's session view.
        $this->forgetFields($request);
        View::share('errors', new ViewErrorBag);

        if ($hasToken) {
            $payload = $this->take($request, $token);
            if (is_array($payload) && ($payload['path'] ?? null) === $request->path()) {
                foreach ((array) ($payload['data'] ?? []) as $key => $value) {
                    if (! in_array($key, self::FIELDS, true) || $key === 'errors') {
                        continue;
                    }
                    $request->session()->put($key, $value);
                }
                $errors = $this->restoreErrors($payload['data']['errors'] ?? null);
                $request->session()->put('errors', $errors);
                View::share('errors', $errors);
            }
        }

        try {
            return $next($request);
        } finally {
            // GET handlers (notably external authorization handoffs) may
            // generate NEW flash errors while rendering an earlier result.
            // Keep the new generation; routeFeedback() then correlates its
            // redirect independently of the old result.
            $newFlash = (array) $request->session()->get('_flash.new', []);
            $request->session()->forget(array_diff(self::FIELDS, $newFlash));
        }
    }

    private function routeFeedback(Request $request, RedirectResponse $response): void
    {
        $fields = array_intersect(self::FIELDS, (array) $request->session()->get('_flash.new', []));
        if ($fields === []) {
            return;
        }

        // A Laravel validation redirect may inherit the current Referer,
        // which could still contain the previous operation's consumed token.
        // Replace that token before binding the new result to the destination.
        $destination = Uri::of($response->getTargetUrl())->withoutQuery(self::PARAMETER);
        $origin = Uri::of($request->url());
        if ($destination->scheme() !== $origin->scheme()
            || $destination->host() !== $origin->host()
            || $destination->port() !== $origin->port()
            || ! ($destination->path() === 'admin' || str_starts_with($destination->path(), 'admin/'))) {
            return;
        }

        $data = [];
        foreach ($fields as $field) {
            $value = $request->session()->get($field);
            $data[$field] = $field === 'errors' ? $this->packErrors($value) : $value;
        }

        try {
            $token = bin2hex(random_bytes(20));
            $key = $this->cacheKey($request, $token, $destination->path(), $destination->query()->all());
            $ciphertext = Crypt::encryptString(json_encode([
                'path' => $destination->path(),
                'data' => $data,
            ], JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
            if (! Cache::put($key, $ciphertext, self::LIFETIME_SECONDS)) {
                // Degrade to Laravel native flash; no correlation source tag
                // is installed if shared cache cannot retain the result.
                return;
            }

            // Source tagging ages with Laravel flash, not cache TTL. A
            // competing GET suppresses native flash from this redirect only,
            // never a new independent result generated on that GET.
            $request->session()->flash(self::REDIRECT_FLASH_SOURCE, $token);
            $response->setTargetUrl((string) $destination->withQuery([self::PARAMETER => $token]));
        } catch (Throwable $exception) {
            // The operation may have succeeded already. Feedback transport
            // must never roll it back, expose the input or trigger a retry.
            $this->logTransportFailure('Admin feedback transport failed.', $exception);
        }
    }

    /** @return array<string,mixed>|null */
    private function take(Request $request, string $token): ?array
    {
        try {
            // Bind the token to the intended destination including its
            // non-token filters, not merely the session and the random key.
            // A wrong-page GET carrying the token cannot consume the result.
            // Laravel's TrimStrings/ConvertEmptyStringsToNull middleware
            // modifies the parsed query bag before this route executes.
            // The original redirect may contain trailing spaces or empty
            // filters, so match using the actual inbound HTTP query bytes.
            $rawQuery = parse_url($request->getRequestUri(), PHP_URL_QUERY);
            $query = [];
            parse_str(is_string($rawQuery) ? $rawQuery : '', $query);
            unset($query[self::PARAMETER]);
            $key = $this->cacheKey($request, $token, $request->path(), $query);

            return Cache::lock($key.':claim', 5)->block(2, static function () use ($key): ?array {
                $value = Cache::get($key);
                if (! is_string($value)) {
                    return null;
                }
                Cache::forget($key);
                $decoded = json_decode(Crypt::decryptString($value), true, flags: JSON_THROW_ON_ERROR);

                return is_array($decoded) ? $decoded : null;
            });
        } catch (Throwable $exception) {
            $this->logTransportFailure('Admin feedback claim failed.', $exception);

            return null;
        }
    }

    private function logTransportFailure(string $message, Throwable $exception): void
    {
        try {
            Log::warning($message, ['exception_class' => $exception::class]);
        } catch (Throwable) {
            // Logging is best-effort. Neither failed storage nor the logging
            // backend may rewrite the original operation's HTTP outcome.
        }
    }

    /**
     * @param  array<string,mixed>  $query
     */
    private function cacheKey(Request $request, string $token, string $path, array $query): string
    {
        ksort($query);

        return 'admin:feedback:'.hash('sha256', implode(':', [
            (string) $request->session()->get(self::SESSION_BINDING),
            (string) $request->user()?->getAuthIdentifier(),
            $path,
            hash('sha256', json_encode($query, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE)),
            $token,
        ]));
    }

    /** @return array<string,array{messages:array<string,array<int,string>>,format:string}> */
    private function packErrors(mixed $value): array
    {
        if (! $value instanceof ViewErrorBag) {
            return is_array($value) ? $value : [];
        }

        $packed = [];
        foreach ($value->getBags() as $name => $bag) {
            $packed[$name] = [
                'messages' => $bag->getMessages(),
                'format' => $bag->getFormat(),
            ];
        }

        return $packed;
    }

    private function restoreErrors(mixed $packed): ViewErrorBag
    {
        $errors = new ViewErrorBag;
        if (! is_array($packed)) {
            return $errors;
        }

        foreach ($packed as $name => $bag) {
            if (! is_string($name) || ! is_array($bag)
                || ! is_array($bag['messages'] ?? null)) {
                continue;
            }
            $messages = new MessageBag($bag['messages']);
            if (is_string($bag['format'] ?? null)) {
                $messages->setFormat($bag['format']);
            }
            $errors->put($name, $messages);
        }

        return $errors;
    }

    private function forgetFields(Request $request): void
    {
        $request->session()->forget(self::FIELDS);
    }
}
