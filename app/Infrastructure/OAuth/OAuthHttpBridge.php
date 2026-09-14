<?php

namespace App\Infrastructure\OAuth;

use Http\Discovery\Psr17FactoryDiscovery;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

final class OAuthHttpBridge
{
    public function request(Request $request): ServerRequestInterface
    {
        return (new PsrHttpFactory)->createRequest($request);
    }

    public function response(): ResponseInterface
    {
        return Psr17FactoryDiscovery::findResponseFactory()->createResponse();
    }

    public function laravel(ResponseInterface $response): Response
    {
        return (new HttpFoundationFactory)->createResponse($response, true);
    }

    public function authorizationResponse(ResponseInterface $response): ResponseInterface
    {
        if ($response->getStatusCode() < 300 || $response->getStatusCode() >= 400) {
            return $response;
        }

        $location = $response->getHeaderLine('Location');
        if ($location === '') {
            return $response;
        }

        return $response->withHeader('Location', $this->appendIssuer($location));
    }

    public function error(OAuthServerException $exception): Response
    {
        $response = $exception->generateHttpResponse($this->response())
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        return $this->laravel($this->authorizationResponse($response));
    }

    private function appendIssuer(string $location): string
    {
        $encodedIssuer = rawurlencode((string) config('oauth.issuer'));
        if (preg_match('/([?&])iss=[^&#]*/', $location) === 1) {
            return (string) preg_replace('/([?&])iss=[^&#]*/', '$1iss='.$encodedIssuer, $location, 1);
        }

        $fragment = '';
        $fragmentPosition = strpos($location, '#');
        if ($fragmentPosition !== false) {
            $fragment = substr($location, $fragmentPosition);
            $location = substr($location, 0, $fragmentPosition);
        }

        $separator = str_contains($location, '?') ? '&' : '?';

        return $location.$separator.'iss='.$encodedIssuer.$fragment;
    }
}
