<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Response;
use YesWiki\Wiki;

/**
 * Assembles the league authorization and resource servers for this wiki, and translates between PSR-7 and HttpFoundation.
 */
class OidcServer
{
    private ?AuthorizationServer $authorizationServer = null;
    private Psr17Factory $psr17;

    public function __construct(
        private readonly Wiki $wiki,
        private readonly ParameterBagInterface $params,
        private readonly KeyStore $keyStore,
        private readonly ClientRepository $clientRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly AuthCodeRepository $authCodeRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly TokenStore $tokenStore,
        private readonly UserClaims $userClaims
    ) {
        $this->psr17 = new Psr17Factory();
    }

    /** The issuer identifier: the wiki's base URL, without query string or trailing slash. */
    public function issuer(): string
    {
        return $this->wiki->getBaseUrl();
    }

    public function endpoint(string $name): string
    {
        return $this->wiki->Href('', "api/oidc/{$name}", null, false);
    }

    public function authorizationServer(): AuthorizationServer
    {
        if ($this->authorizationServer !== null) {
            return $this->authorizationServer;
        }
        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->keyStore->privateKey(),
            $this->keyStore->encryptionKey(),
            new IdTokenResponse($this->issuer(), $this->keyStore->keyId(), $this->userClaims)
        );
        $accessTokenTTL = $this->interval('oidc_access_token_ttl');

        $authCodeGrant = new OidcAuthCodeGrant(
            $this->authCodeRepository,
            $this->refreshTokenRepository,
            $this->interval('oidc_auth_code_ttl'),
            $this->tokenStore
        );
        $authCodeGrant->setRefreshTokenTTL($this->interval('oidc_refresh_token_ttl'));
        $server->enableGrantType($authCodeGrant, $accessTokenTTL);

        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($this->interval('oidc_refresh_token_ttl'));
        $server->enableGrantType($refreshTokenGrant, $accessTokenTTL);

        return $this->authorizationServer = $server;
    }

    public function resourceServer(): ResourceServer
    {
        return new ResourceServer($this->accessTokenRepository, $this->keyStore->publicKey());
    }

    public function psrRequest(): ServerRequestInterface
    {
        return (new ServerRequestCreator($this->psr17, $this->psr17, $this->psr17, $this->psr17))->fromGlobals();
    }

    public function psrResponse(): ResponseInterface
    {
        return $this->psr17->createResponse();
    }

    public function toResponse(ResponseInterface $psrResponse): Response
    {
        $response = new Response((string)$psrResponse->getBody(), $psrResponse->getStatusCode());
        foreach ($psrResponse->getHeaders() as $name => $values) {
            $response->headers->set($name, $values);
        }

        return $response;
    }

    private function interval(string $param): \DateInterval
    {
        return new \DateInterval((string)$this->params->get($param));
    }
}
