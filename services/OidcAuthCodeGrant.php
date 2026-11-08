<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The authorization code grant, extended to carry the `nonce` from the authorization request to the ID token.
 */
class OidcAuthCodeGrant extends AuthCodeGrant
{
    private ?OidcAuthorizationRequest $completing = null;

    public function __construct(
        AuthCodeRepository $authCodeRepository,
        RefreshTokenRepository $refreshTokenRepository,
        \DateInterval $authCodeTTL,
        private readonly TokenStore $tokenStore
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);
        if ($authorizationRequest instanceof OidcAuthorizationRequest) {
            $authorizationRequest->setNonce($this->getQueryStringParameter('nonce', $request));
        }

        return $authorizationRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        $this->completing = $authorizationRequest instanceof OidcAuthorizationRequest ? $authorizationRequest : null;
        try {
            return parent::completeAuthorizationRequest($authorizationRequest);
        } finally {
            $this->completing = null;
        }
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        $authCodeId = $this->authCodeIdFrom($request);
        $responseType = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
        if ($responseType instanceof IdTokenResponse && $authCodeId !== null) {
            $responseType->setNonce($this->tokenStore->nonce($authCodeId));
        }

        return $responseType;
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new OidcAuthorizationRequest();
    }

    protected function issueAuthCode(
        \DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        string $userIdentifier,
        ?string $redirectUri,
        array $scopes = []
    ): AuthCodeEntityInterface {
        $authCode = parent::issueAuthCode($authCodeTTL, $client, $userIdentifier, $redirectUri, $scopes);
        $nonce = $this->completing?->getNonce();
        if ($nonce !== null) {
            $this->tokenStore->bindNonce($authCode->getIdentifier(), $nonce);
        }

        return $authCode;
    }

    private function authCodeIdFrom(ServerRequestInterface $request): ?string
    {
        $code = $this->getRequestParameter('code', $request);
        if ($code === null) {
            return null;
        }
        try {
            $payload = json_decode($this->decrypt($code));
        } catch (\Throwable) {
            return null;
        }

        return is_object($payload) && isset($payload->auth_code_id) ? (string)$payload->auth_code_id : null;
    }
}
