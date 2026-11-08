<?php

namespace YesWiki\Oidcserver\Controller;

use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use YesWiki\Core\Controller\AuthController;
use YesWiki\Core\Service\RequestGuard;
use YesWiki\Core\YesWikiController;
use YesWiki\Oidcserver\Entity\ClientEntity;
use YesWiki\Oidcserver\Entity\ScopeEntity;
use YesWiki\Oidcserver\Entity\UserEntity;
use YesWiki\Oidcserver\Service\KeyStore;
use YesWiki\Oidcserver\Service\OidcAuthorizationRequest;
use YesWiki\Oidcserver\Service\OidcServer;
use YesWiki\Oidcserver\Service\ScopeRepository;
use YesWiki\Oidcserver\Service\UserClaims;

/**
 * The OpenID Connect endpoints: discovery, keys, authorization, token and userinfo.
 */
class ApiController extends YesWikiController
{
    private const PENDING_SESSION_KEY = 'oidcserver_pending';

    /**
     * @Route("/api/oidc/openid-configuration", methods={"GET"}, options={"acl":{"public"}})
     */
    public function discovery(): Response
    {
        $server = $this->getService(OidcServer::class);

        return $this->publicJson([
            'issuer' => $server->issuer(),
            'authorization_endpoint' => $server->endpoint('authorize'),
            'token_endpoint' => $server->endpoint('token'),
            'userinfo_endpoint' => $server->endpoint('userinfo'),
            'jwks_uri' => $server->endpoint('jwks'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ScopeRepository::SCOPES,
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'preferred_username', 'email'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'code_challenge_methods_supported' => ['S256', 'plain'],
        ]);
    }

    /**
     * @Route("/api/oidc/jwks", methods={"GET"}, options={"acl":{"public"}})
     */
    public function jwks(): Response
    {
        return $this->publicJson(['keys' => [$this->getService(KeyStore::class)->publicJwk()]]);
    }

    /**
     * @Route("/api/oidc/authorize", methods={"GET"}, options={"acl":{"public"}})
     */
    public function authorize(Request $request): Response
    {
        $server = $this->getService(OidcServer::class);
        try {
            $authRequest = $server->authorizationServer()->validateAuthorizationRequest($server->psrRequest());
        } catch (OAuthServerException $e) {
            return $server->toResponse($e->generateHttpResponse($server->psrResponse()));
        }

        $user = $this->getService(AuthController::class)->getLoggedUser();
        if (empty($user['name'])) {
            if ($request->query->get('prompt') === 'none') {
                return $this->redirectWithError($authRequest, 'login_required');
            }

            return new Response($this->renderInSquelette('@oidcserver/login.twig', [
                'clientName' => $authRequest->getClient()->getName(),
                'loginForm' => $this->wiki->Action('login', 0, ['incomingurl' => $request->getUri()]),
            ]));
        }

        $client = $authRequest->getClient();
        if ($client instanceof ClientEntity && $client->skipsConsent()) {
            return $this->complete($authRequest, $user['name'], true);
        }
        if ($request->query->get('prompt') === 'none') {
            return $this->redirectWithError($authRequest, 'consent_required');
        }

        $pendingId = bin2hex(random_bytes(16));
        $_SESSION[self::PENDING_SESSION_KEY][$pendingId] = serialize($authRequest);

        return new Response($this->renderInSquelette('@oidcserver/consent.twig', [
            'clientName' => $client->getName(),
            'userName' => $user['name'],
            'scopes' => array_map(fn ($scope) => $scope->getIdentifier(), $authRequest->getScopes()),
            'pendingId' => $pendingId,
            'action' => $server->endpoint('authorize'),
        ]));
    }

    /**
     * @Route("/api/oidc/authorize", methods={"POST"}, options={"acl":{"public"}})
     */
    public function decide(Request $request): Response
    {
        $pendingId = (string)$request->request->get('pending');
        $serialized = $_SESSION[self::PENDING_SESSION_KEY][$pendingId] ?? null;
        unset($_SESSION[self::PENDING_SESSION_KEY][$pendingId]);
        $authRequest = is_string($serialized) ? unserialize($serialized, ['allowed_classes' => [
            OidcAuthorizationRequest::class,
            ClientEntity::class,
            ScopeEntity::class,
        ]]) : null;
        $user = $this->getService(AuthController::class)->getLoggedUser();
        if (!$authRequest instanceof OidcAuthorizationRequest || empty($user['name']) || !$this->getService(RequestGuard::class)->carriesToken($request)) {
            return new Response(_t('OIDCSERVER_INVALID_REQUEST'), Response::HTTP_BAD_REQUEST);
        }

        return $this->complete($authRequest, $user['name'], $request->request->get('decision') === 'allow');
    }

    /**
     * @Route("/api/oidc/token", methods={"POST"}, options={"acl":{"public"}})
     */
    public function token(): Response
    {
        $server = $this->getService(OidcServer::class);
        try {
            $psrResponse = $server->authorizationServer()->respondToAccessTokenRequest($server->psrRequest(), $server->psrResponse());
        } catch (OAuthServerException $e) {
            $psrResponse = $e->generateHttpResponse($server->psrResponse());
        }

        return $this->withCors($server->toResponse($psrResponse));
    }

    /**
     * @Route("/api/oidc/userinfo", methods={"GET","POST"}, options={"acl":{"public"}})
     */
    public function userinfo(): Response
    {
        $server = $this->getService(OidcServer::class);
        try {
            $psrRequest = $server->resourceServer()->validateAuthenticatedRequest($server->psrRequest());
        } catch (OAuthServerException $e) {
            return $this->withCors($server->toResponse($e->generateHttpResponse($server->psrResponse())));
        }
        $scopes = (array)$psrRequest->getAttribute('oauth_scopes', []);
        $claims = in_array('openid', $scopes, true)
            ? $this->getService(UserClaims::class)->forUser((string)$psrRequest->getAttribute('oauth_user_id'), $scopes)
            : null;
        if ($claims === null) {
            return $this->withCors(new JsonResponse(['error' => 'invalid_token'], Response::HTTP_UNAUTHORIZED, [
                'WWW-Authenticate' => 'Bearer error="invalid_token"',
            ]));
        }

        return $this->publicJson($claims);
    }

    private function complete(OidcAuthorizationRequest $authRequest, string $userName, bool $approved): Response
    {
        $server = $this->getService(OidcServer::class);
        $authRequest->setUser(new UserEntity($userName));
        $authRequest->setAuthorizationApproved($approved);
        try {
            $psrResponse = $server->authorizationServer()->completeAuthorizationRequest($authRequest, $server->psrResponse());
        } catch (OAuthServerException $e) {
            $psrResponse = $e->generateHttpResponse($server->psrResponse());
        }

        return $server->toResponse($psrResponse);
    }

    private function redirectWithError(OidcAuthorizationRequest $authRequest, string $error): Response
    {
        $redirectUri = $authRequest->getRedirectUri() ?? ((array)$authRequest->getClient()->getRedirectUri())[0];
        $params = array_filter(['error' => $error, 'state' => $authRequest->getState()], fn ($value) => $value !== null);
        $separator = str_contains($redirectUri, '?') ? '&' : '?';

        return new Response('', Response::HTTP_FOUND, ['Location' => $redirectUri . $separator . http_build_query($params)]);
    }

    private function publicJson(array $data): Response
    {
        return $this->withCors(new JsonResponse($data, Response::HTTP_OK, ['Cache-Control' => 'no-store']));
    }

    private function withCors(Response $response): Response
    {
        $response->headers->set('Access-Control-Allow-Origin', '*');

        return $response;
    }
}
