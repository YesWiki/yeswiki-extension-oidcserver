<?php

namespace YesWiki\Test\Oidcserver;

require_once 'tools/oidcserver/tests/includes/OidcserverTestCase.php';

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use YesWiki\Core\Service\UserManager;
use YesWiki\Oidcserver\Entity\UserEntity;
use YesWiki\Oidcserver\Service\AccessTokenRepository;
use YesWiki\Oidcserver\Service\AuthCodeRepository;
use YesWiki\Oidcserver\Service\ClientRepository;
use YesWiki\Oidcserver\Service\KeyStore;
use YesWiki\Oidcserver\Service\OidcServer;
use YesWiki\Oidcserver\Service\RefreshTokenRepository;
use YesWiki\Oidcserver\Service\ScopeRepository;
use YesWiki\Oidcserver\Service\TokenStore;
use YesWiki\Oidcserver\Service\UserClaims;

class AuthorizationFlowTest extends OidcserverTestCase
{
    private const REDIRECT_URI = 'https://app.example/cb';
    private const SECRET = 'app-secret';

    private static string $keysDir;
    private static string $confidential;
    private static string $public;
    private static string $userName;
    private static string $email;
    private OidcServer $server;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        $suffix = bin2hex(random_bytes(5));
        self::$keysDir = sys_get_temp_dir() . "/oidcserver-flow-{$suffix}";
        self::$confidential = "oidc-test-app-{$suffix}";
        self::$public = "oidc-test-spa-{$suffix}";
        self::$userName = "OidcFlowTest{$suffix}";
        self::$email = "oidc-flow-{$suffix}@example.org";
        self::$wiki->services->get(UserManager::class)->create(self::$userName, self::$email, 'Flow-Test-Password-1');
    }

    public static function tearDownAfterClass(): void
    {
        $userManager = self::$wiki->services->get(UserManager::class);
        $user = $userManager->getOneByName(self::$userName);
        if ($user !== null) {
            $userManager->delete($user);
        }
        self::deleteTokensOf([self::$confidential, self::$public]);
        self::removeDirectory(self::$keysDir);
    }

    protected function setUp(): void
    {
        $services = self::$wiki->services;
        $this->server = new OidcServer(
            self::$wiki,
            new ParameterBag(['oidc_auth_code_ttl' => 'PT10M', 'oidc_access_token_ttl' => 'PT1H', 'oidc_refresh_token_ttl' => 'P1M']),
            $this->keyStore(),
            new ClientRepository(new ParameterBag(['oidc_clients' => [
                self::$confidential => [
                    'name' => 'App',
                    'secret_hash' => password_hash(self::SECRET, PASSWORD_DEFAULT),
                    'redirect_uris' => [self::REDIRECT_URI],
                ],
                self::$public => ['redirect_uris' => [self::REDIRECT_URI]],
            ]])),
            new ScopeRepository(),
            $services->get(AccessTokenRepository::class),
            $services->get(AuthCodeRepository::class),
            $services->get(RefreshTokenRepository::class),
            $services->get(TokenStore::class),
            $services->get(UserClaims::class)
        );
    }

    public function testTheCodeFlowIssuesAnIdTokenCarryingTheNonce(): void
    {
        $code = $this->authorize(['scope' => 'openid profile email', 'nonce' => 'n-flow']);
        [$status, $body] = $this->token(['grant_type' => 'authorization_code', 'code' => $code]);

        $this->assertSame(200, $status);
        $idToken = $this->verifiedIdToken($body['id_token']);
        $this->assertSame('n-flow', $idToken->claims()->get('nonce'));
        $this->assertSame(self::$userName, $idToken->claims()->get('preferred_username'));
        $this->assertSame(self::$email, $idToken->claims()->get('email'));
        $this->assertArrayHasKey('refresh_token', $body);
    }

    public function testScopesLimitTheClaims(): void
    {
        [, $body] = $this->token(['grant_type' => 'authorization_code', 'code' => $this->authorize(['scope' => 'openid'])]);
        $claims = $this->verifiedIdToken($body['id_token'])->claims();

        $this->assertFalse($claims->has('email'));
        $this->assertFalse($claims->has('name'));
        $this->assertFalse($claims->has('nonce'));
    }

    public function testACodeIsSingleUse(): void
    {
        $code = $this->authorize(['scope' => 'openid']);
        $this->token(['grant_type' => 'authorization_code', 'code' => $code]);

        [$status, $body] = $this->token(['grant_type' => 'authorization_code', 'code' => $code]);

        $this->assertSame(400, $status);
        $this->assertSame('invalid_grant', $body['error']);
    }

    public function testAWrongSecretIsRefused(): void
    {
        $code = $this->authorize(['scope' => 'openid']);

        [$status, $body] = $this->token(['grant_type' => 'authorization_code', 'code' => $code, 'client_secret' => 'wrong']);

        $this->assertSame(401, $status);
        $this->assertSame('invalid_client', $body['error']);
    }

    public function testAnUnregisteredRedirectUriIsRefused(): void
    {
        $this->expectExceptionObject(OAuthServerException::invalidClient(new ServerRequest('GET', '/')));

        $this->authorize(['scope' => 'openid', 'redirect_uri' => 'https://evil.example/cb']);
    }

    public function testAPublicClientMustUsePkce(): void
    {
        try {
            $this->authorize(['scope' => 'openid', 'client_id' => self::$public]);
            $this->fail('A public client got a code without PKCE');
        } catch (OAuthServerException $e) {
            $this->assertSame('invalid_request', $e->getErrorType());
        }

        $verifier = bin2hex(random_bytes(32));
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $pkce = ['scope' => 'openid', 'client_id' => self::$public, 'code_challenge' => $challenge, 'code_challenge_method' => 'S256'];
        $publicToken = ['grant_type' => 'authorization_code', 'client_id' => self::$public, 'client_secret' => null];

        [$status, $body] = $this->token($publicToken + ['code' => $this->authorize($pkce), 'code_verifier' => strrev($verifier)]);
        $this->assertSame(400, $status);
        $this->assertSame('invalid_grant', $body['error']);

        [$status, $body] = $this->token($publicToken + ['code' => $this->authorize($pkce), 'code_verifier' => $verifier]);
        $this->assertSame(200, $status);
        $this->verifiedIdToken($body['id_token'], self::$public);
    }

    public function testADeniedRequestRedirectsWithAccessDenied(): void
    {
        $request = $this->server->authorizationServer()->validateAuthorizationRequest($this->authorizationRequest(['scope' => 'openid', 'state' => 'st-1']));
        $request->setUser(new UserEntity(self::$userName));
        $request->setAuthorizationApproved(false);

        try {
            $this->server->authorizationServer()->completeAuthorizationRequest($request, new Response());
            $this->fail('A denied request got a code');
        } catch (OAuthServerException $e) {
            parse_str((string)parse_url($e->generateHttpResponse(new Response())->getHeaderLine('Location'), PHP_URL_QUERY), $query);
            $this->assertSame('access_denied', $query['error']);
            $this->assertSame('st-1', $query['state']);
            $this->assertArrayNotHasKey('code', $query);
        }
    }

    public function testTheResourceServerAcceptsAnAccessTokenUntilItIsRevoked(): void
    {
        [, $body] = $this->token(['grant_type' => 'authorization_code', 'code' => $this->authorize(['scope' => 'openid email'])]);
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer ' . $body['access_token']);

        $authenticated = $this->server->resourceServer()->validateAuthenticatedRequest($request);
        $this->assertSame(self::$userName, $authenticated->getAttribute('oauth_user_id'));
        $this->assertSame(['openid', 'email'], $authenticated->getAttribute('oauth_scopes'));

        self::$wiki->services->get(AccessTokenRepository::class)->revokeAccessToken($authenticated->getAttribute('oauth_access_token_id'));
        $this->expectException(OAuthServerException::class);
        $this->server->resourceServer()->validateAuthenticatedRequest($request);
    }

    public function testARefreshKeepsTheAccountAndRotatesTheRefreshToken(): void
    {
        [, $first] = $this->token(['grant_type' => 'authorization_code', 'code' => $this->authorize(['scope' => 'openid', 'nonce' => 'n-once'])]);

        [$status, $refreshed] = $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $first['refresh_token']]);
        $this->assertSame(200, $status);
        $idToken = $this->verifiedIdToken($refreshed['id_token']);
        $this->assertFalse($idToken->claims()->has('nonce'));

        [$status, $body] = $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $first['refresh_token']]);
        $this->assertSame(400, $status);
        $this->assertSame('invalid_grant', $body['error']);
    }

    private function keyStore(): KeyStore
    {
        return new KeyStore(new ParameterBag(['oidc_keys_path' => self::$keysDir]));
    }

    private function authorizationRequest(array $query): ServerRequest
    {
        return (new ServerRequest('GET', 'https://wiki.example/?api/oidc/authorize'))->withQueryParams($query + [
            'response_type' => 'code',
            'client_id' => self::$confidential,
            'redirect_uri' => self::REDIRECT_URI,
        ]);
    }

    private function authorize(array $query): string
    {
        $request = $this->server->authorizationServer()->validateAuthorizationRequest($this->authorizationRequest($query));
        $request->setUser(new UserEntity(self::$userName));
        $request->setAuthorizationApproved(true);
        $location = $this->server->authorizationServer()->completeAuthorizationRequest($request, new Response())->getHeaderLine('Location');
        $this->assertStringStartsWith(self::REDIRECT_URI . '?', $location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $params);

        return $params['code'];
    }

    /**
     * @return array{int, array}
     */
    private function token(array $body): array
    {
        $body = array_filter($body + [
            'client_id' => self::$confidential,
            'client_secret' => self::SECRET,
            'redirect_uri' => self::REDIRECT_URI,
        ], fn ($value) => $value !== null);
        $request = (new ServerRequest('POST', 'https://wiki.example/?api/oidc/token'))->withParsedBody($body);
        try {
            $response = $this->server->authorizationServer()->respondToAccessTokenRequest($request, new Response());
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse(new Response());
        }

        return [$response->getStatusCode(), json_decode((string)$response->getBody(), true)];
    }

    private function verifiedIdToken(string $jwt, ?string $audience = null): UnencryptedToken
    {
        $token = (new Parser(new JoseEncoder()))->parse($jwt);
        $this->assertTrue((new Validator())->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::plainText($this->keyStore()->publicKey()->getKeyContents())),
            new IssuedBy($this->server->issuer()),
            new PermittedFor($audience ?? self::$confidential),
            new RelatedTo(self::$userName)
        ), 'The ID token is not signed by this wiki for this client and account');
        $this->assertSame($this->keyStore()->keyId(), $token->headers()->get('kid'));

        return $token;
    }
}
