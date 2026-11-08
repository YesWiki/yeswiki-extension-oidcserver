<?php

namespace YesWiki\Test\Oidcserver\Service;

require_once 'includes/autoload.inc.php';
require_once 'tools/oidcserver/vendor/autoload.php';

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
use League\OAuth2\Server\CryptKey;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use YesWiki\Oidcserver\Entity\AccessTokenEntity;
use YesWiki\Oidcserver\Entity\ClientEntity;
use YesWiki\Oidcserver\Entity\ScopeEntity;
use YesWiki\Oidcserver\Service\IdTokenResponse;
use YesWiki\Oidcserver\Service\UserClaims;

class IdTokenResponseTest extends TestCase
{
    private const ISSUER = 'https://wiki.example/sub';

    private static string $privatePem;
    private static string $publicPem;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privatePem);
        self::$privatePem = $privatePem;
        self::$publicPem = openssl_pkey_get_details($key)['key'];
    }

    public function testTheOpenidScopeAddsASignedIdToken(): void
    {
        $body = $this->respond(['openid', 'profile', 'email'], ['sub' => 'Alice', 'name' => 'Alice', 'email' => 'alice@example.org'], 'n-123');
        $token = $this->parse($body['id_token']);

        $this->assertTrue((new Validator())->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::plainText(self::$publicPem)),
            new IssuedBy(self::ISSUER),
            new PermittedFor('app'),
            new RelatedTo('Alice')
        ));
        $this->assertSame('kid-1', $token->headers()->get('kid'));
        $this->assertSame('n-123', $token->claims()->get('nonce'));
        $this->assertSame('Alice', $token->claims()->get('name'));
        $this->assertSame('alice@example.org', $token->claims()->get('email'));
        $this->assertSame('Bearer', $body['token_type']);
        $this->assertArrayHasKey('access_token', $body);
    }

    public function testWithoutNonceTheIdTokenHasNone(): void
    {
        $token = $this->parse($this->respond(['openid'], ['sub' => 'Alice'], null)['id_token']);

        $this->assertFalse($token->claims()->has('nonce'));
    }

    public function testWithoutTheOpenidScopeThereIsNoIdToken(): void
    {
        $body = $this->respond(['profile'], ['sub' => 'Alice', 'name' => 'Alice'], 'n-123');

        $this->assertArrayNotHasKey('id_token', $body);
        $this->assertArrayHasKey('access_token', $body);
    }

    public function testADeletedAccountGetsNoIdToken(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->respond(['openid'], null, null);
    }

    private function respond(array $scopes, ?array $claims, ?string $nonce): array
    {
        $userClaims = $this->createMock(UserClaims::class);
        $userClaims->method('forUser')->with('Alice', $scopes)->willReturn($claims);

        $privateKey = new CryptKey(self::$privatePem);
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier(bin2hex(random_bytes(8)));
        $accessToken->setClient(new ClientEntity('app', 'App', ['https://app.example/cb'], false, null, false));
        $accessToken->setUserIdentifier('Alice');
        $accessToken->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));
        $accessToken->setPrivateKey($privateKey);
        foreach ($scopes as $scope) {
            $accessToken->addScope(new ScopeEntity($scope));
        }

        $response = new IdTokenResponse(self::ISSUER, 'kid-1', $userClaims);
        $response->setPrivateKey($privateKey);
        $response->setAccessToken($accessToken);
        $response->setNonce($nonce);

        return json_decode((string)$response->generateHttpResponse(new Response())->getBody(), true);
    }

    private function parse(string $jwt): UnencryptedToken
    {
        return (new Parser(new JoseEncoder()))->parse($jwt);
    }
}
