<?php

namespace YesWiki\Test\Oidcserver\Service;

require_once 'tools/oidcserver/tests/includes/OidcserverTestCase.php';

use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use YesWiki\Core\Service\DbService;
use YesWiki\Oidcserver\Service\TokenStore;
use YesWiki\Test\Oidcserver\OidcserverTestCase;

class TokenStoreTest extends OidcserverTestCase
{
    private static string $clientId;
    private TokenStore $store;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::$clientId = 'oidc-test-store-' . bin2hex(random_bytes(6));
    }

    public static function tearDownAfterClass(): void
    {
        self::deleteTokensOf([self::$clientId]);
    }

    protected function setUp(): void
    {
        $this->store = self::$wiki->services->get(TokenStore::class);
    }

    public function testAnAddedTokenIsLiveUntilRevoked(): void
    {
        $id = $this->add(TokenStore::ACCESS_TOKEN);

        $this->assertFalse($this->store->isRevoked($id));
        $this->store->revoke($id);
        $this->assertTrue($this->store->isRevoked($id));
    }

    public function testAnUnknownTokenCountsAsRevoked(): void
    {
        $this->assertTrue($this->store->isRevoked('never-issued-' . bin2hex(random_bytes(6))));
    }

    public function testAnIdentifierCannotBeIssuedTwice(): void
    {
        $id = $this->add(TokenStore::AUTH_CODE);

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $this->store->add(TokenStore::ACCESS_TOKEN, $id, self::$clientId, 'User', new \DateTimeImmutable('+1 hour'));
    }

    public function testANonceIsBoundToAnAuthorizationCodeOnly(): void
    {
        $code = $this->add(TokenStore::AUTH_CODE);
        $accessToken = $this->add(TokenStore::ACCESS_TOKEN);

        $this->assertNull($this->store->nonce($code));
        $this->store->bindNonce($code, 'n-1');
        $this->store->bindNonce($accessToken, 'n-2');

        $this->assertSame('n-1', $this->store->nonce($code));
        $this->assertNull($this->store->nonce($accessToken));
    }

    public function testAddingPurgesTokensExpiredForMoreThanADay(): void
    {
        $stale = $this->add(TokenStore::REFRESH_TOKEN, new \DateTimeImmutable('-2 days'));
        $recent = $this->add(TokenStore::REFRESH_TOKEN, new \DateTimeImmutable('-1 hour'));

        $this->add(TokenStore::ACCESS_TOKEN);

        $this->assertFalse($this->exists($stale));
        $this->assertTrue($this->exists($recent));
    }

    private function add(string $kind, ?\DateTimeImmutable $expiresAt = null): string
    {
        $id = bin2hex(random_bytes(20));
        $this->store->add($kind, $id, self::$clientId, 'User', $expiresAt ?? new \DateTimeImmutable('+1 hour'));

        return $id;
    }

    private function exists(string $id): bool
    {
        $db = self::$wiki->services->get(DbService::class);

        return $db->count(sprintf("SELECT * FROM %s WHERE identifier = '%s'", $this->store->table(), $db->escape($id))) === 1;
    }
}
