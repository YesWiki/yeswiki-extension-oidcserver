<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use YesWiki\Oidcserver\Entity\AccessTokenEntity;

/**
 * Access tokens, kept in the token store so a revoked one stops opening `/userinfo`.
 */
class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private readonly TokenStore $tokenStore)
    {
    }

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null
    ): AccessTokenEntityInterface {
        $token = new AccessTokenEntity();
        $token->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }
        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->tokenStore->add(
            TokenStore::ACCESS_TOKEN,
            $accessTokenEntity->getIdentifier(),
            $accessTokenEntity->getClient()->getIdentifier(),
            $accessTokenEntity->getUserIdentifier(),
            $accessTokenEntity->getExpiryDateTime()
        );
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->tokenStore->revoke($tokenId);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->tokenStore->isRevoked($tokenId);
    }
}
