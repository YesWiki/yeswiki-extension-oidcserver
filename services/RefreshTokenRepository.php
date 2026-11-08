<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use YesWiki\Oidcserver\Entity\RefreshTokenEntity;

/**
 * Refresh tokens, kept in the token store and rotated on every use.
 */
class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private readonly TokenStore $tokenStore)
    {
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessToken = $refreshTokenEntity->getAccessToken();
        $this->tokenStore->add(
            TokenStore::REFRESH_TOKEN,
            $refreshTokenEntity->getIdentifier(),
            $accessToken->getClient()->getIdentifier(),
            $accessToken->getUserIdentifier(),
            $refreshTokenEntity->getExpiryDateTime()
        );
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->tokenStore->revoke($tokenId);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return $this->tokenStore->isRevoked($tokenId);
    }
}
