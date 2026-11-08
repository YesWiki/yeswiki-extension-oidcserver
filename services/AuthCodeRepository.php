<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use YesWiki\Oidcserver\Entity\AuthCodeEntity;

/**
 * Authorization codes, kept in the token store until used or expired.
 */
class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private readonly TokenStore $tokenStore)
    {
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->tokenStore->add(
            TokenStore::AUTH_CODE,
            $authCodeEntity->getIdentifier(),
            $authCodeEntity->getClient()->getIdentifier(),
            $authCodeEntity->getUserIdentifier(),
            $authCodeEntity->getExpiryDateTime()
        );
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->tokenStore->revoke($codeId);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return $this->tokenStore->isRevoked($codeId);
    }
}
