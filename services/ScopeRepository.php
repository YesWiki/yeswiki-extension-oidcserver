<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use YesWiki\Oidcserver\Entity\ScopeEntity;

/**
 * The scopes this provider knows: `openid`, `profile`, `email` and `offline_access`.
 */
class ScopeRepository implements ScopeRepositoryInterface
{
    public const SCOPES = ['openid', 'profile', 'email', 'offline_access'];

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return in_array($identifier, self::SCOPES, true) ? new ScopeEntity($identifier) : null;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null
    ): array {
        return $scopes;
    }
}
