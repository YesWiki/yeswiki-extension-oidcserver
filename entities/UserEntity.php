<?php

namespace YesWiki\Oidcserver\Entity;

use League\OAuth2\Server\Entities\UserEntityInterface;

/**
 * The wiki account an authorization is granted for, identified by its user name.
 */
class UserEntity implements UserEntityInterface
{
    public function __construct(private readonly string $identifier)
    {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
