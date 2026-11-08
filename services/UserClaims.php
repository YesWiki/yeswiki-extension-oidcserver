<?php

namespace YesWiki\Oidcserver\Service;

use YesWiki\Core\Service\UserManager;

/**
 * The OpenID Connect claims a wiki account exposes, filtered by the granted scopes.
 */
class UserClaims
{
    public function __construct(private readonly UserManager $userManager)
    {
    }

    /**
     * @param string[] $scopes
     *
     * @return array<string,string>|null null when the account no longer exists
     */
    public function forUser(string $userName, array $scopes): ?array
    {
        $user = $this->userManager->getOneByName($userName);
        if ($user === null) {
            return null;
        }
        $claims = ['sub' => $user->getName()];
        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->getName();
            $claims['preferred_username'] = $user->getName();
        }
        if (in_array('email', $scopes, true) && $user->getEmail() !== '') {
            $claims['email'] = $user->getEmail();
        }

        return $claims;
    }
}
