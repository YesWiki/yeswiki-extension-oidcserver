<?php

namespace YesWiki\Oidcserver\Entity;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * An application allowed to sign its users in with this wiki, as declared in `oidc_clients`.
 */
class ClientEntity implements ClientEntityInterface
{
    use ClientTrait;
    use EntityTrait;

    /**
     * @param string[] $redirectUris
     */
    public function __construct(
        string $identifier,
        string $name,
        array $redirectUris,
        bool $isConfidential,
        private readonly ?string $secretHash,
        private readonly bool $skipConsent
    ) {
        $this->setIdentifier($identifier);
        $this->name = $name;
        $this->redirectUri = $redirectUris;
        $this->isConfidential = $isConfidential;
    }

    public function getSecretHash(): ?string
    {
        return $this->secretHash;
    }

    public function skipsConsent(): bool
    {
        return $this->skipConsent;
    }
}
