<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/**
 * An authorization request that also carries the OpenID Connect `nonce`.
 */
class OidcAuthorizationRequest extends AuthorizationRequest
{
    private ?string $nonce = null;

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce === '' ? null : $nonce;
    }
}
