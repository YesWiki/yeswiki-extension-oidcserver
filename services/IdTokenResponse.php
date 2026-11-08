<?php

namespace YesWiki\Oidcserver\Service;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

/**
 * The token endpoint response, with a signed `id_token` added whenever the `openid` scope was granted.
 */
class IdTokenResponse extends BearerTokenResponse
{
    private const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    private ?string $nonce = null;

    public function __construct(
        private readonly string $issuer,
        private readonly string $keyId,
        private readonly UserClaims $userClaims
    ) {
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    protected function getExtraParams(#[\SensitiveParameter] AccessTokenEntityInterface $accessToken): array
    {
        $scopes = array_map(fn ($scope) => $scope->getIdentifier(), $accessToken->getScopes());
        $userId = $accessToken->getUserIdentifier();
        if (!in_array('openid', $scopes, true) || $userId === null) {
            return [];
        }
        $claims = $this->userClaims->forUser($userId, $scopes);
        if ($claims === null) {
            throw new \RuntimeException('The account this token was issued for no longer exists');
        }

        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->issuedBy($this->issuer)
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->relatedTo($claims['sub'])
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->withHeader('kid', $this->keyId);
        if ($this->nonce !== null) {
            $builder = $builder->withClaim('nonce', $this->nonce);
        }
        foreach ($claims as $name => $value) {
            if (!in_array($name, self::REGISTERED_CLAIMS, true)) {
                $builder = $builder->withClaim($name, $value);
            }
        }

        return [
            'id_token' => $builder->getToken(new Sha256(), InMemory::plainText($this->privateKey->getKeyContents()))->toString(),
        ];
    }
}
