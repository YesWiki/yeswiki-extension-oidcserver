<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use YesWiki\Oidcserver\Entity\ClientEntity;

/**
 * Reads the applications declared in the `oidc_clients` configuration key.
 */
class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(private readonly ParameterBagInterface $params)
    {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $clients = $this->params->get('oidc_clients');
        $client = is_array($clients) ? ($clients[$clientIdentifier] ?? null) : null;
        if (!is_array($client) || empty($client['redirect_uris'])) {
            return null;
        }
        $secretHash = isset($client['secret_hash']) && is_string($client['secret_hash']) && $client['secret_hash'] !== ''
            ? $client['secret_hash']
            : null;

        return new ClientEntity(
            $clientIdentifier,
            (string)($client['name'] ?? $clientIdentifier),
            array_values(array_map('strval', (array)$client['redirect_uris'])),
            $secretHash !== null,
            $secretHash,
            ($client['skip_consent'] ?? false) === true
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $client = $this->getClientEntity($clientIdentifier);
        if (!$client instanceof ClientEntity || !in_array($grantType, ['authorization_code', 'refresh_token'], true)) {
            return false;
        }
        if ($client->getSecretHash() === null) {
            return true;
        }

        return $clientSecret !== null && password_verify($clientSecret, $client->getSecretHash());
    }
}
