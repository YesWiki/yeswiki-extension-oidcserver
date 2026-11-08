<?php

namespace YesWiki\Test\Oidcserver\Service;

require_once 'includes/autoload.inc.php';
require_once 'tools/oidcserver/vendor/autoload.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use YesWiki\Oidcserver\Entity\ClientEntity;
use YesWiki\Oidcserver\Service\ClientRepository;

class ClientRepositoryTest extends TestCase
{
    private ClientRepository $repository;

    protected function setUp(): void
    {
        $this->repository = new ClientRepository(new ParameterBag(['oidc_clients' => [
            'confidential' => [
                'name' => 'Confidential app',
                'secret_hash' => password_hash('right-secret', PASSWORD_DEFAULT),
                'redirect_uris' => ['https://app.example/cb'],
                'skip_consent' => true,
            ],
            'public' => ['redirect_uris' => 'https://spa.example/cb'],
            'no-redirect' => ['name' => 'Broken', 'redirect_uris' => []],
        ]]));
    }

    public function testADeclaredClientCarriesItsSettings(): void
    {
        $client = $this->repository->getClientEntity('confidential');

        $this->assertInstanceOf(ClientEntity::class, $client);
        $this->assertSame('Confidential app', $client->getName());
        $this->assertSame(['https://app.example/cb'], $client->getRedirectUri());
        $this->assertTrue($client->isConfidential());
        $this->assertTrue($client->skipsConsent());
    }

    public function testAClientWithoutSecretIsPublicAndNamedAfterItsId(): void
    {
        $client = $this->repository->getClientEntity('public');

        $this->assertFalse($client->isConfidential());
        $this->assertSame('public', $client->getName());
        $this->assertSame(['https://spa.example/cb'], $client->getRedirectUri());
        $this->assertFalse($client->skipsConsent());
    }

    public function testUnknownClientsAndClientsWithoutRedirectUriDoNotExist(): void
    {
        $this->assertNull($this->repository->getClientEntity('unknown'));
        $this->assertNull($this->repository->getClientEntity('no-redirect'));
    }

    public function testNoConfigurationMeansNoClient(): void
    {
        $this->assertNull((new ClientRepository(new ParameterBag(['oidc_clients' => null])))->getClientEntity('confidential'));
    }

    public static function credentials(): array
    {
        return [
            'right secret' => ['confidential', 'right-secret', 'authorization_code', true],
            'right secret on refresh' => ['confidential', 'right-secret', 'refresh_token', true],
            'wrong secret' => ['confidential', 'wrong-secret', 'authorization_code', false],
            'missing secret' => ['confidential', null, 'authorization_code', false],
            'public client without secret' => ['public', null, 'authorization_code', true],
            'client credentials grant' => ['confidential', 'right-secret', 'client_credentials', false],
            'password grant' => ['public', null, 'password', false],
            'unknown client' => ['unknown', 'right-secret', 'authorization_code', false],
        ];
    }

    #[DataProvider('credentials')]
    public function testValidateClient(string $clientId, ?string $secret, string $grantType, bool $expected): void
    {
        $this->assertSame($expected, $this->repository->validateClient($clientId, $secret, $grantType));
    }
}
