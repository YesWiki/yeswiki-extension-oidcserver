<?php

namespace YesWiki\Test\Oidcserver\Service;

require_once 'includes/autoload.inc.php';
require_once 'tools/oidcserver/vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use YesWiki\Oidcserver\Entity\ClientEntity;
use YesWiki\Oidcserver\Service\ScopeRepository;

class ScopeRepositoryTest extends TestCase
{
    public function testKnownScopesResolve(): void
    {
        $repository = new ScopeRepository();
        foreach (ScopeRepository::SCOPES as $scope) {
            $this->assertSame($scope, $repository->getScopeEntityByIdentifier($scope)->getIdentifier());
        }
    }

    public function testUnknownScopesDoNotResolve(): void
    {
        $this->assertNull((new ScopeRepository())->getScopeEntityByIdentifier('admin'));
    }

    public function testFinalizeKeepsTheRequestedScopes(): void
    {
        $repository = new ScopeRepository();
        $scopes = [$repository->getScopeEntityByIdentifier('openid'), $repository->getScopeEntityByIdentifier('email')];
        $client = new ClientEntity('app', 'App', ['https://app.example/cb'], false, null, false);

        $this->assertSame($scopes, $repository->finalizeScopes($scopes, 'authorization_code', $client, 'User'));
    }
}
