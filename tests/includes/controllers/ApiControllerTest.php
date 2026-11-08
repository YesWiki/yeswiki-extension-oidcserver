<?php

namespace YesWiki\Test\Oidcserver\Controller;

require_once 'tools/oidcserver/tests/includes/OidcserverTestCase.php';

use YesWiki\Oidcserver\Controller\ApiController;
use YesWiki\Test\Oidcserver\OidcserverTestCase;

class ApiControllerTest extends OidcserverTestCase
{
    public function testDiscoveryDescribesThisWiki(): void
    {
        $controller = self::$wiki->services->get(ApiController::class);
        $controller->setWiki(self::$wiki);
        $response = $controller->discovery();
        $document = json_decode($response->getContent(), true);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame(self::$wiki->getBaseUrl(), $document['issuer']);
        $this->assertStringNotContainsString('?', $document['issuer']);
        foreach (['authorization_endpoint' => 'authorize', 'token_endpoint' => 'token', 'userinfo_endpoint' => 'userinfo', 'jwks_uri' => 'jwks'] as $key => $route) {
            $this->assertStringStartsWith(self::$wiki->config['base_url'], $document[$key]);
            $this->assertStringEndsWith("api/oidc/{$route}", $document[$key]);
        }
        $this->assertSame(['code'], $document['response_types_supported']);
        $this->assertContains('S256', $document['code_challenge_methods_supported']);
        $this->assertContains('openid', $document['scopes_supported']);
    }
}
